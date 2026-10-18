//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"susanoo/internal/event"
)

// ファイルの監視（C3）。fanotify の FID 方式（FAN_REPORT_DFID_NAME）で、
//
//   - 重要な場所（認証情報、設定、自動起動など）の変更を、変更したプロセスとともに記録する
//   - 守る場所（文書など）で、1 つのプロセスが短時間に大量のファイルを変更したら検知結果にする（T7 ランサムウェア）
//
// 重要な場所はディレクトリの印（root でなくても使える）、守る場所はファイルシステムの印（CAP_SYS_ADMIN が必要）で監視する。
// 守る場所の下のディレクトリは起動時に洗い出し、そこでのイベントだけを数える。

// FileConfig はファイルの監視の設定。
type FileConfig struct {
	Paths      []string      // 重要な場所（ファイルかディレクトリ。ディレクトリの下の階層は含まない）
	Protect    []string      // 大量の変更を監視する場所（下の階層を含む）
	MassFiles  int           // この数以上のファイルを MassWindow の間に変更したら検知する。既定 200
	MassWindow time.Duration // 既定 30 秒
}

const (
	defaultMassFiles  = 200
	defaultMassWindow = 30 * time.Second
	massRealert       = 5 * time.Minute // 同じプロセスの大量の変更を、続けて検知結果にしない時間
	maxProtectedDirs  = 20000
	fileDedupe        = 2 * time.Second
	importantMask     = fanCreate | fanDelete | fanMovedFrom | fanMovedTo | fanCloseWrite | fanAttrib | fanEventOnChild | fanOnDir
	changeMask        = fanCreate | fanDelete | fanMovedTo | fanCloseWrite
)

type watchDir struct {
	path  string
	files map[string]bool // nil ならディレクトリの中のすべて
}

type massCount struct {
	start   time.Time
	files   map[string]bool // 時間枠の中で変更されたファイル（同じファイルへの複数のイベントは 1 つと数える）
	samples []string
	alerted time.Time
}

type fileMonitor struct {
	f       *os.File
	cfg     FileConfig
	self    int
	log     *slog.Logger
	limiter *limiter

	mu        sync.Mutex
	watched   map[fidKey]watchDir
	protected map[fidKey]string
	counts    map[int32]*massCount
	recent    map[string]time.Time
	massOn    bool
}

func newFileMonitor(cfg FileConfig, log *slog.Logger) (*fileMonitor, error) {
	if cfg.MassFiles <= 0 {
		cfg.MassFiles = defaultMassFiles
	}
	if cfg.MassWindow <= 0 {
		cfg.MassWindow = defaultMassWindow
	}
	fd, err := fanotifyInit(fanClassNotif|fanCloexec|fanNonblock|fanReportDFIDNm, syscall.O_RDONLY|syscall.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init（FID）: %w", err)
	}
	m := &fileMonitor{cfg: cfg, self: os.Getpid(), log: log, limiter: newLimiter(50, 200),
		watched: map[fidKey]watchDir{}, protected: map[fidKey]string{}, counts: map[int32]*massCount{}, recent: map[string]time.Time{}}

	for _, p := range cfg.Paths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		dir, file := p, ""
		if !fi.IsDir() {
			dir, file = filepath.Dir(p), filepath.Base(p)
		}
		key, err := dirKey(dir)
		if err != nil {
			continue
		}
		if err := fanotifyMark(fd, fanMarkAdd, importantMask, dir); err != nil {
			continue
		}
		w, ok := m.watched[key]
		if !ok {
			w = watchDir{path: dir, files: map[string]bool{}}
		}
		if file == "" {
			w.files = nil
		} else if w.files != nil {
			w.files[file] = true
		}
		m.watched[key] = w
	}

	marked := map[string]bool{}
	for _, root := range cfg.Protect {
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return nil
			}
			if len(m.protected) >= maxProtectedDirs {
				return filepath.SkipAll
			}
			if key, err := dirKey(path); err == nil {
				m.protected[key] = path
			}
			return nil
		})
		var st syscall.Statfs_t
		if syscall.Statfs(root, &st) != nil {
			continue
		}
		fsid := fmt.Sprint(st.Fsid)
		if marked[fsid] {
			continue
		}
		if err := fanotifyMark(fd, fanMarkAdd|fanMarkFS, changeMask|fanOnDir, root); err != nil {
			log.Info("大量の変更の監視を使えません（root 権限が必要）", "場所", root, "理由", err)
			continue
		}
		marked[fsid] = true
		m.massOn = true
	}
	if len(m.watched) == 0 && !m.massOn {
		syscall.Close(fd)
		return nil, errors.New("fanotify: 監視できる場所がありません")
	}
	m.f = os.NewFile(uintptr(fd), "fanotify-files")
	return m, nil
}

func (m *fileMonitor) close() error { return m.f.Close() }

func (m *fileMonitor) run(ctx context.Context, emit func(*event.Event)) error {
	buf := make([]byte, 64*1024)
	for {
		n, err := m.f.Read(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) {
				return ctx.Err()
			}
			return fmt.Errorf("fanotify: %w", err)
		}
		evs, perr := parseFIDEvents(buf[:n])
		now := time.Now()
		for _, ev := range evs {
			for _, e := range m.handle(ev, now) {
				emit(e)
			}
		}
		if perr != nil {
			return perr
		}
	}
}

// handle は 1 件のイベントを処理し、記録するイベントを返す。
func (m *fileMonitor) handle(ev fidEvent, now time.Time) []*event.Event {
	if ev.pid == int32(m.self) || ev.mask&fanQOverflow != 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*event.Event

	if w, ok := m.watched[ev.dir]; ok && (w.files == nil || w.files[ev.name]) {
		path := filepath.Join(w.path, ev.name)
		var proc *event.Process
		for _, activity := range fileActivities(ev.mask) {
			key := fmt.Sprintf("%s\x00%d\x00%d", path, ev.pid, activity)
			if t, dup := m.recent[key]; (dup && now.Sub(t) <= fileDedupe) || !m.limiter.allow(now) {
				continue
			}
			m.recent[key] = now
			if proc == nil {
				proc = processInfo(int(ev.pid))
			}
			e := event.New(event.ClassFileSystemActivity, activity, event.SeverityLow, now)
			e.File = &event.File{Name: ev.name, Path: path}
			e.Actor = &event.Actor{Process: proc}
			out = append(out, e)
		}
		if len(m.recent) > 4096 {
			for k, t := range m.recent {
				if now.Sub(t) > fileDedupe {
					delete(m.recent, k)
				}
			}
		}
	}

	if dir, ok := m.protected[ev.dir]; ok && ev.mask&changeMask != 0 {
		path := filepath.Join(dir, ev.name)
		if ev.mask&fanOnDir != 0 {
			if ev.mask&fanCreate != 0 && len(m.protected) < maxProtectedDirs {
				if key, err := dirKey(path); err == nil {
					m.protected[key] = path // 新しく作られたディレクトリも監視する
				}
			}
		} else if e := m.count(ev.pid, path, now); e != nil {
			out = append(out, e)
		}
	}
	return out
}

// count はプロセスごとの変更を数え、しきい値を超えたら検知結果を返す。
func (m *fileMonitor) count(pid int32, path string, now time.Time) *event.Event {
	c := m.counts[pid]
	if c == nil {
		c = &massCount{start: now}
		m.counts[pid] = c
	}
	if c.files == nil || now.Sub(c.start) > m.cfg.MassWindow {
		c.start, c.files, c.samples = now, map[string]bool{}, nil
	}
	if !c.files[path] && len(c.files) < 4*m.cfg.MassFiles {
		c.files[path] = true
		if len(c.samples) < 3 {
			c.samples = append(c.samples, path)
		}
	}
	n := len(c.files)
	if n < m.cfg.MassFiles || now.Sub(c.alerted) < massRealert {
		return nil
	}
	c.alerted = now
	if len(m.counts) > 1024 {
		for p, x := range m.counts {
			if now.Sub(x.start) > m.cfg.MassWindow && now.Sub(x.alerted) > massRealert {
				delete(m.counts, p)
			}
		}
	}
	proc := processInfo(int(pid))
	who := "不明なプロセス"
	if proc != nil && proc.Name != "" {
		who = fmt.Sprintf("%s（PID %d）", proc.Name, pid)
	}
	msg := fmt.Sprintf("%s が %s 以内に %d 個以上のファイルを変更しました（例: %s）", who, m.cfg.MassWindow, n, strings.Join(c.samples, "、"))
	e := event.New(event.ClassDetectionFinding, event.FindingCreate, event.SeverityHigh, now)
	e.Message = msg
	e.FindingInfo = &event.FindingInfo{UID: randomID(), Title: "短時間の大量変更", Desc: msg, Types: []string{event.FindingTypeMassChange}}
	e.Evidences = []event.Evidence{{Process: proc}}
	return e
}

// fileActivities はイベントのマスクを OCSF の操作の列にする。fanotify は、読み出されていない同じファイル、
// 同じプロセスのイベントを 1 件にまとめる（作成と書き込みなど）ので、起きた順に近い並びですべて返す。
func fileActivities(mask uint64) []int {
	var out []int
	for _, a := range []struct {
		bits     uint64
		activity int
	}{
		{fanCreate, event.FileCreate},
		{fanMovedFrom | fanMovedTo, event.FileRename},
		{fanCloseWrite, event.FileUpdate},
		{fanAttrib, event.FileSetAttributes},
		{fanDelete, event.FileDelete},
	} {
		if mask&a.bits != 0 {
			out = append(out, a.activity)
		}
	}
	return out
}
