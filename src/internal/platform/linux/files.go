//go:build linux

package linux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"susanoo/internal/event"
)

// ファイルの監視（C3、C4、C8、C9）。fanotify の FID 方式（FAN_REPORT_DFID_NAME と FAN_REPORT_FID）で、
//
//   - 重要な場所の変更を、変更したプロセスとともに記録する（C3）
//   - 永続化の場所（自動起動、cron、サービスなど）と権限の設定の場所の変更を、変更したプロセスと変更の内容の抜粋とともに
//     検知結果にする（C4）
//   - 認証情報のファイルを、ふだん読むプログラム以外が読んだら検知結果にする（C8 の認証情報へのアクセス、C9 の鍵の置き場所の監視）
//   - 守る場所（文書など）で、1 つのプロセスが短時間に大量のファイルを変更したら検知結果にする（T7 ランサムウェア）
//
// 場所はディレクトリの印（root でなくても使える）で監視し、認証情報のファイルそのものにはファイルの印を付ける
// （ディレクトリの印で開く操作を受けると、ディレクトリの中のすべての開く操作が届いて重いため）。
// 守る場所はファイルシステムの印（CAP_SYS_ADMIN が必要）で監視する。守る場所の下のディレクトリは起動時に洗い出し、そこでのイベントだけを数える。

// SensitiveSpec は認証情報のファイルの指定。Path はファイル、ディレクトリ、ワイルドカード（*、?、[...]）を含むパスのどれか。
// 名前の部分がワイルドカードなら、そのディレクトリの中で名前が当てはまるファイルを対象にする。
type SensitiveSpec struct {
	Path    string   `json:"path"`
	Exclude []string `json:"exclude,omitempty"` // 対象にしない名前（ワイルドカード）
	Readers []string `json:"readers,omitempty"` // 読んでよいプログラム（プロセスの名前か、「/」で始まる実行ファイルのパス）。空ならすべての読み取りを検知結果にする
}

// FileConfig はファイルの監視の設定。
type FileConfig struct {
	Paths       []string        // 重要な場所（ファイルかディレクトリ。ディレクトリの下の階層は含まない）。変更を記録する
	Persistence []string        // 永続化の場所。変更を検知結果にする
	Privilege   []string        // 権限の設定の場所。変更を検知結果にする
	Sensitive   []SensitiveSpec // 認証情報のファイル。読み取りを検知結果にする
	Protect     []string        // 大量の変更を監視する場所（下の階層を含む）
	MassFiles   int             // この数以上のファイルを MassWindow の間に変更したら検知する。既定 200
	MassWindow  time.Duration   // 既定 30 秒
}

// enabled は監視する場所が 1 つでもあるかを返す。
func (c FileConfig) enabled() bool {
	return len(c.Paths) > 0 || len(c.Persistence) > 0 || len(c.Privilege) > 0 || len(c.Sensitive) > 0 || len(c.Protect) > 0
}

const (
	defaultMassFiles  = 200
	defaultMassWindow = 30 * time.Second
	massRealert       = 5 * time.Minute // 同じプロセスの大量の変更を、続けて検知結果にしない時間
	maxProtectedDirs  = 20000
	fileDedupe        = 2 * time.Second
	findingDedupe     = time.Minute // 同じファイル、同じプロセスの検知結果をまとめる時間
	remarkInterval    = time.Minute // 認証情報のファイルの印を付け直す間隔（置き換えられたファイル、後から作られたファイルのため）
	snippetRead       = 4096
	snippetMax        = 200
	importantMask     = fanCreate | fanDelete | fanMovedFrom | fanMovedTo | fanCloseWrite | fanAttrib | fanEventOnChild | fanOnDir
	openMask          = fanOpen | fanEventOnChild
	changeMask        = fanCreate | fanDelete | fanMovedTo | fanCloseWrite
	findingMask       = fanCreate | fanMovedTo | fanCloseWrite | fanAttrib // 永続化と権限の場所で検知結果にする操作
)

// watchKind は監視する場所の種類。
type watchKind uint8

const (
	kindRecord      watchKind = iota + 1 // 変更を記録する（C3）
	kindPersistence                      // 永続化の場所（C4）
	kindPrivilege                        // 権限の設定の場所（C4）
	kindSensitive                        // 認証情報（C8、C9）
)

// watchRule はディレクトリの中の、監視する名前と種類。
type watchRule struct {
	kind    watchKind
	name    string   // 空ならディレクトリの中のすべて。ワイルドカードを含めば path.Match で比べる
	exclude []string // 対象にしない名前（ワイルドカード）
	readers []string // kindSensitive のとき、読んでよいプログラム
}

func (r watchRule) matches(name string) bool {
	switch {
	case r.name == "":
	case hasMeta(r.name):
		if ok, _ := path.Match(r.name, name); !ok {
			return false
		}
	case r.name != name:
		return false
	}
	for _, x := range r.exclude {
		if ok, _ := path.Match(x, name); ok || x == name {
			return false
		}
	}
	return true
}

type watchDir struct {
	path  string
	rules []watchRule
}

// sensitiveFile はファイルの印を付けた認証情報のファイル。
type sensitiveFile struct {
	path    string
	readers []string
}

type massCount struct {
	start   time.Time
	files   map[string]bool // 時間枠の中で変更されたファイル（同じファイルへの複数のイベントは 1 つと数える）
	samples []string
	alerted time.Time
}

type fileMonitor struct {
	f        *os.File
	fd       int
	cfg      FileConfig
	self     int
	log      *slog.Logger
	limiter  *limiter // 記録するイベント
	flimiter *limiter // 検知結果
	procs    *procCache
	agents   *agentMatcher

	mu        sync.Mutex
	watched   map[fidKey]*watchDir
	files     map[fidKey]sensitiveFile
	fileKeys  map[string]fidKey // 認証情報のファイルのパスと、今の印の識別子
	filePaths []sensitiveFile   // 印を付け直す認証情報のファイル
	protected map[fidKey]string
	counts    map[int32]*massCount
	recent    map[string]time.Time
	findings  map[string]time.Time
	massOn    bool
	overflow  overflowLog
}

func newFileMonitor(cfg FileConfig, procs *procCache, agents *agentMatcher, log *slog.Logger) (*fileMonitor, error) {
	if cfg.MassFiles <= 0 {
		cfg.MassFiles = defaultMassFiles
	}
	if cfg.MassWindow <= 0 {
		cfg.MassWindow = defaultMassWindow
	}
	fd, err := fanotifyInit(fanClassNotif|fanCloexec|fanNonblock|fanReportDFIDNm|fanReportFID, syscall.O_RDONLY|syscall.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init（FID）: %w", err)
	}
	m := &fileMonitor{fd: fd, cfg: cfg, self: os.Getpid(), log: log, limiter: newLimiter(50, 200), flimiter: newLimiter(10, 50), procs: procs, agents: agents,
		watched: map[fidKey]*watchDir{}, files: map[fidKey]sensitiveFile{}, fileKeys: map[string]fidKey{},
		protected: map[fidKey]string{}, counts: map[int32]*massCount{}, recent: map[string]time.Time{}, findings: map[string]time.Time{}}

	for _, l := range []struct {
		paths []string
		kind  watchKind
	}{{cfg.Paths, kindRecord}, {cfg.Persistence, kindPersistence}, {cfg.Privilege, kindPrivilege}} {
		for _, p := range l.paths {
			for _, q := range expand(p) {
				m.addPath(q, l.kind)
			}
		}
	}
	for _, s := range cfg.Sensitive {
		m.addSensitive(s)
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
	if len(m.watched) == 0 && len(m.files) == 0 && len(m.filePaths) == 0 && !m.massOn {
		syscall.Close(fd)
		return nil, errors.New("fanotify: 監視できる場所がありません")
	}
	m.f = os.NewFile(uintptr(fd), "fanotify-files")
	return m, nil
}

// hasMeta はワイルドカード（*、?、[）を含むかを返す。
func hasMeta(s string) bool { return strings.ContainsAny(s, `*?[`) }

// expand はワイルドカードを含むパスを、当てはまるパスに広げる。含まなければそのまま返す。
func expand(p string) []string {
	if !hasMeta(p) {
		return []string{p}
	}
	matches, _ := filepath.Glob(p)
	return matches
}

// addPath は場所 p（ファイルかディレクトリ）を種類 kind で監視する。存在しなければ監視しない。
func (m *fileMonitor) addPath(p string, kind watchKind) {
	fi, err := os.Stat(p)
	if err != nil {
		return
	}
	dir, file := p, ""
	if !fi.IsDir() {
		dir, file = filepath.Dir(p), filepath.Base(p)
	}
	m.addRule(dir, watchRule{kind: kind, name: file}, importantMask)
}

// addRule はディレクトリ dir に印（mask）を付け、名前の条件 r を加える。
func (m *fileMonitor) addRule(dir string, r watchRule, mask uint64) {
	key, err := dirKey(dir)
	if err != nil {
		return
	}
	if err := fanotifyMark(m.fd, fanMarkAdd, mask, dir); err != nil {
		return
	}
	w := m.watched[key]
	if w == nil {
		w = &watchDir{path: dir}
		m.watched[key] = w
	}
	w.rules = append(w.rules, r)
}

// addSensitive は認証情報のファイルの指定を監視に加える。名前がワイルドカードならディレクトリの印、
// ディレクトリならその中のすべて、ファイルならファイルの印（存在しなければ、後で付け直す）。
func (m *fileMonitor) addSensitive(s SensitiveSpec) {
	clean := filepath.Clean(s.Path)
	dir, name := filepath.Dir(clean), filepath.Base(clean)
	if hasMeta(name) {
		for _, d := range expand(dir) {
			if fi, err := os.Stat(d); err == nil && fi.IsDir() {
				m.addRule(d, watchRule{kind: kindSensitive, name: name, exclude: s.Exclude, readers: s.Readers}, openMask|importantMask)
			}
		}
		return
	}
	for _, p := range expand(clean) {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			m.addRule(p, watchRule{kind: kindSensitive, exclude: s.Exclude, readers: s.Readers}, openMask|importantMask)
			continue
		}
		sf := sensitiveFile{path: p, readers: s.Readers}
		m.filePaths = append(m.filePaths, sf)
		m.markFile(sf)
	}
}

// markFile は認証情報のファイルに印を付ける（まだ付けていないか、ファイルが置き換えられていれば）。m.mu を持って呼ぶ。
func (m *fileMonitor) markFile(sf sensitiveFile) {
	fi, err := os.Stat(sf.path)
	if err != nil || !fi.Mode().IsRegular() {
		return
	}
	key, err := dirKey(sf.path)
	if err != nil || m.fileKeys[sf.path] == key {
		return
	}
	if err := fanotifyMark(m.fd, fanMarkAdd, fanOpen, sf.path); err != nil {
		return
	}
	if old, ok := m.fileKeys[sf.path]; ok {
		delete(m.files, old)
	}
	m.fileKeys[sf.path] = key
	m.files[key] = sf
}

func (m *fileMonitor) close() error { return m.f.Close() }

func (m *fileMonitor) run(ctx context.Context, emit func(*event.Event)) error {
	if len(m.filePaths) > 0 {
		go m.remarkLoop(ctx)
	}
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

// remarkLoop は認証情報のファイルの印を定期的に付け直す。
func (m *fileMonitor) remarkLoop(ctx context.Context) {
	t := time.NewTicker(remarkInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		m.mu.Lock()
		for _, sf := range m.filePaths {
			m.markFile(sf)
		}
		m.mu.Unlock()
	}
}

// handle は 1 件のイベントを処理し、記録するイベントと検知結果を返す。
func (m *fileMonitor) handle(ev fidEvent, now time.Time) []*event.Event {
	if ev.mask&fanQOverflow != 0 {
		m.overflow.note(m.log, "ファイルの監視", now)
		return nil
	}
	if ev.pid == int32(m.self) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*event.Event
	var proc *event.Process
	var anc []ancestor
	lookup := func() {
		if proc == nil {
			proc, anc = m.procs.inspect(int(ev.pid))
		}
	}

	if w := m.watched[ev.dir]; w != nil && ev.name != "" {
		var rules []watchRule
		for _, r := range w.rules {
			if r.matches(ev.name) {
				rules = append(rules, r)
			}
		}
		if len(rules) > 0 {
			p := filepath.Join(w.path, ev.name)
			for _, activity := range fileActivities(ev.mask) {
				key := fmt.Sprintf("%s\x00%d\x00%d", p, ev.pid, activity)
				if t, dup := m.recent[key]; (dup && now.Sub(t) <= fileDedupe) || !m.limiter.allow(now) {
					continue
				}
				m.recent[key] = now
				lookup()
				e := event.New(event.ClassFileSystemActivity, activity, event.SeverityLow, now)
				e.File = &event.File{Name: ev.name, Path: p}
				e.Actor = &event.Actor{Process: proc}
				m.agents.annotate(e, proc, anc)
				out = append(out, e)
			}
			if len(m.recent) > 4096 {
				for k, t := range m.recent {
					if now.Sub(t) > fileDedupe {
						delete(m.recent, k)
					}
				}
			}
			for _, r := range rules {
				switch {
				case (r.kind == kindPersistence || r.kind == kindPrivilege) && ev.mask&findingMask != 0:
					lookup()
					if e := m.changeFinding(r.kind, p, ev, proc, anc, now); e != nil {
						out = append(out, e)
					}
				case r.kind == kindSensitive && ev.mask&fanOpen != 0:
					lookup()
					if e := m.readFinding(p, r.readers, ev.pid, proc, anc, now); e != nil {
						out = append(out, e)
					}
				}
			}
		}
	}
	if sf, ok := m.files[ev.file]; ok && ev.mask&fanOpen != 0 {
		lookup()
		if e := m.readFinding(sf.path, sf.readers, ev.pid, proc, anc, now); e != nil {
			out = append(out, e)
		}
	}

	if dir, ok := m.protected[ev.dir]; ok && ev.mask&changeMask != 0 {
		p := filepath.Join(dir, ev.name)
		if ev.mask&fanOnDir != 0 {
			if ev.mask&fanCreate != 0 && len(m.protected) < maxProtectedDirs {
				if key, err := dirKey(p); err == nil {
					m.protected[key] = p // 新しく作られたディレクトリも監視する
				}
			}
		} else if e := m.count(ev.pid, p, now); e != nil {
			out = append(out, e)
		}
	}
	return out
}

// dedupeFinding は、同じ種類、ファイル、プロセスの検知結果を findingDedupe の間にもう出していれば false を返す。
func (m *fileMonitor) dedupeFinding(kind string, path string, pid int32, now time.Time) bool {
	key := fmt.Sprintf("%s\x00%s\x00%d", kind, path, pid)
	if t, ok := m.findings[key]; ok && now.Sub(t) < findingDedupe {
		return false
	}
	if !m.flimiter.allow(now) {
		return false
	}
	if len(m.findings) > 4096 {
		for k, t := range m.findings {
			if now.Sub(t) >= findingDedupe {
				delete(m.findings, k)
			}
		}
	}
	m.findings[key] = now
	return true
}

// changeFinding は永続化か権限の設定の場所の変更を検知結果にする。永続化の場所では、変更の内容の抜粋（実行する命令など）を添える。
func (m *fileMonitor) changeFinding(kind watchKind, path string, ev fidEvent, proc *event.Process, anc []ancestor, now time.Time) *event.Event {
	category, title, typ := "privilege", "権限の設定の変更", event.FindingTypePrivilegeChange
	if kind == kindPersistence {
		category, title, typ = "persistence", "永続化の場所の変更", event.FindingTypePersistence
	}
	var content string
	if kind == kindPersistence && ev.mask&fanDelete == 0 {
		content = snippet(path)
		// 作られたばかりで中身のないファイルは、書き終わり（CLOSE_WRITE）のイベントで内容とともに検知結果にする。
		if content == "" && ev.mask&(fanCloseWrite|fanAttrib|fanMovedTo) == 0 {
			if fi, err := os.Lstat(path); err == nil && fi.Mode().IsRegular() && fi.Size() == 0 {
				return nil
			}
		}
	}
	if !m.dedupeFinding(category, path, ev.pid, now) {
		return nil
	}
	op := opLabel(ev.mask)
	what := map[string]string{"persistence": "永続化の場所", "privilege": "権限の設定"}[category]
	msg := fmt.Sprintf("%s が%sのファイル %s を%s", who(proc, int(ev.pid)), what, path, op)
	detail := map[string]any{"category": category, "operation": op}
	if content != "" {
		msg += fmt.Sprintf("（内容: %s）", content)
		detail["snippet"] = content
	}
	e := event.New(event.ClassDetectionFinding, event.FindingCreate, event.SeverityMedium, now)
	e.Message = msg
	e.FindingInfo = &event.FindingInfo{UID: randomID(), Title: title, Desc: msg, Types: []string{typ}}
	e.Evidences = []event.Evidence{{File: &event.File{Name: filepath.Base(path), Path: path}, Process: proc}}
	e.Unmapped = map[string]any{"file_change": detail}
	m.agents.annotate(e, proc, anc)
	return e
}

// readFinding は、認証情報のファイルを、ふだん読むプログラム以外が読んだことを検知結果にする。
func (m *fileMonitor) readFinding(path string, readers []string, pid int32, proc *event.Process, anc []ancestor, now time.Time) *event.Event {
	if allowedReader(proc, readers) || !m.dedupeFinding("credential", path, pid, now) {
		return nil
	}
	msg := fmt.Sprintf("%s が認証情報のファイル %s を読みました", who(proc, int(pid)), path)
	e := event.New(event.ClassDetectionFinding, event.FindingCreate, event.SeverityMedium, now)
	e.Message = msg
	e.FindingInfo = &event.FindingInfo{UID: randomID(), Title: "認証情報へのアクセス", Desc: msg, Types: []string{event.FindingTypeCredentialAccess}}
	e.Evidences = []event.Evidence{{File: &event.File{Name: filepath.Base(path), Path: path}, Process: proc}}
	e.Unmapped = map[string]any{"credential": map[string]any{"readers": readers}}
	m.agents.annotate(e, proc, anc)
	return e
}

// allowedReader は、プロセス proc が readers（プロセスの名前か実行ファイルのパス）のどれかかを返す。
// プロセスが分からなければ（すでに終わっていて、起動の記録もなければ）false。
func allowedReader(proc *event.Process, readers []string) bool {
	if proc == nil || proc.Name == "" {
		return false
	}
	exe := ""
	if proc.File != nil {
		exe = proc.File.Path
	}
	for _, r := range readers {
		if r == "" {
			continue
		}
		if strings.HasPrefix(r, "/") {
			if r == exe {
				return true
			}
			continue
		}
		if r == proc.Name || (exe != "" && r == filepath.Base(exe)) {
			return true
		}
	}
	return false
}

// who はプロセスの表し方（名前と PID）を返す。
func who(proc *event.Process, pid int) string {
	switch {
	case proc != nil && proc.Name != "":
		return fmt.Sprintf("%s（PID %d）", proc.Name, proc.PID)
	case pid > 0:
		return fmt.Sprintf("不明なプロセス（PID %d）", pid)
	}
	return "不明なプロセス"
}

// opLabel は操作の表し方を返す。fanotify がまとめた複数の操作では、作成、名前の変更、更新、属性の変更、削除の順に 1 つ選ぶ。
func opLabel(mask uint64) string {
	switch {
	case mask&fanCreate != 0:
		return "作成しました"
	case mask&(fanMovedTo|fanMovedFrom) != 0:
		return "名前を変えました"
	case mask&fanCloseWrite != 0:
		return "書き換えました"
	case mask&fanAttrib != 0:
		return "属性を変えました"
	case mask&fanDelete != 0:
		return "削除しました"
	}
	return "操作しました"
}

// snippet は、永続化の場所に書かれたファイルの要点を 1 行で返す。systemd のユニットや autostart の Exec の行があればそれを、
// なければ最後の注釈でない行を使う。シンボリックリンクなら指す先。読めない、文字でない、大きすぎるファイルは空。
func snippet(path string) string {
	fi, err := os.Lstat(path)
	if err != nil {
		return ""
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil {
			return ""
		}
		return trimSnippet("→ " + target)
	}
	if !fi.Mode().IsRegular() || fi.Size() > 1<<20 {
		return ""
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, snippetRead)
	n, _ := f.Read(buf)
	buf = buf[:n]
	if bytes.IndexByte(buf, 0) >= 0 {
		return ""
	}
	if !utf8.Valid(buf) {
		if i := bytes.LastIndexByte(buf, '\n'); i > 0 && utf8.Valid(buf[:i]) {
			buf = buf[:i]
		} else {
			return ""
		}
	}
	lines := strings.Split(string(buf), "\n")
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "ExecStart=") || strings.HasPrefix(t, "Exec=") {
			return trimSnippet(t)
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		t := strings.TrimSpace(lines[i])
		if t != "" && !strings.HasPrefix(t, "#") {
			return trimSnippet(t)
		}
	}
	return ""
}

func trimSnippet(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > snippetMax {
		r := []rune(s)
		s = string(r[:snippetMax]) + "…"
	}
	return s
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
	proc, anc := m.procs.inspect(int(pid))
	msg := fmt.Sprintf("%s が %s 以内に %d 個以上のファイルを変更しました（例: %s）", who(proc, int(pid)), m.cfg.MassWindow, n, strings.Join(c.samples, "、"))
	e := event.New(event.ClassDetectionFinding, event.FindingCreate, event.SeverityHigh, now)
	e.Message = msg
	e.FindingInfo = &event.FindingInfo{UID: randomID(), Title: "短時間の大量変更", Desc: msg, Types: []string{event.FindingTypeMassChange}}
	e.Evidences = []event.Evidence{{Process: proc}}
	m.agents.annotate(e, proc, anc)
	return e
}

// fileActivities はイベントのマスクを OCSF の操作の列にする。fanotify は、読み出されていない同じファイル、
// 同じプロセスのイベントを 1 件にまとめる（作成と書き込みなど）ので、起きた順に近い並びですべて返す。
// 開く操作は記録しない（認証情報の読み取りの検知結果だけにする）。
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
