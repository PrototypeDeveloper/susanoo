//go:build linux

package linux

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"susanoo/internal/event"
)

// プロセスの監視（C1）。実ファイルを持つファイルシステムごとに fanotify の FAN_OPEN_EXEC を受け取り、
// 実行されたファイル（イベントの fd）のパスとハッシュと、プロセスの情報を記録する。
// proc connector と違ってネットワーク名前空間の中（コンテナなど）でも動く。終了は /proc で確かめる。
// CAP_SYS_ADMIN が必要。

const (
	execInfoDelay = 30 * time.Millisecond // execve が新しいプロセスの情報に切り替わるのを待つ時間
	exitPoll      = 2 * time.Second
	maxTracked    = 10000
)

// 監視しない（実行ファイルを置かない）ファイルシステム。
var pseudoFS = map[string]bool{
	"proc": true, "sysfs": true, "cgroup": true, "cgroup2": true, "devpts": true, "securityfs": true,
	"debugfs": true, "tracefs": true, "pstore": true, "bpf": true, "mqueue": true, "hugetlbfs": true,
	"configfs": true, "fusectl": true, "binfmt_misc": true, "autofs": true, "efivarfs": true, "nsfs": true,
	"rpc_pipefs": true, "devtmpfs": true,
}

type tracked struct {
	start uint64 // /proc/<pid>/stat の starttime（PID の使い回しを見分ける）
	name  string
	exe   string
}

type execMonitor struct {
	f       *os.File
	hasher  *hasher
	self    int
	limiter *limiter
	log     *slog.Logger

	mu      sync.Mutex
	tracked map[int]tracked
}

// mountPoints は監視するファイルシステムのマウント位置を、デバイスごとに 1 つずつ返す。
func mountPoints() ([]string, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		sep := -1
		for i, x := range fields {
			if x == "-" {
				sep = i
				break
			}
		}
		if len(fields) < 5 || sep < 0 || sep+1 >= len(fields) {
			continue
		}
		dev, mp, fstype := fields[2], unescapeMount(fields[4]), fields[sep+1]
		if pseudoFS[fstype] || seen[dev] {
			continue
		}
		seen[dev] = true
		out = append(out, mp)
	}
	return out, sc.Err()
}

// unescapeMount は mountinfo の 8 進数のエスケープ（\040 など）を戻す。
func unescapeMount(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func newExecMonitor(log *slog.Logger) (*execMonitor, error) {
	fd, err := fanotifyInit(fanClassNotif|fanCloexec|fanNonblock, syscall.O_RDONLY|syscall.O_LARGEFILE|syscall.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w", err)
	}
	mounts, err := mountPoints()
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	marked := 0
	for _, mp := range mounts {
		if fanotifyMark(fd, fanMarkAdd|fanMarkFS, fanOpenExec, mp) == nil {
			marked++
		}
	}
	if marked == 0 {
		syscall.Close(fd)
		return nil, errors.New("fanotify: 実行を監視できるファイルシステムがありません")
	}
	return &execMonitor{
		f: os.NewFile(uintptr(fd), "fanotify-exec"), hasher: newHasher(), self: os.Getpid(),
		limiter: newLimiter(100, 500), log: log, tracked: map[int]tracked{},
	}, nil
}

func (m *execMonitor) close() error { return m.f.Close() }

func (m *execMonitor) run(ctx context.Context, emit func(*event.Event)) error {
	go m.pollExits(ctx, emit)
	buf := make([]byte, 64*1024)
	for {
		n, err := m.f.Read(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) {
				return ctx.Err()
			}
			return fmt.Errorf("fanotify: %w", err)
		}
		evs, perr := parseFanotify(buf[:n])
		for _, ev := range evs {
			if ev.fd < 0 {
				continue
			}
			path, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", ev.fd))
			pid := int(ev.pid)
			if ev.mask&fanOpenExec == 0 || pid == m.self || !m.limiter.allow(time.Now()) {
				syscall.Close(int(ev.fd))
				continue
			}
			sum := m.hasher.hashFD(int(ev.fd))
			syscall.Close(int(ev.fd))
			go m.launched(ctx, pid, path, sum, emit)
		}
		if perr != nil {
			return perr
		}
	}
}

// launched は、execve が終わるのを少し待ってからプロセスの情報を集めて記録する。
func (m *execMonitor) launched(ctx context.Context, pid int, path, sum string, emit func(*event.Event)) {
	select {
	case <-time.After(execInfoDelay):
	case <-ctx.Done():
		return
	}
	p := processInfo(pid)
	if p == nil {
		p = &event.Process{PID: pid} // 別の PID 名前空間のプロセス（fanotify は PID を 0 で渡す）
	}
	if p.Parent != nil && p.Parent.PID == m.self {
		return // 自分が実行した nft など
	}
	// /proc の実行ファイルがまだ切り替わっていなければ、コマンドラインは実行前のものなので使わない。
	if p.File == nil || p.File.Path != path {
		select {
		case <-time.After(4 * execInfoDelay):
		case <-ctx.Done():
			return
		}
		if q := processInfo(pid); q != nil && q.File != nil && q.File.Path == path {
			p = q
		} else {
			p.CmdLine = ""
		}
	}
	p.File = &event.File{Name: filepath.Base(path), Path: path}
	if sum != "" {
		p.File.Hashes = []event.Fingerprint{{AlgorithmID: event.HashSHA256, Value: sum}}
	}
	if start, ok := startTime(pid); ok {
		m.mu.Lock()
		if len(m.tracked) < maxTracked {
			m.tracked[pid] = tracked{start: start, name: p.Name, exe: path}
		}
		m.mu.Unlock()
	}
	e := event.New(event.ClassProcessActivity, event.ProcessLaunch, event.SeverityInformational, time.Now())
	e.Process = p
	emit(e)
}

// pollExits は、起動を記録したプロセスが終わったかを定期的に確かめて記録する。
func (m *execMonitor) pollExits(ctx context.Context, emit func(*event.Event)) {
	t := time.NewTicker(exitPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var ended []int
		var info []tracked
		m.mu.Lock()
		for pid, tr := range m.tracked {
			if start, ok := startTime(pid); !ok || start != tr.start {
				ended = append(ended, pid)
				info = append(info, tr)
				delete(m.tracked, pid)
			}
		}
		m.mu.Unlock()
		for i, pid := range ended {
			e := event.New(event.ClassProcessActivity, event.ProcessTerminate, event.SeverityInformational, time.Now())
			e.Process = &event.Process{PID: pid, Name: info[i].name, File: &event.File{Name: filepath.Base(info[i].exe), Path: info[i].exe}}
			emit(e)
		}
		if n := m.limiter.takeDropped(); n > 0 {
			m.log.Warn("プロセスの起動が多すぎるため、一部を記録しませんでした", "件数", n)
		}
	}
}

// startTime は /proc/<pid>/stat の starttime（22 番目の項目）を返す。
func startTime(pid int) (uint64, bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, false
	}
	// comm は括弧で囲まれ、空白や括弧を含みうるので、最後の「)」の後ろから数える。
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return 0, false
	}
	fields := strings.Fields(string(b[i+1:]))
	if len(fields) < 20 {
		return 0, false
	}
	v, err := strconv.ParseUint(fields[19], 10, 64)
	return v, err == nil
}
