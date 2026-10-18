//go:build linux

package linux

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"susanoo/internal/platform"
)

// 証拠の保全（C11）。隔離の指示を受けたときなどに、プロセスの一覧、ソケットと持ち主のプロセス、カーネルモジュール、
// ログの末尾を集める。集めるのは執行部（root。ほかの利用者のプロセスの情報と、root だけが読めるログを読める）。

// DefaultEvidenceLogs は既定で末尾を集めるログ。ない場所は飛ばす。journald だけの環境ではテキストのログがないため集まらない。
func DefaultEvidenceLogs() []string {
	return []string{"/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log", "/var/log/secure", "/var/log/messages"}
}

const (
	maxSnapshotProcs = 10000
	maxSnapshotConns = 10000
	logTailLines     = 200
	logTailBytes     = 64 << 10
	maxLogLine       = 2048
	clockTicks       = 100 // USER_HZ。Linux の主なアーキテクチャでは 100（/proc/<pid>/stat の starttime の単位）
	tcpAllStates     = 0xFFE
)

var tcpStates = map[uint8]string{
	1: "established", 2: "syn_sent", 3: "syn_recv", 4: "fin_wait1", 5: "fin_wait2", 6: "time_wait",
	7: "close", 8: "close_wait", 9: "last_ack", 10: "listen", 11: "closing",
}

// Snapshot は今の端末の状態を集める（platform.Collector）。
func (p *Platform) Snapshot(ctx context.Context) (*platform.Snapshot, error) {
	s := &platform.Snapshot{}
	s.Processes = snapshotProcesses(ctx, &s.Errors)
	s.Connections = snapshotConns(&s.Errors)
	if data, err := os.ReadFile(modulesPath); err == nil {
		s.Modules = parseModules(data)
	}
	logs := p.cfg.EvidenceLogs
	if logs == nil {
		logs = DefaultEvidenceLogs()
	}
	for _, path := range logs {
		if ctx.Err() != nil {
			break
		}
		l, err := tailLog(path, logTailLines, logTailBytes)
		switch {
		case err == nil:
			s.Logs = append(s.Logs, l)
		case !os.IsNotExist(err):
			s.Errors = append(s.Errors, fmt.Sprintf("ログ %s: %v", path, err))
		}
	}
	return s, ctx.Err()
}

// bootTime は起動した時刻（UNIX 時間の秒）を /proc/stat の btime から読む。
func bootTime() int64 {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "btime "); ok {
			n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			return n
		}
	}
	return 0
}

// snapshotProcesses は動いているプロセスの一覧を返す（カーネルのスレッドは除く）。
func snapshotProcesses(ctx context.Context, errs *[]string) []platform.SnapshotProcess {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		*errs = append(*errs, "プロセスの一覧: "+err.Error())
		return nil
	}
	boot := bootTime()
	var out []platform.SnapshotProcess
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || ctx.Err() != nil {
			continue
		}
		uid, ppid := readStatus(procPath(pid, "status"))
		if uid == "" || pid == 2 || ppid == 2 {
			continue // 終わったプロセスか、カーネルのスレッド
		}
		if len(out) >= maxSnapshotProcs {
			*errs = append(*errs, fmt.Sprintf("プロセスが %d を超えたため、残りを省きました", maxSnapshotProcs))
			break
		}
		a := readAncestor(pid)
		sp := platform.SnapshotProcess{PID: pid, PPID: ppid, UID: uid, Name: a.name, Exe: a.exe, CmdLine: a.argv}
		if st, ok := startTime(pid); ok && boot > 0 {
			sp.Started = (boot + int64(st/clockTicks)) * 1000
		}
		out = append(out, sp)
	}
	return out
}

// snapshotConns は TCP と UDP のソケット（待ち受けを含む）と、持ち主のプロセスを返す。
func snapshotConns(errs *[]string) []platform.SnapshotConn {
	owners := socketOwners()
	names := map[int]string{}
	var out []platform.SnapshotConn
	for _, fam := range []uint8{syscall.AF_INET, syscall.AF_INET6} {
		for _, proto := range []uint8{syscall.IPPROTO_TCP, syscall.IPPROTO_UDP} {
			socks, err := dumpSockets(fam, proto, tcpAllStates)
			if err != nil {
				*errs = append(*errs, fmt.Sprintf("ソケットの一覧（%d/%d）: %v", fam, proto, err))
			}
			for _, s := range socks {
				if len(out) >= maxSnapshotConns {
					*errs = append(*errs, fmt.Sprintf("ソケットが %d を超えたため、残りを省きました", maxSnapshotConns))
					return out
				}
				c := platform.SnapshotConn{Proto: "tcp", State: tcpStates[s.state], Local: s.local.String(), UID: strconv.Itoa(int(s.uid))}
				if proto == syscall.IPPROTO_UDP {
					c.Proto = "udp"
					c.State = map[bool]string{true: "connected", false: "bound"}[s.state == tcpEstablished]
				}
				if s.peer.Port() != 0 || (s.peer.Addr().IsValid() && !s.peer.Addr().IsUnspecified()) {
					c.Remote = s.peer.String()
				}
				if pid, ok := owners[s.inode]; ok {
					c.PID = pid
					if _, ok := names[pid]; !ok {
						b, _ := os.ReadFile(procPath(pid, "comm"))
						names[pid] = strings.TrimSpace(string(b))
					}
					c.Process = names[pid]
				}
				out = append(out, c)
			}
		}
	}
	slices.SortFunc(out, func(a, b platform.SnapshotConn) int {
		return strings.Compare(a.Proto+a.State+a.Local, b.Proto+b.State+b.Local)
	})
	return out
}

// tailLog はログのファイルの末尾（lines 行、maxBytes まで）を返す。1 行は maxLogLine 文字までに切る。
func tailLog(path string, lines int, maxBytes int64) (platform.SnapshotLog, error) {
	l := platform.SnapshotLog{Path: path}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return l, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return l, err
	}
	if !fi.Mode().IsRegular() {
		return l, fmt.Errorf("通常のファイルではありません")
	}
	start := max(fi.Size()-maxBytes, 0)
	buf := make([]byte, fi.Size()-start)
	n, err := f.ReadAt(buf, start)
	if err != nil && err != io.EOF {
		return l, err
	}
	buf = buf[:n]
	if start > 0 {
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:] // 途中から読んだ最初の行は捨てる
		}
		l.Truncated = true
	}
	all := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if len(all) == 1 && all[0] == "" {
		all = nil
	}
	if len(all) > lines {
		all = all[len(all)-lines:]
		l.Truncated = true
	}
	for _, s := range all {
		s = strings.ToValidUTF8(s, "?")
		if utf8.RuneCountInString(s) > maxLogLine {
			s = string([]rune(s)[:maxLogLine]) + "…"
		}
		l.Lines = append(l.Lines, s)
	}
	if l.Lines == nil {
		l.Lines = []string{}
	}
	return l, nil
}

// evidenceLogsValid はログの場所が絶対パスかを確かめる。
func evidenceLogsValid(paths []string) error {
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("証拠のログ %q は絶対パスで書いてください", p)
		}
	}
	return nil
}
