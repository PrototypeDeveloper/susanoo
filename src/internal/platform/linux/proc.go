//go:build linux

package linux

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"susanoo/internal/event"
)

// maxCmdLine はイベントに入れるコマンドラインの上限。
const maxCmdLine = 4096

// maxAncestors は辿る祖先のプロセスの数の上限。
const maxAncestors = 8

// ancestor は祖先のプロセスの、検知に使う情報。
type ancestor struct {
	pid  int
	uid  string // 実 UID（分からなければ空）
	name string // comm
	exe  string // 実行ファイルのパス（分からなければ空）
	argv string // コマンドライン（空白区切り。agentMatcher が使う）
}

// processInfo は /proc からプロセスの情報を集める。すでに終了したプロセスは PID だけになる。
func processInfo(pid int) *event.Process {
	p, _ := inspect(pid)
	return p
}

// inspect は /proc からプロセスの情報と、祖先のプロセス（親から順に、maxAncestors まで）を集める。
// 祖先は、親子関係の検知（process.lineage、process.parent_process）、権限昇格の検知、AI エージェントの帰属に使う。
func inspect(pid int) (*event.Process, []ancestor) {
	if pid <= 0 {
		return nil, nil
	}
	self := readAncestor(pid)
	p := &event.Process{PID: pid, Name: self.name}
	if cmd := readCmdline(pid); cmd != "" {
		p.CmdLine = cmd
	}
	if self.exe != "" {
		p.File = &event.File{Name: filepath.Base(self.exe), Path: self.exe}
	}
	if self.uid != "" {
		p.User = &event.User{UID: self.uid}
	}
	anc := ancestry(pid)
	if len(anc) > 0 {
		a := anc[0]
		p.Parent = &event.Process{PID: a.pid, Name: a.name}
		if a.exe != "" {
			p.Parent.File = &event.File{Name: filepath.Base(a.exe), Path: a.exe}
		}
		if a.uid != "" {
			p.Parent.User = &event.User{UID: a.uid}
		}
		for i := len(anc) - 1; i >= 0; i-- {
			if anc[i].exe != "" {
				p.Lineage = append(p.Lineage, anc[i].exe)
			}
		}
	}
	return p, anc
}

// ancestry は pid の祖先のプロセスを、親から順に返す（PID 1 とカーネルのスレッドの手前まで、maxAncestors まで）。
func ancestry(pid int) []ancestor {
	var out []ancestor
	seen := map[int]bool{pid: true}
	_, ppid := readStatus(procPath(pid, "status"))
	for ppid > 1 && !seen[ppid] && len(out) < maxAncestors {
		seen[ppid] = true
		a := readAncestor(ppid)
		out = append(out, a)
		_, ppid = readStatus(procPath(ppid, "status"))
	}
	return out
}

// readAncestor は祖先のプロセス 1 つの情報を読む。
func readAncestor(pid int) ancestor {
	a := ancestor{pid: pid}
	if b, err := os.ReadFile(procPath(pid, "comm")); err == nil {
		a.name = strings.TrimSpace(string(b))
	}
	if exe, err := os.Readlink(procPath(pid, "exe")); err == nil {
		a.exe = strings.TrimSuffix(exe, " (deleted)")
	}
	a.uid, _ = readStatus(procPath(pid, "status"))
	a.argv = readCmdline(pid)
	return a
}

// readCmdline は /proc/<pid>/cmdline を空白区切りで読む（maxCmdLine まで）。
func readCmdline(pid int) string {
	b, err := os.ReadFile(procPath(pid, "cmdline"))
	if err != nil {
		return ""
	}
	b = bytes.TrimRight(b, "\x00")
	cmd := string(bytes.ReplaceAll(b, []byte{0}, []byte{' '}))
	if len(cmd) > maxCmdLine {
		cmd = cmd[:maxCmdLine]
	}
	return cmd
}

func procPath(pid int, name string) string {
	return filepath.Join("/proc", strconv.Itoa(pid), name)
}

// readStatus は /proc/<pid>/status から実 UID と親の PID を読む。
func readStatus(path string) (uid string, ppid int) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(val)
		if len(fields) == 0 {
			continue
		}
		switch key {
		case "Uid":
			uid = fields[0]
		case "PPid":
			ppid, _ = strconv.Atoi(fields[0])
		}
	}
	return uid, ppid
}

// escalation は、root の権限で起動したプロセス p が、一般の利用者のプロセスから起動されたか（権限昇格）を調べる（C4）。
// 一般の利用者の祖先が親か祖父（sudo などの仲介を 1 つ挟む）にあるときだけ検知する。root の権限で動き始めた
// シェルの中の 2 つ目以降のコマンドは、祖先が遠くなるので重ねて検知しない。
// 検知したら、昇格の元のプロセス（一般の利用者のもの）と、経路（元のプロセスから p まで）の名前を返す。
func escalation(p *event.Process, anc []ancestor) (origin ancestor, via []string, ok bool) {
	if p == nil || p.User == nil || p.User.UID != "0" {
		return ancestor{}, nil, false
	}
	for i := 0; i < len(anc) && i < 2; i++ {
		a := anc[i]
		if a.uid == "" || a.uid == "0" {
			continue
		}
		for j := i; j >= 0; j-- {
			via = append(via, anc[j].name)
		}
		return a, append(via, p.Name), true
	}
	return ancestor{}, nil, false
}

// procCache は、起動を記録したプロセスの情報を覚えておき、すぐに終わったプロセス（/proc から消えた後）でも
// 名前や祖先を引けるようにする。ファイルを読んですぐ終わるプログラムの見分けに使う。
type procCache struct {
	mu sync.Mutex
	m  map[int]cachedProc
}

type cachedProc struct {
	at   time.Time
	proc *event.Process
	anc  []ancestor
}

const (
	procCacheMax = 10000
	procCacheTTL = 10 * time.Minute
)

func newProcCache() *procCache { return &procCache{m: map[int]cachedProc{}} }

// put は起動を記録したプロセスの情報を覚える。
func (c *procCache) put(pid int, p *event.Process, anc []ancestor, now time.Time) {
	if c == nil || p == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= procCacheMax {
		for k, v := range c.m {
			if now.Sub(v.at) > procCacheTTL {
				delete(c.m, k)
			}
		}
		if len(c.m) >= procCacheMax {
			return
		}
	}
	c.m[pid] = cachedProc{at: now, proc: p, anc: anc}
}

// inspect は /proc からプロセスの情報を集め、プロセスがもう終わっていれば、覚えていた情報（あれば）を返す。
func (c *procCache) inspect(pid int) (*event.Process, []ancestor) {
	p, anc := inspect(pid)
	if p == nil || p.Name != "" || c == nil {
		return p, anc
	}
	c.mu.Lock()
	cached, ok := c.m[pid]
	c.mu.Unlock()
	if !ok || time.Since(cached.at) > procCacheTTL {
		return p, anc
	}
	q := *cached.proc
	return &q, cached.anc
}
