//go:build linux

package linux

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"susanoo/internal/event"
)

// maxCmdLine はイベントに入れるコマンドラインの上限。
const maxCmdLine = 4096

// processInfo は /proc からプロセスの情報を集める。すでに終了したプロセスは PID だけになる。
func processInfo(pid int) *event.Process {
	if pid <= 0 {
		return nil
	}
	dir := filepath.Join("/proc", strconv.Itoa(pid))
	p := &event.Process{PID: pid}
	if b, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
		p.Name = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		b = bytes.TrimRight(b, "\x00")
		cmd := string(bytes.ReplaceAll(b, []byte{0}, []byte{' '}))
		if len(cmd) > maxCmdLine {
			cmd = cmd[:maxCmdLine]
		}
		p.CmdLine = cmd
	}
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		p.File = &event.File{Name: filepath.Base(exe), Path: exe}
	}
	uid, ppid := readStatus(filepath.Join(dir, "status"))
	if uid != "" {
		p.User = &event.User{UID: uid}
	}
	if ppid > 0 {
		parent := &event.Process{PID: ppid}
		if b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(ppid), "comm")); err == nil {
			parent.Name = strings.TrimSpace(string(b))
		}
		p.Parent = parent
	}
	return p
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
