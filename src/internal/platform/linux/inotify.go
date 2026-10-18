//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"

	"susanoo/internal/honeytoken"
)

const inotifyHeaderLen = 16 // struct inotify_event の name を除く長さ

const inotifyMask = syscall.IN_OPEN | syscall.IN_ACCESS | syscall.IN_MODIFY | syscall.IN_ATTRIB |
	syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF

type inoEvent struct {
	wd   int32
	mask uint32
}

// parseInotify は read(2) で読んだイベントの列を解析する。解析できた分と、あればエラーを返す。
func parseInotify(buf []byte) ([]inoEvent, error) {
	var evs []inoEvent
	for len(buf) > 0 {
		if len(buf) < inotifyHeaderLen {
			return evs, fmt.Errorf("inotify: イベントが途中で切れています（%d バイト）", len(buf))
		}
		nameLen := binary.NativeEndian.Uint32(buf[12:16])
		total := uint64(inotifyHeaderLen) + uint64(nameLen)
		if total > uint64(len(buf)) {
			return evs, fmt.Errorf("inotify: イベントの長さが不正です（%d）", total)
		}
		evs = append(evs, inoEvent{
			wd:   int32(binary.NativeEndian.Uint32(buf[0:4])),
			mask: binary.NativeEndian.Uint32(buf[4:8]),
		})
		buf = buf[total:]
	}
	return evs, nil
}

func inotifyOp(mask uint32) string {
	switch {
	case mask&syscall.IN_DELETE_SELF != 0:
		return honeytoken.OpDelete
	case mask&syscall.IN_MOVE_SELF != 0:
		return honeytoken.OpMove
	case mask&syscall.IN_MODIFY != 0:
		return honeytoken.OpModify
	case mask&syscall.IN_ATTRIB != 0:
		return honeytoken.OpAttrib
	case mask&syscall.IN_OPEN != 0:
		return honeytoken.OpOpen
	case mask&syscall.IN_ACCESS != 0:
		return honeytoken.OpAccess
	}
	return ""
}

// inotifyWatcher は inotify でおとりのファイルを監視する。権限は要らないが、触ったプロセスは分からない。
type inotifyWatcher struct {
	f   *os.File
	wds map[int32]int
}

func newInotify(paths []string) (watcher, error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify_init1: %w", err)
	}
	w := &inotifyWatcher{wds: map[int32]int{}}
	for i, p := range paths {
		wd, err := syscall.InotifyAddWatch(fd, p, inotifyMask)
		if err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("inotify_add_watch %s: %w", p, err)
		}
		w.wds[int32(wd)] = i
	}
	w.f = os.NewFile(uintptr(fd), "inotify")
	return w, nil
}

func (w *inotifyWatcher) name() string { return "inotify" }
func (w *inotifyWatcher) close() error { return w.f.Close() }

func (w *inotifyWatcher) run(ctx context.Context, out chan<- fileEvent) error {
	buf := make([]byte, 64*1024)
	for {
		n, err := w.f.Read(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) {
				return ctx.Err()
			}
			return fmt.Errorf("inotify: %w", err)
		}
		evs, perr := parseInotify(buf[:n])
		for _, ev := range evs {
			i, ok := w.wds[ev.wd]
			op := inotifyOp(ev.mask)
			if !ok || op == "" {
				continue
			}
			select {
			case out <- fileEvent{token: i, op: op}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if perr != nil {
			return perr
		}
	}
}
