//go:build linux && (amd64 || arm64)

package linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func fanotifyInit(flags, eventFFlags uint) (int, error) {
	fd, _, errno := syscall.Syscall(syscall.SYS_FANOTIFY_INIT, uintptr(flags), uintptr(eventFFlags), 0)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

func fanotifyMark(fd int, flags uint, mask uint64, path string) error {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	dirfd := -100 // AT_FDCWD
	_, _, errno := syscall.Syscall6(syscall.SYS_FANOTIFY_MARK, uintptr(fd), uintptr(flags), uintptr(mask),
		uintptr(dirfd), uintptr(unsafe.Pointer(p)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func newFanotify(paths []string) (watcher, error) {
	fd, err := fanotifyInit(fanClassNotif|fanCloexec|fanNonblock, syscall.O_RDONLY|syscall.O_LARGEFILE|syscall.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w", err)
	}
	w := &fanotifyWatcher{tokens: map[fileID]int{}}
	for i, p := range paths {
		if err := fanotifyMark(fd, fanMarkAdd, fanOpen|fanAccess|fanModify|fanOpenExec, p); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("fanotify_mark %s: %w", p, err)
		}
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			syscall.Close(fd)
			return nil, err
		}
		w.tokens[fileID{uint64(st.Dev), st.Ino}] = i
	}
	// 非ブロッキングの fd なので、os.File の読み込みは Go のポーラーで待ち、Close で中断できる。
	w.f = os.NewFile(uintptr(fd), "fanotify")
	w.fid, w.names = watchTokenDirs(paths)
	return w, nil
}

func (w *fanotifyWatcher) name() string { return "fanotify" }

func (w *fanotifyWatcher) close() error {
	if w.fid != nil {
		w.fid.Close()
	}
	return w.f.Close()
}

func (w *fanotifyWatcher) run(ctx context.Context, out chan<- fileEvent) error {
	errc := make(chan error, 2)
	go func() { errc <- w.readFiles(ctx, out) }()
	if w.fid != nil {
		go func() { errc <- w.readDirs(ctx, out) }()
	}
	return <-errc
}

// readFiles はおとりのファイルそのものへの読み書きを取り出す。
func (w *fanotifyWatcher) readFiles(ctx context.Context, out chan<- fileEvent) error {
	buf := make([]byte, 64*1024)
	for {
		n, err := w.f.Read(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) {
				return ctx.Err()
			}
			return fmt.Errorf("fanotify: %w", err)
		}
		evs, perr := parseFanotify(buf[:n])
		for i, ev := range evs {
			fe, ok := w.convert(ev)
			if !ok {
				continue
			}
			select {
			case out <- fe:
			case <-ctx.Done():
				closeFDs(evs[i+1:])
				return ctx.Err()
			}
		}
		if perr != nil {
			return perr
		}
	}
}

// convert はイベントの fd からおとりを特定し、fd を閉じる。
func (w *fanotifyWatcher) convert(ev fanMeta) (fileEvent, bool) {
	if ev.fd < 0 {
		return fileEvent{}, false // キューのあふれなど、ファイルを伴わないイベント
	}
	var st syscall.Stat_t
	err := syscall.Fstat(int(ev.fd), &st)
	syscall.Close(int(ev.fd))
	if err != nil {
		return fileEvent{}, false
	}
	i, ok := w.tokens[fileID{uint64(st.Dev), st.Ino}]
	op := fanotifyOp(ev.mask)
	if !ok || op == "" {
		return fileEvent{}, false
	}
	return fileEvent{token: i, op: op, pid: int(ev.pid)}, true
}

func closeFDs(evs []fanMeta) {
	for _, ev := range evs {
		if ev.fd >= 0 {
			syscall.Close(int(ev.fd))
		}
	}
}
