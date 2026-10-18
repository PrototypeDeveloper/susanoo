//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"susanoo/internal/honeytoken"
)

// fanotify でのおとりの監視のうち、アーキテクチャに依存しない部分。

type fileID struct{ dev, ino uint64 }

// fidName はディレクトリの中の名前。
type fidName struct {
	dir  fidKey
	name string
}

// tokenDirMask はおとりの親ディレクトリで受け取るイベント（削除、名前の変更、属性の変更）。
const tokenDirMask = fanDelete | fanMovedFrom | fanAttrib | fanEventOnChild

// fanotifyWatcher は fanotify でおとりのファイルを監視する。触ったプロセスの PID が分かる。
// 読み書きはファイルそのものの印（fd 方式）で、削除、名前の変更、属性の変更は親ディレクトリの印（FID 方式）で受け取る。
// CAP_SYS_ADMIN が必要。
type fanotifyWatcher struct {
	f      *os.File
	fid    *os.File // FID 方式の監視。使えなければ nil（読み書きだけを検知する）
	tokens map[fileID]int
	names  map[fidName]int
}

// watchTokenDirs は、おとりの親ディレクトリを FID 方式で監視する。使えなければ nil を返す。
func watchTokenDirs(paths []string) (*os.File, map[fidName]int) {
	fd, err := fanotifyInit(fanClassNotif|fanCloexec|fanNonblock|fanReportDFIDNm, syscall.O_RDONLY|syscall.O_CLOEXEC)
	if err != nil {
		return nil, nil
	}
	names := map[fidName]int{}
	marked := map[fidKey]bool{}
	for i, p := range paths {
		dir := filepath.Dir(p)
		key, err := dirKey(dir)
		if err != nil {
			continue
		}
		if !marked[key] {
			if fanotifyMark(fd, fanMarkAdd, tokenDirMask, dir) != nil {
				continue
			}
			marked[key] = true
		}
		names[fidName{key, filepath.Base(p)}] = i
	}
	if len(names) == 0 {
		syscall.Close(fd)
		return nil, nil
	}
	return os.NewFile(uintptr(fd), "fanotify-tokens"), names
}

// readDirs は親ディレクトリのイベントから、おとりの削除、名前の変更、属性の変更を取り出す。
func (w *fanotifyWatcher) readDirs(ctx context.Context, out chan<- fileEvent) error {
	buf := make([]byte, 64*1024)
	for {
		n, err := w.fid.Read(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) {
				return ctx.Err()
			}
			return fmt.Errorf("fanotify: %w", err)
		}
		evs, perr := parseFIDEvents(buf[:n])
		for _, ev := range evs {
			i, ok := w.names[fidName{ev.dir, ev.name}]
			op := tokenDirOp(ev.mask)
			if !ok || op == "" {
				continue
			}
			select {
			case out <- fileEvent{token: i, op: op, pid: int(ev.pid)}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if perr != nil {
			return perr
		}
	}
}

func tokenDirOp(mask uint64) string {
	switch {
	case mask&fanDelete != 0:
		return honeytoken.OpDelete
	case mask&fanMovedFrom != 0:
		return honeytoken.OpMove
	case mask&fanAttrib != 0:
		return honeytoken.OpAttrib
	}
	return ""
}
