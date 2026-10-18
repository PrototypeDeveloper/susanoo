//go:build linux && !(amd64 || arm64)

package linux

import "errors"

var errArch = errors.New("fanotify: このアーキテクチャには対応していません")

// fanotify_mark の引数の渡し方がアーキテクチャによって違うため、64 ビットの amd64 と arm64 だけで使う。
func newFanotify([]string) (watcher, error) { return nil, errArch }

func fanotifyInit(flags, eventFFlags uint) (int, error) { return -1, errArch }

func fanotifyMark(fd int, flags uint, mask uint64, path string) error { return errArch }
