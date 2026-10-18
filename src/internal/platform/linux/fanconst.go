//go:build linux

package linux

import (
	"encoding/binary"
	"fmt"

	"susanoo/internal/honeytoken"
)

// fanotify の定数（linux/fanotify.h）。標準ライブラリの syscall パッケージにはないため、ここで定める。
const (
	fanClassNotif = 0x0
	fanCloexec    = 0x1
	fanNonblock   = 0x2

	fanMarkAdd = 0x1

	fanAccess    = 0x1
	fanModify    = 0x2
	fanOpen      = 0x20
	fanOpenExec  = 0x1000
	fanQOverflow = 0x4000

	fanEventMetadataLen     = 24
	fanotifyMetadataVersion = 3
)

// fanMeta は struct fanotify_event_metadata のうち使う項目。
type fanMeta struct {
	mask uint64
	fd   int32
	pid  int32
}

// parseFanotify は read(2) で読んだイベントの列を解析する。解析できた分と、あればエラーを返す。
// 返したイベントの fd は呼び出し側が閉じる。
func parseFanotify(buf []byte) ([]fanMeta, error) {
	var evs []fanMeta
	for len(buf) > 0 {
		if len(buf) < fanEventMetadataLen {
			return evs, fmt.Errorf("fanotify: イベントが途中で切れています（%d バイト）", len(buf))
		}
		eventLen := binary.NativeEndian.Uint32(buf[0:4])
		vers := buf[4]
		metaLen := binary.NativeEndian.Uint16(buf[6:8])
		if vers != fanotifyMetadataVersion {
			return evs, fmt.Errorf("fanotify: 対応していない版 %d です", vers)
		}
		if metaLen < fanEventMetadataLen || eventLen < uint32(metaLen) || uint64(eventLen) > uint64(len(buf)) {
			return evs, fmt.Errorf("fanotify: イベントの長さが不正です（%d / %d）", eventLen, metaLen)
		}
		evs = append(evs, fanMeta{
			mask: binary.NativeEndian.Uint64(buf[8:16]),
			fd:   int32(binary.NativeEndian.Uint32(buf[16:20])),
			pid:  int32(binary.NativeEndian.Uint32(buf[20:24])),
		})
		buf = buf[eventLen:]
	}
	return evs, nil
}

func fanotifyOp(mask uint64) string {
	switch {
	case mask&fanModify != 0:
		return honeytoken.OpModify
	case mask&fanOpenExec != 0:
		return honeytoken.OpExec
	case mask&fanOpen != 0:
		return honeytoken.OpOpen
	case mask&fanAccess != 0:
		return honeytoken.OpAccess
	}
	return ""
}
