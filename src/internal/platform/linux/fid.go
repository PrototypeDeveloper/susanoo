//go:build linux

package linux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// fanotify の FID 方式（FAN_REPORT_DFID_NAME）の定数。イベントには fd の代わりに、
// 親ディレクトリの識別子（fsid とファイルハンドル）と、エントリーの名前が付く。
const (
	fanReportFID     = 0x200
	fanReportDirFID  = 0x400
	fanReportName    = 0x800
	fanReportDFIDNm  = fanReportDirFID | fanReportName
	fanMarkFS        = 0x100 // FAN_MARK_FILESYSTEM
	fanAttrib        = 0x4
	fanCloseWrite    = 0x8
	fanMovedFrom     = 0x40
	fanMovedTo       = 0x80
	fanCreate        = 0x100
	fanDelete        = 0x200
	fanEventOnChild  = 0x08000000
	fanOnDir         = 0x40000000
	infoTypeDFIDName = 2
	maxHandleSize    = 128
)

// fidKey はファイルシステムの中のファイル（ディレクトリ）を識別する。
type fidKey string

func makeFIDKey(fsid [8]byte, handleType int32, handle []byte) fidKey {
	b := make([]byte, 0, 12+len(handle))
	b = append(b, fsid[:]...)
	b = binary.NativeEndian.AppendUint32(b, uint32(handleType))
	return fidKey(append(b, handle...))
}

// fidEvent は FID 方式のイベント。
type fidEvent struct {
	mask uint64
	pid  int32
	dir  fidKey // 親ディレクトリ
	name string // エントリーの名前
}

// parseFIDEvents は FID 方式の fanotify のイベントの列を解析する。
func parseFIDEvents(buf []byte) ([]fidEvent, error) {
	var evs []fidEvent
	for len(buf) > 0 {
		if len(buf) < fanEventMetadataLen {
			return evs, errors.New("fanotify: イベントが途中で切れています")
		}
		eventLen := int(binary.NativeEndian.Uint32(buf[0:4]))
		metaLen := int(binary.NativeEndian.Uint16(buf[6:8]))
		if buf[4] != fanotifyMetadataVersion || metaLen < fanEventMetadataLen || eventLen < metaLen || eventLen > len(buf) {
			return evs, fmt.Errorf("fanotify: イベントの長さが不正です（%d / %d）", eventLen, metaLen)
		}
		ev := fidEvent{mask: binary.NativeEndian.Uint64(buf[8:16]), pid: int32(binary.NativeEndian.Uint32(buf[20:24]))}
		info := buf[metaLen:eventLen]
		for len(info) >= 4 {
			typ, l := info[0], int(binary.NativeEndian.Uint16(info[2:4]))
			if l < 4 || l > len(info) {
				return evs, errors.New("fanotify: 情報の長さが不正です")
			}
			if typ == infoTypeDFIDName {
				// ヘッダー（4）、fsid（8）、handle_bytes（4）、handle_type（4）、ハンドル、名前（NUL 終端）
				rec := info[4:l]
				if len(rec) < 16 {
					return evs, errors.New("fanotify: 識別子が短すぎます")
				}
				var fsid [8]byte
				copy(fsid[:], rec[0:8])
				hb := int(binary.NativeEndian.Uint32(rec[8:12]))
				ht := int32(binary.NativeEndian.Uint32(rec[12:16]))
				if hb > maxHandleSize || 16+hb > len(rec) {
					return evs, errors.New("fanotify: ハンドルの長さが不正です")
				}
				ev.dir = makeFIDKey(fsid, ht, rec[16:16+hb])
				name := rec[16+hb:]
				for i, c := range name {
					if c == 0 {
						name = name[:i]
						break
					}
				}
				ev.name = string(name)
			}
			info = info[l:]
		}
		evs = append(evs, ev)
		buf = buf[eventLen:]
	}
	return evs, nil
}

// dirKey は、パス path のディレクトリの識別子を、イベントと同じ形で返す。
func dirKey(path string) (fidKey, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return "", err
	}
	var fsid [8]byte
	binary.NativeEndian.PutUint32(fsid[0:4], uint32(st.Fsid.X__val[0]))
	binary.NativeEndian.PutUint32(fsid[4:8], uint32(st.Fsid.X__val[1]))

	buf := make([]byte, 8+maxHandleSize)
	binary.NativeEndian.PutUint32(buf[0:4], maxHandleSize)
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return "", err
	}
	var mountID int32
	dirfd := -100 // AT_FDCWD
	_, _, errno := syscall.Syscall6(sysNameToHandleAt, uintptr(dirfd), uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&mountID)), 0, 0)
	if errno != 0 {
		return "", errno
	}
	hb := binary.NativeEndian.Uint32(buf[0:4])
	ht := int32(binary.NativeEndian.Uint32(buf[4:8]))
	if hb > maxHandleSize {
		return "", errors.New("name_to_handle_at: ハンドルが長すぎます")
	}
	return makeFIDKey(fsid, ht, buf[8:8+hb]), nil
}
