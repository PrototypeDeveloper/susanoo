//go:build linux

package linux

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"susanoo/internal/event"
)

func TestParseARPTable(t *testing.T) {
	table := `IP address       HW type     Flags       HW address            Mask     Device
10.77.0.9        0x1         0x0         00:00:00:00:00:00     *        eth0
10.77.0.1        0x1         0x2         02:00:00:00:00:fe     *        eth0
10.77.0.5        0x1         0x6         02:00:00:00:00:05     *        eth1
`
	mac, iface, ok := parseARPTable([]byte(table), netip.MustParseAddr("10.77.0.1"))
	if !ok || mac.String() != "02:00:00:00:00:fe" || iface != "eth0" {
		t.Errorf("parseARPTable = %v %q %v", mac, iface, ok)
	}
	if mac, iface, ok := parseARPTable([]byte(table), netip.MustParseAddr("10.77.0.5")); !ok || mac.String() != "02:00:00:00:00:05" || iface != "eth1" {
		t.Errorf("固定したエントリ = %v %q %v", mac, iface, ok)
	}
	for _, ip := range []string{"10.77.0.9", "10.77.0.2"} { // 解決していないエントリと、ないエントリ
		if _, _, ok := parseARPTable([]byte(table), netip.MustParseAddr(ip)); ok {
			t.Errorf("%s のエントリを返しました", ip)
		}
	}
	if _, _, ok := parseARPTable(nil, netip.MustParseAddr("10.77.0.1")); ok {
		t.Error("空の表でエントリを返しました")
	}
}

func TestNeighMessage(t *testing.T) {
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 0xfe}
	b := neighMessage(syscall.RTM_NEWNEIGH, syscall.NLM_F_CREATE|syscall.NLM_F_REPLACE, 3, netip.MustParseAddr("10.77.0.1"), mac, nudPermanent)
	if int(binary.NativeEndian.Uint32(b[0:4])) != len(b) || binary.NativeEndian.Uint16(b[4:6]) != syscall.RTM_NEWNEIGH {
		t.Fatalf("見出し = % x", b[:16])
	}
	if f := binary.NativeEndian.Uint16(b[6:8]); f != syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|syscall.NLM_F_CREATE|syscall.NLM_F_REPLACE {
		t.Errorf("フラグ = %#x", f)
	}
	nd := b[nlmsgHdrLen : nlmsgHdrLen+ndmsgLen]
	if nd[0] != syscall.AF_INET || binary.NativeEndian.Uint32(nd[4:8]) != 3 || binary.NativeEndian.Uint16(nd[8:10]) != nudPermanent {
		t.Errorf("ndmsg = % x", nd)
	}
	attrs, err := nlAttributes(b[nlmsgHdrLen+ndmsgLen:])
	if err != nil || !bytes.Equal(attrs[ndaDst], []byte{10, 77, 0, 1}) || !bytes.Equal(attrs[ndaLLAddr], mac) {
		t.Errorf("属性 = %v %v", attrs, err)
	}
	del := neighMessage(syscall.RTM_DELNEIGH, 0, 3, netip.MustParseAddr("10.77.0.1"), nil, 0)
	if attrs, _ := nlAttributes(del[nlmsgHdrLen+ndmsgLen:]); len(attrs) != 1 {
		t.Errorf("消すときの属性 = %v", attrs)
	}
}

// 守る場所の外では、1 つのプロセスが既存のファイルを書き換えるか消した数を数える。そのプロセスが作ったファイル、
// 名前の変更の行き先、ほかのファイルシステム、守る場所の中は数えない。
func TestWideMassChange(t *testing.T) {
	const fsA, fsB = "fsid-aaa", "fsid-bbb"
	dir, other, protected := fidKey(fsA+"dir1"), fidKey(fsB+"dir1"), fidKey(fsA+"prot")
	m := &fileMonitor{cfg: FileConfig{WideFiles: 5, MassFiles: 100, MassWindow: time.Second}, log: quiet,
		watched: map[fidKey]*watchDir{}, files: map[fidKey]sensitiveFile{}, protected: map[fidKey]string{protected: "/srv/docs"},
		counts: map[int32]*massCount{}, wideFS: map[string]bool{fsA: true}, wide: map[int32]*wideCount{},
		recent: map[string]time.Time{}, findings: map[string]time.Time{}}
	now := time.Now()
	var found []*event.Event
	handle := func(mask uint64, pid int32, d fidKey, name string) {
		found = append(found, m.handle(fidEvent{mask: mask, pid: pid, dir: d, name: name}, now)...)
	}
	for i := range 20 {
		name := "new" + string(rune('a'+i))
		handle(fanCreate|fanCloseWrite, 7, dir, name) // 作って書いた（まとめて届いた）
		handle(fanCloseWrite, 7, dir, name)           // 作ったファイルへの書き込み
		handle(fanMovedTo, 7, dir, "moved"+name)      // 名前の変更の行き先
		handle(fanMovedFrom, 7, dir, "moved"+name)
		handle(fanCloseWrite, 7, other, "x"+name) // 別のファイルシステム
		handle(fanCloseWrite, 7, protected, name) // 守る場所の中（守る場所の数え方で数える）
		handle(fanCloseWrite|fanOnDir, 7, dir, "d"+name)
	}
	if len(found) != 0 {
		t.Fatalf("数えない変更で検知しました: %s", found[0].Message)
	}
	for i, mask := range []uint64{fanCloseWrite, fanDelete, fanMovedFrom, fanCloseWrite} {
		handle(mask, 8, dir, "old"+string(rune('a'+i)))
		handle(fanCloseWrite, 8, dir, "old"+string(rune('a'+i))) // 同じファイルは 1 つと数える
	}
	if len(found) != 0 {
		t.Fatalf("4 個で検知しました")
	}
	handle(fanDelete, 8, dir, "olde")
	if len(found) != 1 || !found[0].FindingInfo.HasType(event.FindingTypeWideMassChange) || !strings.Contains(found[0].Message, "5 個以上") {
		t.Fatalf("検知結果 = %+v", found)
	}
	// 5 分間は同じプロセスを検知結果にしない。
	for i := range 10 {
		handle(fanCloseWrite, 8, dir, "more"+string(rune('a'+i)))
	}
	if len(found) != 1 {
		t.Errorf("続けて検知結果にしました: %d 件", len(found))
	}
}
