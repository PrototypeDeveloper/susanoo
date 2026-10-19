//go:build linux

package linux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"susanoo/internal/platform"
)

// ARP の表（2m-1）。CLIENT は、CONTROLLER が署名付きの指示で知らせた GW の MAC アドレスと、ARP の表の GW の
// エントリを比べる。違えば（端末だけに宛てたユニキャストの ARP のなりすましは GW から見えない）、エントリを正しい
// MAC アドレスに固定して（NUD_PERMANENT。ほかの ARP では書き換わらない）、管理通信を GW に届くようにする。
// 固定は netlink（NETLINK_ROUTE の RTM_NEWNEIGH）で行う。CAP_NET_ADMIN が必要。

const (
	atfCom       = 0x2  // /proc/net/arp の Flags の ATF_COM（解決済み）
	nudPermanent = 0x80 // NUD_PERMANENT
	ndaDst       = 1    // NDA_DST
	ndaLLAddr    = 2    // NDA_LLADDR
	ndmsgLen     = 12   // struct ndmsg
)

var _ platform.Neighbors = (*Platform)(nil)

// neighborPins は固定したエントリ（アドレスと装置の番号）。
type neighborPins struct {
	mu   sync.Mutex
	pins map[netip.Addr]int
}

// Neighbor は /proc/net/arp から ip の解決済みのエントリを返す（platform.Neighbors）。
func (p *Platform) Neighbor(ip netip.Addr) (net.HardwareAddr, string, bool, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, "", false, err
	}
	mac, iface, ok := parseARPTable(data, ip)
	return mac, iface, ok, nil
}

// parseARPTable は /proc/net/arp（IP address、HW type、Flags、HW address、Mask、Device の欄）から、ip の解決済みのエントリを探す。
func parseARPTable(data []byte, ip netip.Addr) (net.HardwareAddr, string, bool) {
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[min(1, len(lines)):] {
		f := strings.Fields(line)
		if len(f) < 6 || f[0] != ip.String() {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(f[2], "0x"), 16, 32)
		if err != nil || flags&atfCom == 0 {
			continue
		}
		mac, err := net.ParseMAC(f[3])
		if err != nil || len(mac) != 6 {
			continue
		}
		return mac, f[5], true
	}
	return nil, "", false
}

// PinNeighbor は装置 iface の ip のエントリを mac に固定する（platform.Neighbors）。
func (p *Platform) PinNeighbor(ip netip.Addr, iface string, mac net.HardwareAddr) error {
	if !ip.Is4() || len(mac) != 6 {
		return errors.New("linux: 固定できるのは IPv4 のアドレスと 6 バイトの MAC アドレスだけです")
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	if err := neighRequest(syscall.RTM_NEWNEIGH, syscall.NLM_F_CREATE|syscall.NLM_F_REPLACE, ifi.Index, ip, mac, nudPermanent); err != nil {
		return fmt.Errorf("linux: ARP の表のエントリを固定できません: %w", err)
	}
	p.neigh.mu.Lock()
	defer p.neigh.mu.Unlock()
	if p.neigh.pins == nil {
		p.neigh.pins = map[netip.Addr]int{}
	}
	p.neigh.pins[ip] = ifi.Index
	return nil
}

// UnpinNeighbors は固定したエントリを消す（platform.Neighbors）。
func (p *Platform) UnpinNeighbors() error {
	p.neigh.mu.Lock()
	defer p.neigh.mu.Unlock()
	var errs []error
	for ip, index := range p.neigh.pins {
		if err := neighRequest(syscall.RTM_DELNEIGH, 0, index, ip, nil, 0); err != nil && !errors.Is(err, syscall.ENOENT) {
			errs = append(errs, fmt.Errorf("%s: %w", ip, err))
		}
		delete(p.neigh.pins, ip)
	}
	return errors.Join(errs...)
}

// neighMessage は ARP の表のエントリを作るか消す netlink のメッセージを作る。
func neighMessage(typ, flags uint16, ifindex int, ip netip.Addr, mac net.HardwareAddr, state uint16) []byte {
	b := make([]byte, nlmsgHdrLen+ndmsgLen)
	binary.NativeEndian.PutUint16(b[4:6], typ)
	binary.NativeEndian.PutUint16(b[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|flags)
	binary.NativeEndian.PutUint32(b[8:12], 1)
	nd := b[nlmsgHdrLen:]
	nd[0] = syscall.AF_INET
	binary.NativeEndian.PutUint32(nd[4:8], uint32(ifindex))
	binary.NativeEndian.PutUint16(nd[8:10], state)
	a4 := ip.As4()
	b = append(b, nlAttribute(ndaDst, a4[:])...)
	if mac != nil {
		b = append(b, nlAttribute(ndaLLAddr, mac)...)
	}
	binary.NativeEndian.PutUint32(b[0:4], uint32(len(b)))
	return b
}

// neighRequest は ARP の表のエントリを作るか消し、カーネルの応答を確かめる。
func neighRequest(typ, flags uint16, ifindex int, ip netip.Addr, mac net.HardwareAddr, state uint16) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	tv := syscall.Timeval{Sec: 2}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	if err := syscall.Sendto(fd, neighMessage(typ, flags, ifindex, ip, mac, state), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	msgs, err := nlMessages(buf[:n])
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m.typ == syscall.NLMSG_ERROR && len(m.data) >= 4 {
			if errno := int32(binary.NativeEndian.Uint32(m.data[0:4])); errno != 0 {
				return syscall.Errno(-errno)
			}
			return nil
		}
	}
	return errors.New("netlink: 応答がありません")
}
