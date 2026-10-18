//go:build linux

package gw

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"syscall"
	"time"
)

// Neighbor は LAN で観測した ARP。
type Neighbor struct {
	FrameMAC net.HardwareAddr // フレームの送信元の MAC アドレス
	ARP      ARP
}

// LAN は GW の LAN 側のインターフェースで ARP を監視し、機器が LAN にいるかを確かめる（G8）。
// AF_PACKET のソケットを使うため CAP_NET_RAW が必要。
type LAN struct {
	ifindex int
	mac     net.HardwareAddr
	addr    netip.Addr
	prefix  netip.Prefix
	f       *os.File
	rc      syscall.RawConn

	mu      sync.Mutex
	handler func(Neighbor)
	waiters map[netip.Addr][]chan net.HardwareAddr
}

// probeInterval は在席の確認で ARP の要求を送り直す間隔。3 回送る。
const probeInterval = 500 * time.Millisecond

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// OpenLAN はインターフェース name の ARP の監視を始める準備をする（OpenARPSocket と NewLAN をまとめたもの）。
func OpenLAN(name string) (*LAN, error) {
	f, err := OpenARPSocket(name)
	if err != nil {
		return nil, err
	}
	l, err := NewLAN(name, f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return l, nil
}

// OpenARPSocket は、インターフェース name に結び付けた ARP の AF_PACKET のソケットを開く。CAP_NET_RAW が必要。
// 権限を分けるとき（G12）は、執行部が開いて非特権の側に渡す。開いた後のソケットの読み書きには権限は要らない。
func OpenARPSocket(name string) (*os.File, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	proto := htons(syscall.ETH_P_ARP)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(proto))
	if err != nil {
		return nil, fmt.Errorf("gw: ARP のソケットを作れません: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: proto, Ifindex: ifi.Index}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "arp"), nil
}

// InterfaceAddr は、インターフェース name の最初の IPv4 アドレスと、そのネットワークと、MAC アドレスを返す。
// 権限は要らない。
func InterfaceAddr(name string) (netip.Addr, netip.Prefix, net.HardwareAddr, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, nil, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, nil, err
	}
	if len(ifi.HardwareAddr) != 6 {
		return netip.Addr{}, netip.Prefix{}, nil, fmt.Errorf("gw: %s は Ethernet のインターフェースではありません", name)
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP.To4()); ok && ip.Is4() {
				bits, _ := ipn.Mask.Size()
				return ip, netip.PrefixFrom(ip, bits).Masked(), slices.Clone(ifi.HardwareAddr), nil
			}
		}
	}
	return netip.Addr{}, netip.Prefix{}, nil, fmt.Errorf("gw: %s に IPv4 アドレスがありません", name)
}

// NewLAN は、OpenARPSocket で開いたソケット f を使って、インターフェース name の LAN を作る。
// GW のアドレスとネットワークは、インターフェースの最初の IPv4 アドレスから決める。f は非ブロッキングであること。
func NewLAN(name string, f *os.File) (*LAN, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addr, prefix, mac, err := InterfaceAddr(name)
	if err != nil {
		return nil, err
	}
	l := &LAN{ifindex: ifi.Index, mac: mac, addr: addr, prefix: prefix, f: f, waiters: map[netip.Addr][]chan net.HardwareAddr{}}
	if l.rc, err = l.f.SyscallConn(); err != nil {
		return nil, err
	}
	return l, nil
}

// Addr は GW の LAN 側のアドレスを返す。
func (l *LAN) Addr() netip.Addr { return l.addr }

// Prefix は LAN のネットワークを返す。
func (l *LAN) Prefix() netip.Prefix { return l.prefix }

// MAC は GW の LAN 側の MAC アドレスを返す。
func (l *LAN) MAC() net.HardwareAddr { return l.mac }

// SetHandler は観測した ARP を受け取る関数を設定する。
func (l *LAN) SetHandler(h func(Neighbor)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.handler = h
}

// Run は ctx が終わるまで ARP を受信する。
func (l *LAN) Run(ctx context.Context) error {
	go func() { <-ctx.Done(); l.f.Close() }()
	buf := make([]byte, 1500)
	for {
		var n int
		var from syscall.Sockaddr
		var rerr error
		err := l.rc.Read(func(fd uintptr) bool {
			n, from, rerr = syscall.Recvfrom(int(fd), buf, 0)
			return rerr != syscall.EAGAIN
		})
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) {
				return ctx.Err()
			}
			return err
		}
		if rerr != nil {
			continue
		}
		ll, ok := from.(*syscall.SockaddrLinklayer)
		if !ok || ll.Pkttype == syscall.PACKET_OUTGOING || ll.Halen != 6 {
			continue
		}
		a, err := ParseARP(buf[:n])
		if err != nil {
			continue
		}
		nb := Neighbor{FrameMAC: slices.Clone(net.HardwareAddr(ll.Addr[:6])), ARP: a}
		l.deliver(a.SenderIP, nb.FrameMAC)
		l.mu.Lock()
		h := l.handler
		l.mu.Unlock()
		if h != nil {
			h(nb)
		}
	}
}

func (l *LAN) deliver(ip netip.Addr, mac net.HardwareAddr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ch := range l.waiters[ip] {
		select {
		case ch <- mac:
		default:
		}
	}
}

// Probe は ip のアドレスを持つ機器が LAN にいるかを ARP で確かめ、いれば MAC アドレスを返す。
// 隔離中の機器にも届く（nftables は ARP を遮断しない）。
func (l *LAN) Probe(ctx context.Context, ip netip.Addr) (net.HardwareAddr, bool) {
	ch := make(chan net.HardwareAddr, 1)
	l.mu.Lock()
	l.waiters[ip] = append(l.waiters[ip], ch)
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.waiters[ip] = slices.DeleteFunc(l.waiters[ip], func(c chan net.HardwareAddr) bool { return c == ch })
		if len(l.waiters[ip]) == 0 {
			delete(l.waiters, ip)
		}
	}()

	req := ARP{Op: ARPRequest, SenderMAC: l.mac, SenderIP: l.addr, TargetMAC: make(net.HardwareAddr, 6), TargetIP: ip}.Marshal()
	for range 3 {
		if err := l.send(req); err != nil {
			return nil, false
		}
		select {
		case mac := <-ch:
			return mac, true
		case <-time.After(probeInterval):
		case <-ctx.Done():
			return nil, false
		}
	}
	return nil, false
}

func (l *LAN) send(pkt []byte) error {
	to := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ARP),
		Ifindex:  l.ifindex,
		Halen:    6,
		Addr:     [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
	var werr error
	err := l.rc.Write(func(fd uintptr) bool {
		werr = syscall.Sendto(int(fd), pkt, 0, to)
		return werr != syscall.EAGAIN
	})
	if err != nil {
		return err
	}
	return werr
}
