//go:build linux

package gw

import (
	"context"
	"crypto/rand"
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
	"unsafe"
)

// Neighbor は LAN で観測した ARP。
type Neighbor struct {
	FrameMAC net.HardwareAddr // フレームの送信元の MAC アドレス
	ARP      ARP
}

// NDEvent は LAN で観測した近隣探索か、GW の問い合わせに答えた DHCPv6 のメッセージ。どちらか一方が入る。
type NDEvent struct {
	FrameMAC net.HardwareAddr // フレームの送信元の MAC アドレス
	ND       *ND
	DHCPv6   *DHCPv6Message
}

// LAN は GW の LAN 側のインターフェースで ARP と IPv6 の近隣探索を監視し、機器が LAN にいるかを確かめる（G8）。
// AF_PACKET のソケットを使うため CAP_NET_RAW が必要。
type LAN struct {
	name    string
	ifindex int
	mac     net.HardwareAddr
	addr    netip.Addr
	prefix  netip.Prefix
	f       *os.File
	rc      syscall.RawConn
	nd      *os.File // IPv6 の近隣探索（使わなければ nil）
	ndRC    syscall.RawConn

	mu        sync.Mutex
	handler   func(Neighbor)
	ndHandler func(NDEvent)
	waiters   map[netip.Addr][]chan net.HardwareAddr
	xids      []uint32 // 最近送った DHCPv6 の SOLICIT の取引の ID
}

const maxProbeXIDs = 8

// ndFilter は、IPv6 のうち ICMPv6 の近隣探索（133〜136）と、DHCPv6 のクライアントのポート（546）への UDP だけを通す
// classic BPF（SOCK_DGRAM なので IPv6 のヘッダーから数える。拡張ヘッダーのあるものは通さない）。
var ndFilter = []syscall.SockFilter{
	{Code: syscall.BPF_LD | syscall.BPF_B | syscall.BPF_ABS, K: 6},                   // 0: 次のヘッダー
	{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, K: protoICMPv6, Jf: 3}, // 1: ICMPv6 でなければ 5 へ
	{Code: syscall.BPF_LD | syscall.BPF_B | syscall.BPF_ABS, K: ipv6HeaderLen},       // 2: ICMPv6 の種類
	{Code: syscall.BPF_JMP | syscall.BPF_JGE | syscall.BPF_K, K: NDRouterSolicit, Jf: 5},
	{Code: syscall.BPF_JMP | syscall.BPF_JGT | syscall.BPF_K, K: NDNeighborAdvert, Jt: 4, Jf: 3},
	{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, K: protoUDP, Jf: 3},  // 5: UDP でなければ捨てる
	{Code: syscall.BPF_LD | syscall.BPF_H | syscall.BPF_ABS, K: ipv6HeaderLen + 2}, // 6: 宛先のポート
	{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, K: dhcpv6Client, Jf: 1},
	{Code: syscall.BPF_RET | syscall.BPF_K, K: 0xffff}, // 8: 通す
	{Code: syscall.BPF_RET | syscall.BPF_K, K: 0},      // 9: 捨てる
}

// OpenNDSocket は、インターフェース name の IPv6 の近隣探索と、DHCPv6 のクライアントのポートへの UDP だけを受け取る
// AF_PACKET のソケットを開く（絞り込みはカーネルで行う）。ほかの機器の近隣探索も見えるよう、すべてのマルチキャストを
// 受け取る。CAP_NET_RAW が必要。権限を分けるときは、執行部が開いて非特権の側に渡す。
func OpenNDSocket(name string) (*os.File, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	proto := htons(syscall.ETH_P_IPV6)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("gw: 近隣探索のソケットを作れません: %w", err)
	}
	// 絞り込みを付けてから結び付ける（付ける前のパケットを受け取らない）。
	if err := syscall.AttachLsf(fd, ndFilter); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("gw: 近隣探索の絞り込みを付けられません: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: proto, Ifindex: ifi.Index}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	if err := allMulticast(fd, ifi.Index); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("gw: マルチキャストを受け取れません: %w", err)
	}
	return os.NewFile(uintptr(fd), "nd"), nil
}

// packetMreq は struct packet_mreq（linux/if_packet.h）。
type packetMreq struct {
	ifindex int32
	typ     uint16
	alen    uint16
	address [8]byte
}

// allMulticast は、AF_PACKET のソケット fd で、インターフェースのすべてのマルチキャストを受け取る（PACKET_MR_ALLMULTI）。
// syscall パッケージに packet_mreq の setsockopt がないため、直接呼ぶ。
func allMulticast(fd, ifindex int) error {
	mreq := packetMreq{ifindex: int32(ifindex), typ: syscall.PACKET_MR_ALLMULTI}
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), syscall.SOL_PACKET, syscall.PACKET_ADD_MEMBERSHIP,
		uintptr(unsafe.Pointer(&mreq)), unsafe.Sizeof(mreq), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// InterfaceAddrs6 は、インターフェース name の IPv6 アドレス（リンクローカルを含む）を返す。権限は要らない。
func InterfaceAddrs6(name string) ([]netip.Addr, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() == nil {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, ip)
			}
		}
	}
	return out, nil
}

// InterfacePrefix6 は、インターフェース name の、リンクローカルでない最初の IPv6 アドレスと、そのネットワークを返す。
// 権限は要らない。ルーター方式の IPv6（G1）で、LAN に知らせるネットワークと、GW のアドレスに使う。
func InterfacePrefix6(name string) (netip.Addr, netip.Prefix, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, err
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.To4() != nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok || ip.IsLinkLocalUnicast() || ip.IsLoopback() {
			continue
		}
		bits, _ := ipn.Mask.Size()
		return ip, netip.PrefixFrom(ip, bits).Masked(), nil
	}
	return netip.Addr{}, netip.Prefix{}, fmt.Errorf("gw: %s にリンクローカルでない IPv6 アドレスがありません", name)
}

// Addrs6Cache は、インターフェースの IPv6 アドレスを、間をおいて読み直しながら返す。
type Addrs6Cache struct {
	Name  string
	mu    sync.Mutex
	at    time.Time
	addrs []netip.Addr
}

const addrs6Refresh = 30 * time.Second

// Get は今の IPv6 アドレスを返す（30 秒ごとに読み直す）。
func (c *Addrs6Cache) Get() []netip.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.at) > addrs6Refresh {
		if a, err := InterfaceAddrs6(c.Name); err == nil {
			c.addrs = a
		}
		c.at = time.Now()
	}
	return c.addrs
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
	l := &LAN{name: name, ifindex: ifi.Index, mac: mac, addr: addr, prefix: prefix, f: f, waiters: map[netip.Addr][]chan net.HardwareAddr{}}
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

// AttachND は、OpenNDSocket で開いたソケット f で IPv6 の近隣探索を監視する準備をする。f は非ブロッキングであること。
func (l *LAN) AttachND(f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	l.nd, l.ndRC = f, rc
	return nil
}

// HasND は IPv6 の近隣探索を監視するかを返す。
func (l *LAN) HasND() bool { return l.nd != nil }

// SetNDHandler は観測した近隣探索と DHCPv6 のメッセージを受け取る関数を設定する。
func (l *LAN) SetNDHandler(h func(NDEvent)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ndHandler = h
}

// RunND は ctx が終わるまで近隣探索と DHCPv6 のメッセージを受信する。DHCPv6 のメッセージは、GW が最近送った
// SOLICIT への応答だけを渡す。
func (l *LAN) RunND(ctx context.Context) error {
	if l.nd == nil {
		return errors.New("gw: 近隣探索のソケットがありません")
	}
	go func() { <-ctx.Done(); l.nd.Close() }()
	buf := make([]byte, 2048)
	for {
		var n int
		var from syscall.Sockaddr
		var rerr error
		err := l.ndRC.Read(func(fd uintptr) bool {
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
		ev := NDEvent{FrameMAC: slices.Clone(net.HardwareAddr(ll.Addr[:6]))}
		if nd, err := ParseND(buf[:n]); err == nil {
			ev.ND = &nd
		} else if m, err := ParseDHCPv6(buf[:n]); err == nil && l.probed(m.XID) {
			ev.DHCPv6 = &m
		} else {
			continue
		}
		l.mu.Lock()
		h := l.ndHandler
		l.mu.Unlock()
		if h != nil {
			h(ev)
		}
	}
}

func (l *LAN) probed(xid uint32) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Contains(l.xids, xid)
}

// linkLocal は GW の LAN 側のリンクローカルのアドレスを返す。
func (l *LAN) linkLocal() (netip.Addr, error) {
	addrs, err := InterfaceAddrs6(l.name)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if a.IsLinkLocalUnicast() {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("gw: %s に IPv6 のリンクローカルのアドレスがありません", l.name)
}

// ProbeIPv6 は、ルーター要請と DHCPv6 の SOLICIT を送り、答えるルーターと DHCPv6 のサーバーを探す。
// GW はどちらも動かさないので、答えるものは LAN の不正なルーターかサーバーである（答えは RunND で受け取る）。
func (l *LAN) ProbeIPv6() error {
	src, err := l.linkLocal()
	if err != nil {
		return err
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	xid := binary.BigEndian.Uint32(b[:]) & 0xffffff
	l.mu.Lock()
	l.xids = append(l.xids, xid)
	if len(l.xids) > maxProbeXIDs {
		l.xids = l.xids[len(l.xids)-maxProbeXIDs:]
	}
	l.mu.Unlock()
	return errors.Join(l.send6(RouterSolicit(src, l.mac), AllRouters), l.send6(SolicitDHCPv6(src, l.mac, xid), AllDHCPv6Servers))
}

// Advertise は、GW を LAN のルーターとして知らせるルーター広告を、GW のリンクローカルのアドレスからすべての機器に送る。
func (l *LAN) Advertise(o RAOptions) error {
	src, err := l.linkLocal()
	if err != nil {
		return err
	}
	return l.send6(BuildRA(src, l.mac, o), AllNodes)
}

// WithdrawRA は、不正なルーター src（MAC アドレス mac）の広告を取り消すルーター広告を、src を名乗ってすべての機器に送る。
func (l *LAN) WithdrawRA(src netip.Addr, mac net.HardwareAddr, prefixes []netip.Prefix, rdnss []netip.Addr) error {
	if !src.IsLinkLocalUnicast() {
		return fmt.Errorf("gw: ルーターのアドレス %s がリンクローカルではありません", src)
	}
	return l.send6(WithdrawRA(src, mac, prefixes, rdnss), AllNodes)
}

func (l *LAN) send6(pkt []byte, dst netip.Addr) error {
	if l.nd == nil {
		return errors.New("gw: 近隣探索のソケットがありません")
	}
	to := &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_IPV6), Ifindex: l.ifindex, Halen: 6}
	copy(to.Addr[:], MulticastMAC(dst))
	var werr error
	err := l.ndRC.Write(func(fd uintptr) bool {
		werr = syscall.Sendto(int(fd), pkt, 0, to)
		return werr != syscall.EAGAIN
	})
	if err != nil {
		return err
	}
	return werr
}
