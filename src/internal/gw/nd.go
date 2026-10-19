package gw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
)

// IPv6 の近隣探索（ND。RFC 4861）と DHCPv6（RFC 8415）のうち、LAN の監視（G8）に使うものを解析し、組み立てる。
// どれも IPv6 のヘッダーから始まるパケット（AF_PACKET の SOCK_DGRAM で読み書きする形）を扱う。

// ICMPv6 の近隣探索の種類。
const (
	NDRouterSolicit   = 133
	NDRouterAdvert    = 134
	NDNeighborSolicit = 135
	NDNeighborAdvert  = 136
)

// DHCPv6 のメッセージの種類と、ポート。
const (
	DHCPv6Solicit   = 1
	DHCPv6Advertise = 2
	DHCPv6Reply     = 7
	dhcpv6Client    = 546
	dhcpv6Server    = 547
)

const (
	ipv6HeaderLen = 40
	protoICMPv6   = 58
	protoUDP      = 17
	maxNDPrefixes = 16
	maxNDServers  = 8
)

// よく使う IPv6 のマルチキャストのアドレス。
var (
	AllNodes            = netip.MustParseAddr("ff02::1")
	AllRouters          = netip.MustParseAddr("ff02::2")
	AllDHCPv6Servers    = netip.MustParseAddr("ff02::1:2")
	errNotND            = errors.New("nd: 近隣探索のメッセージではありません")
	errNotLinkLocalOnly = errors.New("nd: ホップの上限が 255 ではありません（リンクの外から届いた）")
)

// ND は近隣探索のメッセージ。
type ND struct {
	Type     uint8
	Src, Dst netip.Addr
	Target   netip.Addr       // NS と NA の対象のアドレス
	LinkAddr net.HardwareAddr // 送信元（NS、RS、RA）か対象（NA）のリンク層のアドレスのオプション
	// NA の印（Router、Solicited、Override）。
	Router, Solicited, Override bool
	// RA の項目。
	RouterLifetime uint16
	Managed, Other bool           // アドレスとその他の設定を DHCPv6 で得るかの印
	Prefixes       []netip.Prefix // 知らせたネットワーク（プレフィックス情報のオプション）
	RDNSS          []netip.Addr   // 知らせた DNS サーバー（RFC 8106）
}

// ipv6Packet は IPv6 のヘッダーを確かめ、送信元、宛先、次のヘッダー、ホップの上限、中身を返す。拡張ヘッダーは扱わない。
func ipv6Packet(b []byte) (src, dst netip.Addr, next, hop uint8, payload []byte, err error) {
	if len(b) < ipv6HeaderLen || b[0]>>4 != 6 {
		return src, dst, 0, 0, nil, errors.New("nd: IPv6 のパケットではありません")
	}
	plen := int(binary.BigEndian.Uint16(b[4:6]))
	if ipv6HeaderLen+plen > len(b) {
		return src, dst, 0, 0, nil, errors.New("nd: パケットが短すぎます")
	}
	src, dst = netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40]))
	return src, dst, b[6], b[7], b[ipv6HeaderLen : ipv6HeaderLen+plen], nil
}

// checksum は、IPv6 の疑似ヘッダーを含めた上位層のチェックサムを計算する。
func checksum(src, dst netip.Addr, proto uint8, payload []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	s, d := src.As16(), dst.As16()
	add(s[:])
	add(d[:])
	var l [8]byte
	binary.BigEndian.PutUint32(l[0:4], uint32(len(payload)))
	l[7] = proto
	add(l[:])
	add(payload)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// ParseND は近隣探索のメッセージを解析する。ホップの上限が 255 でないもの（リンクの外から届いたもの）と、
// チェックサムの合わないものは受け付けない。
func ParseND(b []byte) (ND, error) {
	src, dst, next, hop, m, err := ipv6Packet(b)
	if err != nil {
		return ND{}, err
	}
	if next != protoICMPv6 || len(m) < 8 || m[0] < NDRouterSolicit || m[0] > NDNeighborAdvert || m[1] != 0 {
		return ND{}, errNotND
	}
	if hop != 255 {
		return ND{}, errNotLinkLocalOnly
	}
	if checksum(src, dst, protoICMPv6, m) != 0 {
		return ND{}, errors.New("nd: チェックサムが合いません")
	}
	n := ND{Type: m[0], Src: src, Dst: dst}
	var opts []byte
	switch n.Type {
	case NDRouterSolicit:
		opts = m[8:]
	case NDRouterAdvert:
		if len(m) < 16 {
			return ND{}, errors.New("nd: ルーター広告が短すぎます")
		}
		n.Managed, n.Other = m[5]&0x80 != 0, m[5]&0x40 != 0
		n.RouterLifetime = binary.BigEndian.Uint16(m[6:8])
		opts = m[16:]
	case NDNeighborSolicit, NDNeighborAdvert:
		if len(m) < 24 {
			return ND{}, errors.New("nd: 近隣探索のメッセージが短すぎます")
		}
		if n.Type == NDNeighborAdvert {
			n.Router, n.Solicited, n.Override = m[4]&0x80 != 0, m[4]&0x40 != 0, m[4]&0x20 != 0
		}
		n.Target = netip.AddrFrom16([16]byte(m[8:24]))
		if n.Target.IsMulticast() {
			return ND{}, errors.New("nd: 対象のアドレスがマルチキャストです")
		}
		opts = m[24:]
	}
	for len(opts) > 0 {
		if len(opts) < 2 || opts[1] == 0 || int(opts[1])*8 > len(opts) {
			return ND{}, errors.New("nd: オプションの長さが不正です")
		}
		o := opts[:int(opts[1])*8]
		opts = opts[len(o):]
		switch o[0] {
		case 1, 2: // 送信元か対象のリンク層のアドレス
			if len(o) >= 8 {
				n.LinkAddr = slices.Clone(net.HardwareAddr(o[2:8]))
			}
		case 3: // プレフィックス情報
			if len(o) == 32 && len(n.Prefixes) < maxNDPrefixes && o[2] <= 128 {
				if p, err := netip.AddrFrom16([16]byte(o[16:32])).Prefix(int(o[2])); err == nil {
					n.Prefixes = append(n.Prefixes, p)
				}
			}
		case 25: // RDNSS
			for a := o[8:]; len(a) >= 16 && len(n.RDNSS) < maxNDServers; a = a[16:] {
				n.RDNSS = append(n.RDNSS, netip.AddrFrom16([16]byte(a[:16])))
			}
		}
	}
	return n, nil
}

// DHCPv6Message は、GW の問い合わせに答えた DHCPv6 のサーバーのメッセージ（ADVERTISE か REPLY）。
type DHCPv6Message struct {
	Type    uint8
	Src     netip.Addr
	XID     uint32       // 取引の ID（下位 24 ビット）
	DNS     []netip.Addr // 知らせた DNS サーバー（オプション 23）
	Address []netip.Addr // 割り当てようとしたアドレス（IA_NA の中の IA Address）
}

// ParseDHCPv6 は、DHCPv6 のクライアントのポート（546）に届いた、サーバーからのメッセージを解析する。
func ParseDHCPv6(b []byte) (DHCPv6Message, error) {
	src, _, next, _, u, err := ipv6Packet(b)
	if err != nil {
		return DHCPv6Message{}, err
	}
	if next != protoUDP || len(u) < 8+4 || binary.BigEndian.Uint16(u[0:2]) != dhcpv6Server || binary.BigEndian.Uint16(u[2:4]) != dhcpv6Client {
		return DHCPv6Message{}, errors.New("dhcpv6: サーバーからのメッセージではありません")
	}
	if ulen := int(binary.BigEndian.Uint16(u[4:6])); ulen < 8+4 || ulen > len(u) {
		return DHCPv6Message{}, errors.New("dhcpv6: UDP の長さが不正です")
	} else {
		u = u[:ulen]
	}
	// UDP のチェックサムは確かめない。送信元がチェックサムの計算を装置に任せ、仮想の装置（veth）で計算しないまま届くと、
	// AF_PACKET では計算の途中の値が見えるため。壊れたフレームはイーサネットの検査で落ち、チェックサムは偽造も防がない。
	m := u[8:]
	msg := DHCPv6Message{Type: m[0], Src: src, XID: uint32(m[1])<<16 | uint32(m[2])<<8 | uint32(m[3])}
	if msg.Type != DHCPv6Advertise && msg.Type != DHCPv6Reply {
		return DHCPv6Message{}, fmt.Errorf("dhcpv6: 種類 %d は ADVERTISE か REPLY ではありません", msg.Type)
	}
	var walk func(opts []byte, depth int) error
	walk = func(opts []byte, depth int) error {
		for len(opts) > 0 {
			if len(opts) < 4 {
				return errors.New("dhcpv6: オプションが短すぎます")
			}
			code, olen := binary.BigEndian.Uint16(opts[0:2]), int(binary.BigEndian.Uint16(opts[2:4]))
			if 4+olen > len(opts) {
				return errors.New("dhcpv6: オプションの長さが不正です")
			}
			data := opts[4 : 4+olen]
			opts = opts[4+olen:]
			switch {
			case code == 23: // DNS サーバー
				for a := data; len(a) >= 16 && len(msg.DNS) < maxNDServers; a = a[16:] {
					msg.DNS = append(msg.DNS, netip.AddrFrom16([16]byte(a[:16])))
				}
			case code == 3 && len(data) >= 12 && depth == 0: // IA_NA（IAID、T1、T2 の後にオプション）
				if err := walk(data[12:], depth+1); err != nil {
					return err
				}
			case code == 5 && len(data) >= 24 && depth == 1 && len(msg.Address) < maxNDServers: // IA Address
				msg.Address = append(msg.Address, netip.AddrFrom16([16]byte(data[:16])))
			}
		}
		return nil
	}
	if err := walk(m[4:], 0); err != nil {
		return DHCPv6Message{}, err
	}
	return msg, nil
}

// ipv6Header は IPv6 のヘッダーを付ける。
func ipv6Header(src, dst netip.Addr, next uint8, payload []byte) []byte {
	b := make([]byte, ipv6HeaderLen, ipv6HeaderLen+len(payload))
	b[0] = 6 << 4
	binary.BigEndian.PutUint16(b[4:6], uint16(len(payload)))
	b[6], b[7] = next, 255
	s, d := src.As16(), dst.As16()
	copy(b[8:24], s[:])
	copy(b[24:40], d[:])
	return append(b, payload...)
}

// icmpv6 はチェックサムを入れた ICMPv6 のパケット（IPv6 のヘッダーを含む）を作る。
func icmpv6(src, dst netip.Addr, m []byte) []byte {
	binary.BigEndian.PutUint16(m[2:4], 0)
	binary.BigEndian.PutUint16(m[2:4], checksum(src, dst, protoICMPv6, m))
	return ipv6Header(src, dst, protoICMPv6, m)
}

// RouterSolicit は、src（GW のリンクローカルのアドレス）からすべてのルーターに送るルーター要請を作る。
func RouterSolicit(src netip.Addr, mac net.HardwareAddr) []byte {
	m := make([]byte, 8, 16)
	m[0] = NDRouterSolicit
	m = append(m, 1, 1)
	m = append(m, mac...)
	return icmpv6(src, AllRouters, m)
}

// RAOptions はルーター広告の中身。
type RAOptions struct {
	HopLimit       uint8          // 端末に使わせるホップの上限（0 なら指定しない）
	RouterLifetime uint16         // 既定の経路として使ってよい秒数（0 なら既定の経路にしない）
	Prefixes       []netip.Prefix // SLAAC でアドレスを作らせるネットワーク（オンリンクと自動設定の印を付ける）
	Valid          uint32         // ネットワークの有効期限（秒）
	Preferred      uint32         // ネットワークの推奨期限（秒）
	RDNSS          []netip.Addr   // DNS サーバー（RFC 8106）
	RDNSSLifetime  uint32
}

// BuildRA は、src（リンクローカルのアドレス）、リンク層のアドレス mac のルーターとして、すべての機器に送るルーター広告を作る。
func BuildRA(src netip.Addr, mac net.HardwareAddr, o RAOptions) []byte {
	m := make([]byte, 16, 128)
	m[0], m[4] = NDRouterAdvert, o.HopLimit // 印、到達可能時間、再送の間隔は 0
	binary.BigEndian.PutUint16(m[6:8], o.RouterLifetime)
	if len(mac) == 6 {
		m = append(m, 1, 1)
		m = append(m, mac...)
	}
	for _, p := range o.Prefixes {
		opt := make([]byte, 32)
		opt[0], opt[1], opt[2], opt[3] = 3, 4, byte(p.Bits()), 0xc0 // オンリンクと自動設定の印
		binary.BigEndian.PutUint32(opt[4:8], o.Valid)
		binary.BigEndian.PutUint32(opt[8:12], o.Preferred)
		a := p.Masked().Addr().As16()
		copy(opt[16:], a[:])
		m = append(m, opt...)
	}
	if len(o.RDNSS) > 0 {
		opt := make([]byte, 8, 8+16*len(o.RDNSS))
		opt[0], opt[1] = 25, byte(1+2*len(o.RDNSS))
		binary.BigEndian.PutUint32(opt[4:8], o.RDNSSLifetime)
		for _, a := range o.RDNSS {
			b := a.As16()
			opt = append(opt, b[:]...)
		}
		m = append(m, opt...)
	}
	return icmpv6(src, AllNodes, m)
}

// WithdrawRA は、src のルーターの広告を取り消すルーター広告を作る（ルーターの寿命を 0 にして既定の経路から外させ、
// 知らせたネットワークの期限を 0 にして、新しい通信に使わせない。DNS サーバーの寿命も 0 にする）。
// 不正なルーターを隔離したときに、GW が src を名乗って、すべての機器に送る。
func WithdrawRA(src netip.Addr, mac net.HardwareAddr, prefixes []netip.Prefix, rdnss []netip.Addr) []byte {
	return BuildRA(src, mac, RAOptions{Prefixes: prefixes, RDNSS: rdnss})
}

// SolicitDHCPv6 は、src（GW のリンクローカルのアドレス）から DHCPv6 のサーバーを探す SOLICIT を作る。
// GW は DHCPv6 のサーバーを動かさないので、答えるものは LAN の不正なサーバー（DNS を差し替える攻撃など）である。
func SolicitDHCPv6(src netip.Addr, mac net.HardwareAddr, xid uint32) []byte {
	m := []byte{DHCPv6Solicit, byte(xid >> 16), byte(xid >> 8), byte(xid)}
	opt := func(code uint16, data []byte) {
		m = binary.BigEndian.AppendUint16(m, code)
		m = binary.BigEndian.AppendUint16(m, uint16(len(data)))
		m = append(m, data...)
	}
	opt(1, append([]byte{0, 3, 0, 1}, mac...))             // クライアントの識別子（DUID-LL）
	opt(8, []byte{0, 0})                                   // 経過時間
	opt(6, []byte{0, 23, 0, 24})                           // 求めるオプション（DNS サーバー、ドメインの検索リスト）
	opt(3, append([]byte{0, 0, 0, 1}, make([]byte, 8)...)) // IA_NA（IAID 1、T1 と T2 は 0）
	u := make([]byte, 8, 8+len(m))
	binary.BigEndian.PutUint16(u[0:2], dhcpv6Client)
	binary.BigEndian.PutUint16(u[2:4], dhcpv6Server)
	binary.BigEndian.PutUint16(u[4:6], uint16(8+len(m)))
	u = append(u, m...)
	binary.BigEndian.PutUint16(u[6:8], checksum(src, AllDHCPv6Servers, protoUDP, u))
	return ipv6Header(src, AllDHCPv6Servers, protoUDP, u)
}

// MulticastMAC は IPv6 のマルチキャストのアドレスの宛先の MAC アドレス（33:33 と下位 32 ビット）を返す。
func MulticastMAC(a netip.Addr) net.HardwareAddr {
	b := a.As16()
	return net.HardwareAddr{0x33, 0x33, b[12], b[13], b[14], b[15]}
}
