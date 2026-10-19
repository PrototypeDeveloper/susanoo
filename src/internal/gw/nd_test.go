package gw

import (
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"testing"
)

var (
	llRogue = netip.MustParseAddr("fe80::bad")
	llGW    = netip.MustParseAddr("fe80::1")
	macX    = net.HardwareAddr{2, 0, 0, 0, 0, 0x99}
)

// neighborAdvert は NA を組み立てる（試験用）。
func neighborAdvert(src, target netip.Addr, mac net.HardwareAddr, flags byte, hop byte) []byte {
	m := make([]byte, 24, 32)
	m[0], m[4] = NDNeighborAdvert, flags
	t := target.As16()
	copy(m[8:], t[:])
	m = append(m, 2, 1)
	m = append(m, mac...)
	p := icmpv6(src, AllNodes, m)
	p[7] = hop
	return p
}

func TestParseND(t *testing.T) {
	ra, err := ParseND(WithdrawRA(llRogue, macX, []netip.Prefix{netip.MustParsePrefix("2001:db8:bad::/64")}, []netip.Addr{llRogue}))
	if err != nil {
		t.Fatal(err)
	}
	if ra.Type != NDRouterAdvert || ra.Src != llRogue || ra.Dst != AllNodes || ra.RouterLifetime != 0 || !slices.Equal(ra.LinkAddr, macX) ||
		len(ra.Prefixes) != 1 || ra.Prefixes[0].String() != "2001:db8:bad::/64" || len(ra.RDNSS) != 1 || ra.RDNSS[0] != llRogue {
		t.Errorf("ルーター広告 = %+v", ra)
	}
	rs, err := ParseND(RouterSolicit(llGW, macX))
	if err != nil || rs.Type != NDRouterSolicit || rs.Dst != AllRouters || !slices.Equal(rs.LinkAddr, macX) {
		t.Errorf("ルーター要請 = %+v %v", rs, err)
	}
	na, err := ParseND(neighborAdvert(llRogue, llGW, macX, 0x20, 255))
	if err != nil || na.Type != NDNeighborAdvert || na.Target != llGW || !na.Override || na.Solicited || na.Router || !slices.Equal(na.LinkAddr, macX) {
		t.Errorf("近隣広告 = %+v %v", na, err)
	}
	// ホップの上限が 255 でないもの、チェックサムが合わないもの、壊れたものは受け付けない。
	if _, err := ParseND(neighborAdvert(llRogue, llGW, macX, 0x20, 64)); err == nil {
		t.Error("ホップの上限が 64 の NA を受け付けた")
	}
	bad := neighborAdvert(llRogue, llGW, macX, 0x20, 255)
	bad[len(bad)-1] ^= 1
	if _, err := ParseND(bad); err == nil {
		t.Error("チェックサムの合わない NA を受け付けた")
	}
	short := neighborAdvert(llRogue, llGW, macX, 0, 255)
	binary.BigEndian.PutUint16(short[4:6], 100)
	if _, err := ParseND(short); err == nil {
		t.Error("長さの合わないパケットを受け付けた")
	}
	if _, err := ParseND(SolicitDHCPv6(llGW, macX, 1)); err == nil {
		t.Error("UDP を近隣探索として受け付けた")
	}
}

// advertise は DHCPv6 の ADVERTISE を組み立てる（試験用）。
func advertise(src, dst netip.Addr, xid uint32, dns, addr netip.Addr) []byte {
	m := []byte{DHCPv6Advertise, byte(xid >> 16), byte(xid >> 8), byte(xid)}
	opt := func(b []byte, code uint16, data []byte) []byte {
		b = binary.BigEndian.AppendUint16(b, code)
		b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
		return append(b, data...)
	}
	d := dns.As16()
	m = opt(m, 23, d[:])
	a := addr.As16()
	iaaddr := opt(nil, 5, append(a[:], make([]byte, 8)...))
	m = opt(m, 3, append(make([]byte, 12), iaaddr...))
	u := make([]byte, 8, 8+len(m))
	binary.BigEndian.PutUint16(u[0:2], dhcpv6Server)
	binary.BigEndian.PutUint16(u[2:4], dhcpv6Client)
	binary.BigEndian.PutUint16(u[4:6], uint16(8+len(m)))
	u = append(u, m...)
	binary.BigEndian.PutUint16(u[6:8], checksum(src, dst, protoUDP, u))
	return ipv6Header(src, dst, protoUDP, u)
}

func TestParseDHCPv6(t *testing.T) {
	addr := netip.MustParseAddr("2001:db8:bad::10")
	m, err := ParseDHCPv6(advertise(llRogue, llGW, 0xabcdef, llRogue, addr))
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != DHCPv6Advertise || m.Src != llRogue || m.XID != 0xabcdef || len(m.DNS) != 1 || m.DNS[0] != llRogue || len(m.Address) != 1 || m.Address[0] != addr {
		t.Errorf("= %+v", m)
	}
	// GW が送る SOLICIT（クライアントからサーバーへ）は、サーバーからのメッセージではない。
	if _, err := ParseDHCPv6(SolicitDHCPv6(llGW, macX, 1)); err == nil {
		t.Error("SOLICIT をサーバーからのメッセージとして受け付けた")
	}
	// 送信元が計算を装置に任せたまま届いた（チェックサムの欄が途中の値の）メッセージも読む。
	p := advertise(llRogue, llGW, 1, llRogue, addr)
	p[ipv6HeaderLen+6], p[ipv6HeaderLen+7] = 0x12, 0x34
	if m, err := ParseDHCPv6(p); err != nil || m.XID != 1 {
		t.Errorf("チェックサムが途中の値のメッセージ = %+v %v", m, err)
	}
	// SOLICIT のチェックサムは正しい（受け取る側で確かめられる）。
	s := SolicitDHCPv6(llGW, macX, 0x123456)
	if checksum(llGW, AllDHCPv6Servers, protoUDP, s[ipv6HeaderLen:]) != 0 || s[ipv6HeaderLen+9] != 0x12 || s[7] != 255 {
		t.Errorf("SOLICIT = %x", s)
	}
	if mac := MulticastMAC(AllDHCPv6Servers); mac.String() != "33:33:00:01:00:02" {
		t.Errorf("マルチキャストの MAC アドレス = %s", mac)
	}
}

// 近隣探索と DHCPv6 の解析は、どんな入力でも止まらない。
func FuzzParseND(f *testing.F) {
	f.Add(WithdrawRA(llRogue, macX, []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")}, []netip.Addr{llRogue}))
	f.Add(neighborAdvert(llRogue, llGW, macX, 0x20, 255))
	f.Add(advertise(llRogue, llGW, 1, llRogue, llGW))
	f.Add(RouterSolicit(llGW, macX))
	f.Fuzz(func(t *testing.T, b []byte) {
		ParseND(b)
		ParseDHCPv6(b)
	})
}
