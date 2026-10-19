//go:build lab

package lab

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func init() {
	extraHelpers["ra"] = sendRA
	extraHelpers["na"] = sendNA
	extraHelpers["dhcp6"] = dhcp6Serve
}

// icmp6Send は、インターフェース iface からすべての機器（ff02::1）に ICMPv6 のメッセージ msg を送る。
// 送信元はインターフェースのリンクローカルのアドレスで、チェックサムはカーネルが入れる。ホップの上限は 255。
func icmp6Send(iface string, msg []byte) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_HOPS, 255); err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, ifi.Index); err != nil {
		return err
	}
	return syscall.Sendto(fd, msg, 0, &syscall.SockaddrInet6{Addr: netip.MustParseAddr("ff02::1").As16(), ZoneId: uint32(ifi.Index)})
}

// sendRA はルーター広告を送る（不正なルーターの再現）。arg は「インターフェース,ネットワーク,ルーターの寿命」。
func sendRA(arg string) int {
	parts := strings.Split(arg, ",")
	ifi, err := net.InterfaceByName(parts[0])
	if err != nil {
		fmt.Println(err)
		return 1
	}
	prefix := netip.MustParsePrefix(parts[1])
	lifetime, _ := strconv.Atoi(parts[2])
	msg := []byte{134, 0, 0, 0, 64, 0, byte(lifetime >> 8), byte(lifetime), 0, 0, 0, 0, 0, 0, 0, 0}
	msg = append(msg, 1, 1)
	msg = append(msg, ifi.HardwareAddr...)
	pio := make([]byte, 32)
	pio[0], pio[1], pio[2], pio[3] = 3, 4, byte(prefix.Bits()), 0xc0
	binary.BigEndian.PutUint32(pio[4:8], 86400)
	binary.BigEndian.PutUint32(pio[8:12], 14400)
	a := prefix.Addr().As16()
	copy(pio[16:], a[:])
	msg = append(msg, pio...)
	if err := icmp6Send(parts[0], msg); err != nil {
		fmt.Println(err)
		return 1
	}
	return 0
}

// sendNA は、対象のアドレスを自分のものと名乗る近隣広告を送る（なりすましの再現）。arg は「インターフェース,対象のアドレス」。
func sendNA(arg string) int {
	iface, target, _ := strings.Cut(arg, ",")
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		fmt.Println(err)
		return 1
	}
	msg := make([]byte, 24, 32)
	msg[0], msg[4] = 136, 0x20 // Override
	t := netip.MustParseAddr(target).As16()
	copy(msg[8:], t[:])
	msg = append(msg, 2, 1)
	msg = append(msg, ifi.HardwareAddr...)
	if err := icmp6Send(iface, msg); err != nil {
		fmt.Println(err)
		return 1
	}
	return 0
}

// dhcp6Serve は、SOLICIT に ADVERTISE で答え、DNS サーバーとして自分を知らせる DHCPv6 のサーバー（mitm6 などの再現）。
// arg はインターフェース。
func dhcp6Serve(iface string) int {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		fmt.Println(err)
		return 1
	}
	var ll net.IP
	addrs, _ := ifi.Addrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.IsLinkLocalUnicast() && ipn.IP.To4() == nil {
			ll = ipn.IP
		}
	}
	// 待ち受けはワイルドカードのアドレスに結び付くので、答えも同じソケットから送る（送信元はカーネルがリンクローカルを選ぶ）。
	in, err := net.ListenMulticastUDP("udp6", ifi, &net.UDPAddr{IP: net.ParseIP("ff02::1:2"), Port: 547})
	if err != nil {
		fmt.Println(err)
		return 1
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := in.ReadFromUDP(buf)
		if err != nil {
			return 1
		}
		if n < 4 || buf[0] != 1 {
			continue
		}
		fmt.Printf("SOLICIT を受け取りました（%s、取引 %x）\n", from, buf[1:4])
		reply := []byte{2, buf[1], buf[2], buf[3]}
		opt := func(code uint16, data []byte) {
			reply = binary.BigEndian.AppendUint16(reply, code)
			reply = binary.BigEndian.AppendUint16(reply, uint16(len(data)))
			reply = append(reply, data...)
		}
		opt(2, append([]byte{0, 3, 0, 1}, ifi.HardwareAddr...)) // サーバーの識別子
		opt(23, ll.To16())                                      // DNS サーバー
		if _, err := in.WriteToUDP(reply, from); err != nil {
			fmt.Println("ADVERTISE を送れません:", err)
		}
	}
}

// linkLocalOf は名前空間 ns のインターフェース dev のリンクローカルのアドレスを返す。
func linkLocalOf(t *testing.T, ns, dev string) string {
	t.Helper()
	out := sh(t, "ip", "-n", ns, "-6", "-o", "addr", "show", "dev", dev, "scope", "link")
	m := regexp.MustCompile(`inet6 (fe80::[0-9a-f:]+)/64`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("%s の %s にリンクローカルのアドレスがありません: %s", ns, dev, out)
	}
	return m[1]
}

// TestIPv6ND は IPv6 の LAN の監視（G8）を確かめる。LAN で IPv6 を転送しないルーター方式でも、端末は既定で RA に従うので、
// LAN の機器の不正なルーター広告で IPv6 の通信を横取りされうる。
func TestIPv6ND(t *testing.T) {
	if *susanooBin == "" {
		t.Fatal("-susanoo で susanoo の実行ファイルを指定してください")
	}
	pc := &machine{ns: "sus-c1", id: "pc-001", port: "p-c1"}
	rogue := &machine{ns: "sus-c2", id: "rogue-ra", port: "p-c2"}
	spoofer := &machine{ns: "sus-c3", id: "spoofer", port: "p-c3"}
	dhcp6 := &machine{ns: "sus-c4", id: "rogue-dhcp6", port: "p-c4"}
	l := &lab{t: t, dir: t.TempDir()}
	buildTopology6(t, []*machine{pc, rogue, spoofer, dhcp6})
	l.init()
	l.writeGW([]map[string]any{{"name": "default", "egress": map[string]any{"default": "allow"}, "isolation": "management"}}, map[string]any{
		"router": map[string]any{"lan": "lan0", "wan": "wan0", "admin_ports": []int{}, "nd_probe_interval": "2s"},
	})
	start(t, "GW", nsGW, nil, *susanooBin, "gw", "-config", filepath.Join(l.dir, "gw.json"))
	waitFor(t, "GW の起動", 10*time.Second, func() bool { return l.hosts() != nil })
	gwLL := linkLocalOf(t, nsGW, "lan0")
	pcLL := linkLocalOf(t, pc.ns, "eth0")

	t.Log("段階1: 端末の近隣探索から、IPv6 アドレスを機器の台帳に載せる。GW 自身は LAN のルーター広告に従わない")
	// GW のアドレスを探す近隣要請が GW に届く（ping の成否は問わない）。
	inNS(pc.ns, "ping", "-6", "-c", "1", "-W", "2", gwLL+"%eth0").Run()
	waitFor(t, "機器の IPv6 アドレス", 10*time.Second, func() bool {
		h := l.hosts()[pc.mac]
		return len(h.IPv6) > 0 && h.IPv6[0] == pcLL
	})
	if out := strings.TrimSpace(sh(t, "ip", "netns", "exec", nsGW, "cat", "/proc/sys/net/ipv6/conf/lan0/accept_ra")); out != "0" {
		t.Errorf("GW の LAN 側の accept_ra = %s", out)
	}

	t.Log("段階2: LAN の機器がルーター広告を送ると、不正なルーターとして隔離し、GW がその広告を取り消して端末の経路を元に戻す")
	if ok, out := runHelper(t, rogue.ns, "ra:eth0,2001:db8:bad::/64,1800"); !ok {
		t.Fatalf("ルーター広告を送れません: %s", out)
	}
	waitFor(t, "不正なルーターの隔離", 10*time.Second, func() bool {
		h := l.hosts()[rogue.mac]
		return h.Isolation != "" && h.Reason == "不正なルーター広告"
	})
	// 端末は広告に従ってアドレスを作ったが、GW の取り消しで、既定の経路とネットワークの経路が消え、アドレスは新しい通信に使われない。
	waitFor(t, "広告の取り消し", 10*time.Second, func() bool {
		addrs := sh(t, "ip", "-n", pc.ns, "-6", "addr", "show", "dev", "eth0")
		routes := sh(t, "ip", "-n", pc.ns, "-6", "route", "show")
		return strings.Contains(addrs, "2001:db8:bad:") && strings.Contains(addrs, "deprecated") &&
			!strings.Contains(routes, "default") && !strings.Contains(routes, "2001:db8:bad::/64")
	})
	if routes := sh(t, "ip", "-n", nsGW, "-6", "route", "show"); strings.Contains(routes, "default") {
		t.Errorf("GW が不正なルーターの広告に従いました:\n%s", routes)
	}
	waitFor(t, "不正なルーターの検知結果", 10*time.Second, func() bool { return eventLine(l.events(), `"rogue_router"`, rogue.mac, "2001:db8:bad::/64") })

	t.Log("段階3: GW のリンクローカルのアドレスを名乗る近隣広告は、ゲートウェイのなりすましとして隔離する")
	if ok, out := runHelper(t, spoofer.ns, "na:eth0,"+gwLL); !ok {
		t.Fatalf("近隣広告を送れません: %s", out)
	}
	waitFor(t, "ゲートウェイのなりすましの隔離", 10*time.Second, func() bool {
		h := l.hosts()[spoofer.mac]
		return h.Isolation != "" && h.Reason == "ゲートウェイのなりすまし"
	})

	t.Log("段階4: GW の問い合わせに DHCPv6 のサーバーとして答える機器は、DNS の差し替えの疑いで隔離する")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start(t, "不正な DHCPv6 サーバー", dhcp6.ns, []string{helperEnv + "=dhcp6:eth0"}, self)
	waitFor(t, "不正な DHCPv6 サーバーの隔離", 20*time.Second, func() bool {
		h := l.hosts()[dhcp6.mac]
		return h.Isolation != "" && h.Reason == "不正な DHCPv6 サーバー"
	})
	if !eventLine(l.events(), `"rogue_dhcpv6"`, dhcp6.mac) {
		t.Error("不正な DHCPv6 サーバーの検知結果がありません")
	}
	// 端末は隔離されていない。
	if h := l.hosts()[pc.mac]; h.Isolation != "" {
		t.Errorf("端末を隔離しました: %+v", h)
	}
	actions := l.auditActions()
	for _, mac := range []string{rogue.mac, spoofer.mac, dhcp6.mac} {
		if !strings.Contains(strings.Join(actions, " "), "host.isolate:"+mac) {
			t.Errorf("監査ログに %s の隔離がありません: %v", mac, actions)
		}
	}
}
