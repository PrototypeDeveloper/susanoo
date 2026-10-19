//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// globalOf は名前空間 ns の eth0 の、ネットワーク prefix（例 "fd77:"）の IPv6 アドレスを返す。なければ空。
func globalOf(t *testing.T, ns, prefix string) string {
	t.Helper()
	out := sh(t, "ip", "-n", ns, "-6", "-o", "addr", "show", "dev", "eth0", "scope", "global")
	m := regexp.MustCompile(`inet6 (` + regexp.QuoteMeta(prefix) + `[0-9a-f:]+)/64`).FindStringSubmatch(out)
	if m == nil {
		return ""
	}
	return m[1]
}

// TestIPv6Router は、ルーター方式の GW の IPv6 の転送（G1）を確かめる。GW は LAN 側の /64 を RA で知らせ、
// 端末は SLAAC でアドレスを作り、GW が WAN 側のアドレスに変換して送り出す。外部通信の制御、DNS、隔離、通信の記録は
// IPv4 と同じく IPv6 にも効く。
func TestIPv6Router(t *testing.T) {
	if *susanooBin == "" {
		t.Fatal("-susanoo で susanoo の実行ファイルを指定してください")
	}
	pc1 := &machine{ns: "sus-c1", id: "pc-001", port: "p-c1"} // 既定のグループ（学習モード）
	pc2 := &machine{ns: "sus-c2", id: "pc-002", port: "p-c2"} // strict グループ（許可リスト）
	machines := []*machine{pc1, pc2}
	l := &lab{t: t, dir: t.TempDir()}
	buildTopology6(t, machines)
	for _, a := range []struct{ ns, dev, addr string }{
		{nsInet, "eth0", "2001:db8:113::2/64"},
		{nsGW, "wan0", "2001:db8:113::1/64"},
		{nsGW, "lan0", "fd77::1/64"},
	} {
		ip(t, "-n", a.ns, "-6", "addr", "add", a.addr, "dev", a.dev)
	}
	l.init()
	l.writeGW([]map[string]any{
		{"name": "default", "isolation": "management", "egress": map[string]any{"default": "learn"}},
		{"name": "strict", "isolation": "management", "egress": map[string]any{
			"default": "deny", "allow": []map[string]any{{"domain": "v6.test", "ports": []int{8080}, "protocol": "tcp"}},
		}},
	}, map[string]any{
		"router": map[string]any{"lan": "lan0", "wan": "wan0", "admin_ports": []int{}, "ipv6": true, "ra_interval": "5s"},
		"dns":    map[string]any{"upstreams": []map[string]any{{"address": "203.0.113.2:53"}}},
	})
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range []string{"serve:[2001:db8:113::2]:8080", "serve:[2001:db8:113::2]:9000", "dnsserve:203.0.113.2:53"} {
		start(t, spec, nsInet, []string{helperEnv + "=" + spec}, self)
	}
	start(t, "GW", nsGW, nil, *susanooBin, "gw", "-config", filepath.Join(l.dir, "gw.json"))
	waitFor(t, "GW の起動", 10*time.Second, func() bool { return l.devices() != nil })
	for _, k := range []string{"time_wait", "close", "close_wait", "last_ack", "fin_wait"} {
		sh(t, "ip", "netns", "exec", nsGW, "sysctl", "-qw", "net.netfilter.nf_conntrack_tcp_timeout_"+k+"=1")
	}
	for _, m := range machines {
		l.dhcp(m)
	}
	waitFor(t, "機器の台帳", 10*time.Second, func() bool { _, ok := l.hosts()[pc2.mac]; return ok })
	sh(t, "ip", "netns", "exec", nsGW, *susanooBin, "ctl", "group", pc2.mac, "strict", "-dir", l.ctrlDir, "-server", controllerAddr)
	inet6 := "[2001:db8:113::2]"
	dig := func(ns, server, name string) (int, string) {
		t.Helper()
		ok, out := runHelper(t, ns, "dig6:"+server+","+name+",28")
		m := regexp.MustCompile(`^rcode=(\d+) answers=(.*)$`).FindStringSubmatch(out)
		if !ok || m == nil {
			return -1, out
		}
		return int(m[1][0] - '0'), m[2]
	}

	t.Log("段階1: GW が RA で LAN の /64 と DNS サーバーを知らせ、端末は SLAAC でアドレスを作り、GW を既定の経路にする")
	var addr1, addr2 string
	waitFor(t, "端末の IPv6 アドレスと既定の経路", 15*time.Second, func() bool {
		addr1, addr2 = globalOf(t, pc1.ns, "fd77:"), globalOf(t, pc2.ns, "fd77:")
		return addr1 != "" && addr2 != "" && strings.Contains(sh(t, "ip", "-n", pc1.ns, "-6", "route", "show", "default"), "via fe80::")
	})
	for file, want := range map[string]string{"/proc/sys/net/ipv6/conf/all/forwarding": "1", "/proc/sys/net/ipv6/conf/wan0/accept_ra": "2", "/proc/sys/net/ipv6/conf/lan0/accept_ra": "0"} {
		if got := strings.TrimSpace(sh(t, "ip", "netns", "exec", nsGW, "cat", file)); got != want {
			t.Errorf("GW の %s = %s", file, got)
		}
	}

	t.Log("段階2: 既定のグループの端末は、GW が WAN 側のアドレスに変換して外部に IPv6 で接続できる（外からは LAN に戻る経路がない）")
	if !dialFrom(t, pc1.ns, inet6+":8080") {
		t.Fatal("IPv6 で外部に接続できません")
	}
	waitFor(t, "機器の台帳の IPv6 アドレス", 10*time.Second, func() bool {
		return strings.Contains(strings.Join(l.hosts()[pc1.mac].IPv6, ","), addr1)
	})
	if ok, out := runHelper(t, nsGW, "ctflush:6"); !ok { // 接続の終わりのイベントをすぐに出させる
		t.Fatalf("conntrack の表を消せません: %s", out)
	}
	waitFor(t, "IPv6 の通信の記録", 15*time.Second, func() bool {
		return eventLine(l.events(), `"class_uid":4001`, `"ip":"2001:db8:113::2"`, `"port":8080`, `"ip":"`+addr1+`"`)
	})

	t.Log("段階3: GW のリゾルバは IPv6 のアドレスでも答え、外部の DNS サーバーへの IPv6 の問い合わせも GW に向け直す")
	if rcode, answers := dig(pc1.ns, "fd77::1", "v6.test"); rcode != 0 || answers != "2001:db8:113::2" {
		t.Errorf("GW の IPv6 のリゾルバ = %d %s", rcode, answers)
	}
	if rcode, answers := dig(pc1.ns, "2001:db8:113::2", "v6.test"); rcode != 0 || answers != "2001:db8:113::2" {
		t.Errorf("外部の DNS への IPv6 の問い合わせ（向け直し）= %d %s", rcode, answers)
	}

	t.Log("段階4: 許可リストのグループは、IPv6 でも許可した名前を引いた後だけ、そのアドレスと決めたポートに接続できる")
	inNS(pc2.ns, "ping", "-6", "-c", "1", "-W", "2", "fd77::1").Run() // GW が端末のアドレスを近隣探索で知る
	waitFor(t, "strict の端末の IPv6 アドレス", 10*time.Second, func() bool {
		return strings.Contains(strings.Join(l.hosts()[pc2.mac].IPv6, ","), addr2)
	})
	if dialFrom(t, pc2.ns, inet6+":8080") {
		t.Fatal("名前を引く前に接続できました")
	}
	if rcode, answers := dig(pc2.ns, "fd77::1", "v6.test"); rcode != 0 || answers != "2001:db8:113::2" {
		t.Fatalf("strict の端末の問い合わせ = %d %s", rcode, answers)
	}
	waitFor(t, "許可した名前のアドレスへの接続", 5*time.Second, func() bool { return dialFrom(t, pc2.ns, inet6+":8080") })
	if dialFrom(t, pc2.ns, inet6+":9000") {
		t.Error("許可していないポートに接続できました")
	}

	t.Log("段階5: 隔離した機器は IPv6 でも外部に接続できず、DNS も使えない。解除すると元に戻る")
	sh(t, "ip", "netns", "exec", nsGW, *susanooBin, "ctl", "isolate", pc1.mac, "-dir", l.ctrlDir, "-server", controllerAddr)
	waitFor(t, "IPv6 の遮断", 10*time.Second, func() bool { return !dialFrom(t, pc1.ns, inet6+":8080") })
	// management の段階の隔離では、GW の遮断のルールが DNS の問い合わせを落とす（答えない）。
	if rcode, answers := dig(pc1.ns, "fd77::1", "v6.test"); rcode == 0 {
		t.Errorf("隔離中の IPv6 の問い合わせに答えました: %s", answers)
	}
	sh(t, "ip", "netns", "exec", nsGW, *susanooBin, "ctl", "release", pc1.mac, "-dir", l.ctrlDir, "-server", controllerAddr)
	waitFor(t, "解除の後の接続", 10*time.Second, func() bool { return dialFrom(t, pc1.ns, inet6+":8080") })

	t.Log("段階6: 外から LAN への新しい IPv6 の接続は通さない（経路があっても）")
	start(t, "端末のサーバー", pc1.ns, []string{helperEnv + "=serve:[" + addr1 + "]:7070"}, self)
	ip(t, "-n", nsInet, "-6", "route", "add", "fd77::/64", "via", "2001:db8:113::1")
	time.Sleep(200 * time.Millisecond)
	if dialFrom(t, nsInet, "["+addr1+"]:7070") {
		t.Error("外から LAN の端末に IPv6 で接続できました")
	}
	if !dialFrom(t, pc1.ns, "["+addr1+"]:7070") {
		t.Error("端末のサーバーが動いていません")
	}
}
