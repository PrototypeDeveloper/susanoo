//go:build lab

package lab

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// nsRouter はブリッジ方式の試験の、上流のルーター（アドレスの変換をする家庭用のルーターの役）。
const nsRouter = "sus-rtr"

// upstreamRouterAddr は上流のルーターの LAN 側のアドレス。端末の既定の経路で、GW の既定の経路でもある。
const upstreamRouterAddr = "10.77.0.254"

// buildBridgeTopology は、ブリッジ方式の検証環境を作る。
//
//	sus-inet（疑似インターネット 203.0.113.2）
//	   │
//	sus-rtr（上流のルーター。WAN 203.0.113.1、LAN 10.77.0.254。アドレスを変換する）
//	   │
//	sus-gw（GW。ブリッジ br0 = wan0 + lan0、アドレス 10.77.0.1）
//	   │
//	sus-sw（スイッチ）── 端末（10.77.0.101 から。既定の経路は上流のルーター）
//
// IPv6 は GW、上流のルーター、端末で使う（リンクローカルだけ。不正なルーター広告の試験のため）。
func buildBridgeTopology(t *testing.T, machines []*machine, extraInet ...string) {
	t.Helper()
	all := []string{nsInet, nsRouter, nsGW, nsSW}
	for _, m := range machines {
		all = append(all, m.ns)
	}
	for _, ns := range all {
		ip(t, "netns", "add", ns)
		ip(t, "-n", ns, "link", "set", "lo", "up")
		if ns == nsSW || ns == nsInet {
			sh(t, "ip", "netns", "exec", ns, "sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1")
		} else {
			sh(t, "ip", "netns", "exec", ns, "sysctl", "-qw", "net.ipv6.conf.all.accept_dad=0", "net.ipv6.conf.default.accept_dad=0")
		}
	}
	t.Cleanup(func() {
		for _, ns := range all {
			exec.Command("ip", "netns", "del", ns).Run()
		}
	})
	ip(t, "-n", nsRouter, "link", "add", "wan", "type", "veth", "peer", "name", "eth0", "netns", nsInet)
	ip(t, "-n", nsRouter, "link", "add", "lan", "type", "veth", "peer", "name", "wan0", "netns", nsGW)
	ip(t, "-n", nsGW, "link", "add", "lan0", "type", "veth", "peer", "name", "p-gw", "netns", nsSW)
	ip(t, "-n", nsGW, "link", "add", "br0", "type", "bridge")
	for _, p := range []string{"wan0", "lan0"} {
		ip(t, "-n", nsGW, "link", "set", p, "master", "br0")
		ip(t, "-n", nsGW, "link", "set", p, "up")
	}
	ip(t, "-n", nsSW, "link", "add", "br0", "type", "bridge")
	ip(t, "-n", nsSW, "link", "set", "br0", "type", "bridge", "mcast_snooping", "0")
	ports := []string{"p-gw"}
	for _, m := range machines {
		ip(t, "-n", m.ns, "link", "add", "eth0", "type", "veth", "peer", "name", m.port, "netns", nsSW)
		ports = append(ports, m.port)
	}
	for _, p := range ports {
		ip(t, "-n", nsSW, "link", "set", p, "master", "br0")
		ip(t, "-n", nsSW, "link", "set", p, "up")
	}
	ip(t, "-n", nsSW, "link", "set", "br0", "up")
	for _, a := range []struct{ ns, dev, addr string }{
		{nsInet, "eth0", "203.0.113.2/24"},
		{nsRouter, "wan", "203.0.113.1/24"},
		{nsRouter, "lan", upstreamRouterAddr + "/24"},
		{nsGW, "br0", gwLAN + "/24"},
	} {
		ip(t, "-n", a.ns, "addr", "add", a.addr, "dev", a.dev)
		ip(t, "-n", a.ns, "link", "set", a.dev, "up")
	}
	for _, a := range extraInet {
		ip(t, "-n", nsInet, "addr", "add", a, "dev", "eth0")
	}
	ip(t, "-n", nsGW, "route", "add", "default", "via", upstreamRouterAddr)
	sh(t, "ip", "netns", "exec", nsRouter, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	nat := exec.Command("ip", "netns", "exec", nsRouter, "nft", "-f", "-")
	nat.Stdin = strings.NewReader("table ip lab_nat {\n\tchain post {\n\t\ttype nat hook postrouting priority 100; policy accept;\n\t\toifname \"wan\" masquerade\n\t}\n}\n")
	if out, err := nat.CombinedOutput(); err != nil {
		t.Fatalf("上流のルーターのアドレスの変換を設定できません: %v %s", err, out)
	}
	for i, m := range machines {
		m.ip = "10.77.0." + []string{"101", "102", "103", "104", "105"}[i]
		ip(t, "-n", m.ns, "addr", "add", m.ip+"/24", "dev", "eth0")
		ip(t, "-n", m.ns, "link", "set", "eth0", "up")
		ip(t, "-n", m.ns, "route", "add", "default", "via", upstreamRouterAddr)
		m.mac = regexp.MustCompile(`link/ether ([0-9a-f:]{17})`).FindStringSubmatch(ip(t, "-n", m.ns, "-o", "link", "show", "dev", "eth0"))[1]
	}
}

// TestBridge は、ブリッジ方式の GW（G1）を確かめる。GW は上流のルーターと LAN の間に透過のブリッジとして入り、
// アドレスの変換と DHCP は上流のルーターに任せたまま、外部通信の制御、DNS の制御、隔離、LAN の監視、通信の記録を行う。
func TestBridge(t *testing.T) {
	if *susanooBin == "" {
		t.Fatal("-susanoo で susanoo の実行ファイルを指定してください")
	}
	pc1 := &machine{ns: "sus-c1", id: "pc-001", port: "p-c1"} // 既定のグループ（学習モード）
	pc2 := &machine{ns: "sus-c2", id: "pc-002", port: "p-c2"} // strict グループ（許可リスト）
	pc3 := &machine{ns: "sus-c3", id: "pc-003", port: "p-c3"} // 上流のルーターのアドレスを名乗る
	pc4 := &machine{ns: "sus-c4", id: "pc-004", port: "p-c4"} // ルーター広告を送る
	machines := []*machine{pc1, pc2, pc3, pc4}
	l := &lab{t: t, dir: t.TempDir()}
	buildBridgeTopology(t, machines, "203.0.113.4/24")
	l.init()
	writeJSON(t, filepath.Join(l.dir, "policy.json"), map[string]any{
		"version": 1, "name": "検証環境（ブリッジ）", "issued_at": time.Now().UTC(), "response": "enforce", "on_failure": "fail_open",
		"groups": []map[string]any{
			{"name": "default", "isolation": "management", "egress": map[string]any{
				"default": "learn", "deny": []map[string]any{{"domain": "*.blocked.test"}},
			}},
			{"name": "strict", "isolation": "management", "egress": map[string]any{
				"default": "deny", "allow": []map[string]any{{"domain": "allowed.test", "ports": []int{8080}, "protocol": "tcp"}},
			}},
		},
	})
	writeJSON(t, filepath.Join(l.dir, "gw.json"), map[string]any{
		"listen": controllerAddr, "pki_dir": "controller", "state_dir": "gw-state", "policy": "policy.json", "heartbeat_timeout": "4s",
		"controller_user": gwControllerUID, "lan_user": gwLANUID,
		"bridge": map[string]any{"name": "br0", "lan": "lan0", "wan": "wan0", "admin_ports": []int{}},
		"dns":    map[string]any{"upstreams": []map[string]any{{"address": "203.0.113.2:53"}}},
	})
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range []string{"serve:203.0.113.2:8080", "serve:203.0.113.4:8080", "serve:203.0.113.2:443", "dnsserve:203.0.113.2:53"} {
		start(t, spec, nsInet, []string{helperEnv + "=" + spec}, self)
	}
	start(t, "GW", nsGW, nil, *susanooBin, "gw", "-config", filepath.Join(l.dir, "gw.json"))
	waitFor(t, "GW の起動", 10*time.Second, func() bool { return l.hosts() != nil })
	for _, k := range []string{"time_wait", "close", "close_wait", "last_ack", "fin_wait"} {
		sh(t, "ip", "netns", "exec", nsGW, "sysctl", "-qw", "net.netfilter.nf_conntrack_tcp_timeout_"+k+"=1")
	}
	rtrMAC := regexp.MustCompile(`link/ether ([0-9a-f:]{17})`).FindStringSubmatch(ip(t, "-n", nsRouter, "-o", "link", "show", "dev", "lan"))[1]

	t.Log("段階1: 端末は、ブリッジと上流のルーターを通って外部に接続できる。LAN の機器は ARP で台帳に載り、上流のルーターは載らない。通信と TLS の SNI が記録される")
	if !dialFrom(t, pc1.ns, "203.0.113.2:8080") {
		t.Fatal("ブリッジを通って外部に接続できません")
	}
	dialFrom(t, pc2.ns, upstreamRouterAddr+":1") // ARP で上流のルーターを探させる（接続の成否は問わない）
	waitFor(t, "機器の台帳", 10*time.Second, func() bool {
		h := l.hosts()
		return h[pc1.mac].IP == pc1.ip && h[pc2.mac].IP == pc2.ip
	})
	if _, ok := l.hosts()[rtrMAC]; ok {
		t.Errorf("上流のルーターを LAN の機器として台帳に載せました: %+v", l.hosts()[rtrMAC])
	}
	// TLS の SNI も記録する（ブリッジの通信の最初のパケットを NFLOG で受け取る）。上流のルーターのなりすまし（段階 6）で
	// 端末の ARP の表が書き換わる前に確かめる。
	if ok, _ := runHelper(t, pc1.ns, "tls:203.0.113.2:443:secure.bridge.test"); !ok {
		t.Error("TLS の ClientHello を送れません")
	}
	if ok, out := runHelper(t, nsGW, "ctflush"); !ok { // 接続の終わりのイベントをすぐに出させる
		t.Fatalf("conntrack の表を消せません: %s", out)
	}
	waitFor(t, "通信の記録", 15*time.Second, func() bool {
		return eventLine(l.events(), `"class_uid":4001`, `"ip":"203.0.113.2"`, `"port":8080`, `"ip":"`+pc1.ip+`"`)
	})
	waitFor(t, "SNI の記録", 15*time.Second, func() bool { return eventLine(l.events(), "secure.bridge.test") })

	t.Log("段階2: LAN から外部の DNS サーバーへの問い合わせは、GW のリゾルバに向け直され、拒否した名前は引けない")
	if rcode, answers := lookup(t, pc1.ns, "203.0.113.2", "x.blocked.test", 1); rcode != 3 {
		t.Errorf("拒否した名前の問い合わせ = %d %s（GW が NXDOMAIN を返すはず。上流は答える）", rcode, answers)
	}
	if rcode, answers := lookup(t, pc1.ns, "203.0.113.2", "allowed.test", 1); rcode != 0 || answers != "203.0.113.2" {
		t.Errorf("許可した名前の問い合わせ = %d %s", rcode, answers)
	}
	waitFor(t, "DNS の記録", 10*time.Second, func() bool { return eventLine(l.events(), `"class_uid":4003`, "x.blocked.test") })

	t.Log("段階3: 許可リストのグループは、許可した名前を引いた後だけ、そのアドレスと決めたポートに接続できる")
	sh(t, "ip", "netns", "exec", nsGW, *susanooBin, "ctl", "group", pc2.mac, "strict", "-dir", l.ctrlDir, "-server", controllerAddr)
	waitFor(t, "許可リストの反映", 10*time.Second, func() bool { return !dialFrom(t, pc2.ns, "203.0.113.2:8080") })
	if rcode, _ := lookup(t, pc2.ns, "203.0.113.2", "allowed.test", 1); rcode != 0 {
		t.Fatalf("strict の端末の問い合わせ = %d", rcode)
	}
	waitFor(t, "許可した名前のアドレスへの接続", 5*time.Second, func() bool { return dialFrom(t, pc2.ns, "203.0.113.2:8080") })
	if dialFrom(t, pc2.ns, "203.0.113.4:8080") {
		t.Error("許可していないアドレスに接続できました")
	}

	t.Log("段階4: 隔離した機器はブリッジを越えて通信できず、解除すると元に戻る")
	sh(t, "ip", "netns", "exec", nsGW, *susanooBin, "ctl", "isolate", pc1.mac, "-dir", l.ctrlDir, "-server", controllerAddr)
	waitFor(t, "隔離", 10*time.Second, func() bool { return !dialFrom(t, pc1.ns, "203.0.113.2:8080") })
	if ok, _ := runHelper(t, pc1.ns, "hold:"+controllerAddr+":0"); !ok {
		t.Error("隔離中の機器が GW の管理通信のポートに届きません")
	}
	sh(t, "ip", "netns", "exec", nsGW, *susanooBin, "ctl", "release", pc1.mac, "-dir", l.ctrlDir, "-server", controllerAddr)
	waitFor(t, "解除の後の接続", 10*time.Second, func() bool { return dialFrom(t, pc1.ns, "203.0.113.2:8080") })

	t.Log("段階5: GW 自身は、上流のルーター側から管理通信のポートに接続させない")
	if ok, _ := runHelper(t, nsRouter, "hold:"+controllerAddr+":0"); ok {
		t.Error("上流のルーター側から GW の管理通信のポートに接続できました")
	}

	t.Log("段階6: 上流のルーターのアドレスを名乗る ARP は、ゲートウェイのなりすましとして隔離する")
	if ok, out := runHelper(t, pc3.ns, "garp:eth0:"+upstreamRouterAddr); !ok {
		t.Fatalf("ARP を送れません: %s", out)
	}
	waitFor(t, "ゲートウェイのなりすましの隔離", 10*time.Second, func() bool {
		h := l.hosts()[pc3.mac]
		return h.Isolation != "" && h.Reason == "ゲートウェイのなりすまし"
	})

	t.Log("段階7: LAN の機器のルーター広告は、不正なルーターとして隔離し、ブリッジを越えさせない（上流のルーターと GW は従わない）")
	if ok, out := runHelper(t, pc4.ns, "ra:eth0,2001:db8:bad::/64,1800"); !ok {
		t.Fatalf("ルーター広告を送れません: %s", out)
	}
	waitFor(t, "不正なルーターの隔離", 10*time.Second, func() bool {
		h := l.hosts()[pc4.mac]
		return h.Isolation != "" && h.Reason == "不正なルーター広告"
	})
	time.Sleep(500 * time.Millisecond)
	for _, ns := range []string{nsRouter, nsGW} {
		if routes := sh(t, "ip", "-n", ns, "-6", "route", "show"); strings.Contains(routes, "default") || strings.Contains(routes, "2001:db8:bad") {
			t.Errorf("%s が LAN の機器のルーター広告に従いました:\n%s", ns, routes)
		}
	}
}
