//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func init() {
	// 許可した名前が、GW の外側の私的なアドレスと LAN のアドレスに解決される（DNS リバインディングの再現）。
	upstreamRecords["rebind.allowed.test"] = "192.168.77.5"
	upstreamRecords["lan.allowed.test"] = "10.77.0.50"
}

// TestEgressGuard は、1f-3 で v1 に残した GW の検知（2m-2）を確かめる：許可していない名前（SNI）への接続の検知、
// 直接指定したアドレスの学習、DNS で得たアドレスの許可への異常な追加の拒否と、DNS の応答の記録との突き合わせ。
func TestEgressGuard(t *testing.T) {
	if *susanooBin == "" {
		t.Fatal("-susanoo で susanoo の実行ファイルを指定してください")
	}
	pc1 := &machine{ns: "sus-c1", id: "pc-001", port: "p-c1"} // strict グループ（許可リスト）
	pc2 := &machine{ns: "sus-c2", id: "pc-002", port: "p-c2"} // 既定のグループ（学習モード）
	machines := []*machine{pc1, pc2}
	l := &lab{t: t, dir: t.TempDir()}
	buildTopology(t, machines, "203.0.113.4/24")
	l.init()
	l.writeGW([]map[string]any{
		{"name": "default", "isolation": "management", "egress": map[string]any{"default": "learn"}},
		{"name": "strict", "isolation": "management", "egress": map[string]any{
			"default": "deny", "allow": []map[string]any{{"domain": "allowed.test"}, {"domain": "*.allowed.test"}},
		}},
	}, map[string]any{"dns": map[string]any{"upstreams": []map[string]any{{"address": "203.0.113.2:53"}}}})
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range []string{"serve:203.0.113.2:443", "serve:203.0.113.2:8080", "serve:203.0.113.4:8080", "dnsserve:203.0.113.2:53"} {
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
	waitFor(t, "機器の台帳", 10*time.Second, func() bool { _, ok := l.hosts()[pc1.mac]; return ok })
	sh(t, "ip", "netns", "exec", nsGW, *susanooBin, "ctl", "group", pc1.mac, "strict", "-dir", l.ctrlDir, "-server", controllerAddr)
	flush := func() {
		t.Helper()
		if ok, out := runHelper(t, nsGW, "ctflush"); !ok {
			t.Fatalf("conntrack の表を消せません: %s", out)
		}
	}

	t.Log("段階1: 許可リストのグループの機器が、許可した名前のアドレス経由で、許可していない名前（SNI）に接続したら検知結果にする")
	firstLearn := time.Now()
	if rcode, ans := lookup(t, pc1.ns, gwLAN, "allowed.test", 1); rcode != 0 || ans != "203.0.113.2" {
		t.Fatalf("許可した名前の応答 = %d %s", rcode, ans)
	}
	if ok, out := runHelper(t, pc1.ns, "tls:203.0.113.2:443:www.allowed.test"); !ok {
		t.Fatalf("TLS の接続ができません: %s", out)
	}
	runHelper(t, pc1.ns, "tls:203.0.113.2:443:unlisted.example")
	waitFor(t, "許可していない名前への接続の検知結果", 15*time.Second, func() bool {
		return eventLine(l.events(), `"unlisted_sni"`, `"hostname":"unlisted.example"`, `"mac":"`+pc1.mac+`"`)
	})
	if eventLine(l.events(), `"unlisted_sni"`, `"hostname":"www.allowed.test"`) {
		t.Error("許可した名前への接続を検知しました")
	}
	if h := l.hosts()[pc1.mac]; h.Isolation != "" {
		t.Errorf("試験運用のルールで隔離しました: %s", h.Isolation)
	}

	t.Log("段階2: 学習モードのグループで、名前を引かずに直接指定したアドレスへの通信を学習の記録に載せ、許可リストの案に入れる")
	if !dialFrom(t, pc2.ns, "203.0.113.4:8080") {
		t.Fatal("学習モードのグループから接続できません")
	}
	if rcode, ans := lookup(t, pc2.ns, gwLAN, "allowed.test", 1); rcode != 0 || ans != "203.0.113.2" {
		t.Fatalf("名前の応答 = %d %s", rcode, ans)
	}
	if !dialFrom(t, pc2.ns, "203.0.113.2:8080") { // 名前を引いたアドレスは載せない
		t.Fatal("名前を引いたアドレスに接続できません")
	}
	time.Sleep(time.Second)
	flush()
	type learnedAddr struct {
		Group    string `json:"group"`
		Address  string `json:"address"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
	}
	direct := func() []string {
		var list []learnedAddr
		l.ctlJSON(&list, "learned")
		var out []string
		for _, e := range list {
			if e.Address != "" {
				out = append(out, e.Group+" "+e.Address+" "+e.Protocol)
			}
		}
		return out
	}
	waitFor(t, "直接指定したアドレスの学習", 15*time.Second, func() bool { return slices.Contains(direct(), "default 203.0.113.4 tcp") })
	if got := direct(); slices.Contains(got, "default 203.0.113.2 tcp") {
		t.Errorf("名前を引いたアドレスを直接指定したものとして載せました: %v", got)
	}
	var sug struct {
		Allow []struct {
			CIDR     string `json:"cidr"`
			Ports    []int  `json:"ports"`
			Protocol string `json:"protocol"`
		} `json:"allow"`
	}
	if !l.ctlJSON(&sug, "learned", "suggest", "-group", "default", "-min", "1") {
		t.Fatal("ctl learned suggest -json に失敗しました")
	}
	found := false
	for _, a := range sug.Allow {
		if a.CIDR == "203.0.113.4/32" && a.Protocol == "tcp" && slices.Equal(a.Ports, []int{8080}) {
			found = true
		}
	}
	if !found {
		t.Errorf("許可リストの案に直接指定したアドレスがありません: %+v", sug.Allow)
	}

	t.Log("段階3: 許可した名前が私的なアドレスや LAN のアドレスに解決されても、執行部は許可に加えず、検知結果にする（DNS リバインディングの防止）")
	for _, name := range []string{"rebind.allowed.test", "lan.allowed.test"} {
		if rcode, _ := lookup(t, pc1.ns, gwLAN, name, 1); rcode != 0 {
			t.Fatalf("%s の応答コード = %d", name, rcode)
		}
	}
	waitFor(t, "許可への異常な追加の検知結果", 10*time.Second, func() bool {
		ev := l.events()
		return eventLine(ev, `"learn_anomaly"`, `"192.168.77.5"`, "私的なアドレス") && eventLine(ev, `"learn_anomaly"`, `"10.77.0.50"`, "LAN のアドレス")
	})
	table := sh(t, "ip", "netns", "exec", nsGW, "nft", "list", "table", "inet", "susanoo_egress")
	if strings.Contains(table, "192.168.77.5") || strings.Contains(table, "10.77.0.50") || !strings.Contains(table, "203.0.113.2") {
		t.Errorf("許可の集合:\n%s", table)
	}

	t.Log("段階4: 執行部が許可に加えたアドレスは DNS の応答の記録と一致するので、LAN 側の処理の知らせの食い違いは出ない")
	if wait := 25*time.Second - time.Since(firstLearn); wait > 0 {
		time.Sleep(wait) // 突き合わせは、許可に加えてから 10 秒後の、10 秒ごとの確認で行う
	}
	if eventLine(l.events(), `"observation_mismatch"`) {
		t.Error("食い違いでないのに、LAN 側の処理の知らせの食い違いを検知しました")
	}
}
