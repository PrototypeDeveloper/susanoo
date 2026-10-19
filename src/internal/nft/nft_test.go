package nft

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"susanoo/internal/policy"
)

func TestClientIsolationScript(t *testing.T) {
	got, err := ClientIsolation{
		Management: []netip.AddrPort{netip.MustParseAddrPort("10.77.0.1:8443")},
		Updates:    []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		AllowDHCP:  true,
	}.Script()
	if err != nil {
		t.Fatal(err)
	}
	want := `table inet susanoo_client {}
delete table inet susanoo_client
table inet susanoo_client {
	chain input {
		type filter hook input priority -10; policy drop;
		iif "lo" accept
		ip saddr 10.77.0.1 tcp sport 8443 ct state established,related accept
		udp sport 67 udp dport 68 accept
		ip saddr 192.0.2.0/24 ct state established,related accept
	}
	chain output {
		type filter hook output priority -10; policy drop;
		oif "lo" accept
		ip daddr 10.77.0.1 tcp dport 8443 accept
		udp sport 68 udp dport 67 accept
		ip daddr 192.0.2.0/24 accept
	}
	chain forward {
		type filter hook forward priority -10; policy drop;
	}
}
`
	if got != want {
		t.Errorf("スクリプトが違う\n--- got\n%s--- want\n%s", got, want)
	}
}

func TestClientIsolationIPv6(t *testing.T) {
	got, err := ClientIsolation{
		Management: []netip.AddrPort{
			netip.MustParseAddrPort("[fe80::1%eth0]:8443"),
			netip.MustParseAddrPort("[::ffff:10.77.0.1]:8443"),
		},
	}.Script()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip6 saddr fe80::1 tcp sport 8443",  // ゾーンは取り除く
		"ip daddr 10.77.0.1 tcp dport 8443", // IPv4 射影アドレスは IPv4 として扱う
		"icmpv6 type { nd-neighbor-solicit",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("%q が含まれない\n%s", want, got)
		}
	}
	if strings.Contains(got, "udp sport 67") {
		t.Error("許可していない DHCP のルールがある")
	}
}

func TestClientIsolationRejects(t *testing.T) {
	if _, err := (ClientIsolation{}).Script(); err == nil {
		t.Error("管理通信の宛先なしで隔離のルールを作った")
	}
	if _, err := (ClientIsolation{Management: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:0")}}).Script(); err == nil {
		t.Error("ポート 0 の宛先を受け付けた")
	}
}

func TestGWIsolationScript(t *testing.T) {
	got, err := GWIsolation{
		ManagementPort: 8443,
		MACs: map[string]policy.IsolationLevel{
			"02:00:00:00:00:0B": policy.IsolateManagement,
			"02:00:00:00:00:0d": policy.IsolateFull,
		},
		Addrs: map[netip.Addr]policy.IsolationLevel{
			netip.MustParseAddr("10.77.0.12"):        policy.IsolateManagement,
			netip.MustParseAddr("10.77.0.11"):        policy.IsolateManagement,
			netip.MustParseAddr("::ffff:10.77.0.11"): policy.IsolateManagement,
			netip.MustParseAddr("10.77.0.13"):        policy.IsolateFull,
			netip.MustParseAddr("2001:db8::13"):      policy.IsolateFull,
			netip.MustParseAddr("10.77.0.14"):        policy.IsolateManagementAndUpdates,
		},
		Updates: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}.Script()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet susanoo_gw {}\ndelete table inet susanoo_gw\ntable inet susanoo_gw {\n",
		"\tset isolate_full_v4 {\n\t\ttype ipv4_addr\n\t\telements = { 10.77.0.13 }\n\t}\n",
		"\tset isolate_full_v6 {\n\t\ttype ipv6_addr\n\t\telements = { 2001:db8::13 }\n\t}\n",
		// 並べ替えられ、IPv4 射影アドレスとの重複は 1 つにまとまる。
		"\tset isolate_management_v4 {\n\t\ttype ipv4_addr\n\t\telements = { 10.77.0.11, 10.77.0.12 }\n\t}\n",
		"\tset isolate_management_v6 {\n\t\ttype ipv6_addr\n\t}\n",
		"\tset updates_v4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { 192.0.2.0/24 }\n\t}\n",
		"\t\tip saddr @isolate_full_v4 drop\n",
		"\t\tip saddr @isolate_management_v4 tcp dport 8443 accept\n\t\tip saddr @isolate_management_v4 udp dport 67 accept\n\t\tip saddr @isolate_management_v4 drop\n",
		"\t\tip6 saddr @isolate_management_v6 tcp dport 8443 accept\n\t\tip6 saddr @isolate_management_v6 drop\n",
		"\t\tip saddr @isolate_updates_v4 ip daddr @updates_v4 accept\n",
		"\t\tip daddr @isolate_updates_v4 ip saddr @updates_v4 ct state established,related accept\n",
		"\t\ttype filter hook forward priority -10; policy accept;\n",
		// MAC アドレスは小文字にそろえ、送信元で照合する。
		"\tset isolate_management_mac {\n\t\ttype ether_addr\n\t\telements = { 02:00:00:00:00:0b }\n\t}\n",
		"\tset isolate_full_mac {\n\t\ttype ether_addr\n\t\telements = { 02:00:00:00:00:0d }\n\t}\n",
		"\t\tether saddr @isolate_management_mac tcp dport 8443 accept\n\t\tether saddr @isolate_management_mac udp dport 67 accept\n\t\tether saddr @isolate_management_mac drop\n",
		"\t\tether saddr @isolate_updates_mac ip daddr @updates_v4 accept\n\t\tether saddr @isolate_updates_mac ip daddr @updates_dyn_4 accept\n" +
			"\t\tether saddr @isolate_updates_mac ip6 daddr @updates_v6 accept\n\t\tether saddr @isolate_updates_mac ip6 daddr @updates_dyn_6 accept\n" +
			"\t\tether saddr @isolate_updates_mac drop\n",
		// 更新サーバーも許可する段階では、GW の DNS を使える。
		"\t\tip saddr @isolate_updates_v4 meta l4proto { tcp, udp } th dport 53 accept\n\t\tip saddr @isolate_updates_v4 drop\n",
		"\tset updates_dyn_4 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n",
		"\t\tip daddr @isolate_management_v4 drop\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("%q が含まれない\n%s", want, got)
		}
	}
}

func TestGWIsolationRejects(t *testing.T) {
	if _, err := (GWIsolation{}).Script(); err == nil {
		t.Error("管理通信のポートなしでルールを作った")
	}
	_, err := GWIsolation{
		ManagementPort: 8443,
		Addrs:          map[netip.Addr]policy.IsolationLevel{netip.MustParseAddr("10.0.0.1"): "all"},
	}.Script()
	if err == nil {
		t.Error("不明な隔離の段階を受け付けた")
	}
}

func TestGWIsolationRejectsBadMAC(t *testing.T) {
	for _, mac := range []string{"zz:00:00:00:00:01", "02:00:00:00:00:00:00:01", `02:00:00:00:00:01"; drop`} {
		_, err := GWIsolation{ManagementPort: 8443, MACs: map[string]policy.IsolationLevel{mac: policy.IsolateFull}}.Script()
		if err == nil {
			t.Errorf("不正な MAC アドレス %q を受け付けた", mac)
		}
	}
}

func TestRouterScript(t *testing.T) {
	got, err := Router{LAN: "lan0", WAN: "wan0", ManagementPort: 8443, AdminPorts: []uint16{22, 22, 2222}, DHCP: true}.Script()
	if err != nil {
		t.Fatal(err)
	}
	want := `table inet susanoo_router {}
delete table inet susanoo_router
table inet susanoo_router {
	chain input {
		type filter hook input priority 0; policy drop;
		iif "lo" accept
		ct state established,related accept
		ct state invalid drop
		icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept
		iifname "lan0" icmp type echo-request accept
		iifname "lan0" icmpv6 type echo-request accept
		iifname "lan0" tcp dport 8443 accept
		iifname "lan0" udp sport 68 udp dport 67 accept
		iifname "lan0" tcp dport { 22, 2222 } accept
	}
	chain forward {
		type filter hook forward priority 0; policy drop;
		meta nfproto ipv6 drop
		ct state established,related accept
		ct state invalid drop
		iifname "lan0" oifname "wan0" accept
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "wan0" masquerade
	}
}
`
	if got != want {
		t.Errorf("スクリプトが違う\n--- got\n%s--- want\n%s", got, want)
	}
}

func TestRouterRejects(t *testing.T) {
	for name, r := range map[string]Router{
		"不正な名前":    {LAN: `lan0" accept; #`, WAN: "wan0", ManagementPort: 8443},
		"長すぎる名前":   {LAN: "averyveryverylongname", WAN: "wan0", ManagementPort: 8443},
		"同じ名前":     {LAN: "eth0", WAN: "eth0", ManagementPort: 8443},
		"管理のポートなし": {LAN: "lan0", WAN: "wan0"},
	} {
		if _, err := r.Script(); err == nil {
			t.Errorf("%s: 受け付けた", name)
		}
	}
}

func TestDeleteTable(t *testing.T) {
	if got := DeleteTable(ClientTable); got != "table inet susanoo_client {}\ndelete table inet susanoo_client\n" {
		t.Errorf("スクリプトが違う: %q", got)
	}
}

func TestCommandRun(t *testing.T) {
	// nft の代わりに、標準入力をファイルに書き出すシェルを使う。
	out := filepath.Join(t.TempDir(), "script")
	c := Command{Path: "/bin/sh", Args: []string{"-c", `cat > "$0"`, out}}
	if err := c.Run(context.Background(), "table inet x {}\n"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "table inet x {}\n" {
		t.Errorf("渡したスクリプト = %q", got)
	}

	failing := Command{Path: "/bin/sh", Args: []string{"-c", "echo 'Error: syntax error' >&2; exit 1"}}
	err = failing.Run(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "syntax error") {
		t.Errorf("エラー = %v, nft のエラー出力を含むはず", err)
	}
}

func TestGWIsolationSetsScript(t *testing.T) {
	got, err := GWIsolation{
		ManagementPort: 8443,
		Addrs:          map[netip.Addr]policy.IsolationLevel{netip.MustParseAddr("10.77.0.11"): policy.IsolateFull},
		MACs:           map[string]policy.IsolationLevel{"02:00:00:00:00:0b": policy.IsolateFull},
	}.SetsScript()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"flush set inet susanoo_gw isolate_full_v4\nadd element inet susanoo_gw isolate_full_v4 { 10.77.0.11 }\n",
		"flush set inet susanoo_gw isolate_full_mac\nadd element inet susanoo_gw isolate_full_mac { 02:00:00:00:00:0b }\n",
		"flush set inet susanoo_gw isolate_management_v4\nflush set inet susanoo_gw isolate_management_v6\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("%q が含まれない\n%s", want, got)
		}
	}
	if strings.Contains(got, "updates_dyn") || strings.Contains(got, "delete table") {
		t.Errorf("DNS で得たアドレスかテーブル全体を消している\n%s", got)
	}
}

var testEgress = Egress{
	LAN:  "lan0",
	DNS:  netip.MustParseAddr("10.77.0.1"),
	DNS6: netip.MustParseAddr("fd77::1"),
	DoH:  []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32"), netip.MustParsePrefix("2001:4860:4860::8888/128")},
	Groups: []EgressGroup{
		{Name: "default", Default: policy.EgressLearn, Deny: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("203.0.113.128/25")}},
		{
			Name: "strict", Default: policy.EgressDeny, Members: []string{"02:00:00:00:00:0B"},
			Bypass: policy.Bypass{AllowQUIC: true, AllowDoH: true, AllowVPN: true},
			Allow: []EgressRule{
				{},
				{Protocol: "tcp", Ports: []uint16{443, 80}, CIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
				{Ports: []uint16{123}},
			},
		},
	},
}

func TestEgressScript(t *testing.T) {
	got, err := testEgress.Script()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet susanoo_egress {}\ndelete table inet susanoo_egress\ntable inet susanoo_egress {\n",
		"\t\ttype filter hook forward priority -5; policy accept;\n\t\tiifname != \"lan0\" accept\n\t\tct state established,related accept\n\t\tether saddr @g1_m jump g1\n\t\tjump g0\n",
		"\tset g1_m {\n\t\ttype ether_addr\n\t\telements = { 02:00:00:00:00:0b }\n\t}\n",
		// 含まれる CIDR はまとめる。
		"\tset g0_d_s4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { 203.0.113.0/24 }\n\t}\n",
		"\tset g1_a1_d4 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n",
		// 既定のグループは抜け道を遮断し、学習モードなので最後に通す。
		"\tchain g0 {\n\t\tudp dport 443 drop\n\t\tmeta l4proto { tcp, udp } th dport 853 drop\n\t\tip daddr @doh_4 meta l4proto { tcp, udp } th dport 443 drop\n",
		"\t\tmeta l4proto { esp, ah, gre } drop\n\t\tip daddr @g0_d_s4 drop\n\t\tip6 daddr @g0_d_s6 drop\n\t\taccept\n\t}\n",
		// 抜け道を許可したグループには遮断のルールがなく、許可の後に遮断する。
		"\tchain g1 {\n\t\tip daddr @g1_d_s4 drop\n",
		"\t\tip daddr @g1_a0_s4 accept\n\t\tip daddr @g1_a0_d4 accept\n",
		"\t\tip daddr @g1_a1_d4 tcp dport { 80, 443 } accept\n",
		"\t\tip daddr @g1_a2_d4 meta l4proto { tcp, udp } th dport { 123 } accept\n",
		"\t\tip6 daddr @g1_a2_d6 meta l4proto { tcp, udp } th dport { 123 } accept\n\t\tdrop\n\t}\n",
		"\t\tiifname \"lan0\" ip daddr != 10.77.0.1 udp dport 53 dnat ip to 10.77.0.1:53\n",
		"\t\tiifname \"lan0\" ip6 daddr != fd77::1 tcp dport 53 dnat ip6 to [fd77::1]:53\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("%q が含まれない\n%s", want, got)
		}
	}
	if strings.Contains(got[strings.Index(got, "chain g1"):], "udp dport 443 drop") {
		t.Error("QUIC を許可したグループで QUIC を遮断している")
	}
}

func TestEgressRejects(t *testing.T) {
	for name, e := range map[string]Egress{
		"グループなし":   {LAN: "lan0"},
		"不正な名前":    {LAN: "lan 0", Groups: testEgress.Groups},
		"不正な既定":    {LAN: "lan0", Groups: []EgressGroup{{Default: "open"}}},
		"不正なプロトコル": {LAN: "lan0", Groups: []EgressGroup{{Default: policy.EgressAllow, Allow: []EgressRule{{Protocol: "icmp"}}}}},
		"不正な MAC":  {LAN: "lan0", Groups: []EgressGroup{{Default: policy.EgressAllow}, {Default: policy.EgressAllow, Members: []string{"x"}}}},
	} {
		if _, err := e.Script(); err == nil {
			t.Errorf("%s: 受け付けた", name)
		}
	}
}

func TestEgressMembersScript(t *testing.T) {
	got, err := testEgress.MembersScript()
	if err != nil {
		t.Fatal(err)
	}
	if want := "flush set inet susanoo_egress g1_m\nadd element inet susanoo_egress g1_m { 02:00:00:00:00:0b }\n"; got != want {
		t.Errorf("スクリプト = %q, 期待値 %q", got, want)
	}
}

func TestAddWithTimeout(t *testing.T) {
	got := AddWithTimeout(EgressTable, AllowSet(1, 0, false), []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("::ffff:192.0.2.2")}, 90*time.Second)
	want := "add element inet susanoo_egress g1_a0_d4 { 192.0.2.1 timeout 90s, 192.0.2.2 timeout 90s }\n" +
		"delete element inet susanoo_egress g1_a0_d4 { 192.0.2.1, 192.0.2.2 }\n" +
		"add element inet susanoo_egress g1_a0_d4 { 192.0.2.1 timeout 90s, 192.0.2.2 timeout 90s }\n"
	if got != want {
		t.Errorf("スクリプト = %q\n期待値 %q", got, want)
	}
	if AddWithTimeout(EgressTable, "x", nil, time.Minute) != "" {
		t.Error("アドレスなしでスクリプトを作った")
	}
}

func TestFailOpenScript(t *testing.T) {
	got, err := FailOpenScript("lan0", netip.MustParseAddr("10.77.0.1"), netip.MustParseAddrPort("192.0.2.53:53"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `iifname "lan0" ip daddr 10.77.0.1 udp dport 53 dnat ip to 192.0.2.53:53`) || strings.Contains(got, "forward") {
		t.Errorf("スクリプト = %s", got)
	}
	got, err = FailOpenScript("lan0", netip.MustParseAddr("10.77.0.1"), netip.AddrPort{})
	if err != nil || got != DeleteTable(EgressTable) {
		t.Errorf("上流なしのスクリプト = %q, %v", got, err)
	}
}

func TestFlowLogScript(t *testing.T) {
	got, err := FlowLog{LAN: "lan0", Group: 100}.Script()
	if err != nil {
		t.Fatal(err)
	}
	want := "\t\ttype filter hook forward priority -20; policy accept;\n\t\tiifname \"lan0\" tcp dport { 80, 443 } ct original packets < 11 log group 100 snaplen 4096\n"
	if !strings.Contains(got, want) || !strings.HasPrefix(got, "table inet susanoo_flow {}\ndelete table inet susanoo_flow\n") {
		t.Errorf("スクリプト = %s", got)
	}
	if _, err := (FlowLog{LAN: "lan0"}).Script(); err == nil {
		t.Error("グループなしでルールを作った")
	}
	if _, err := (FlowLog{LAN: "bad name", Group: 1}).Script(); err == nil {
		t.Error("不正な名前を受け付けた")
	}
}

func TestParseSetJSON(t *testing.T) {
	data := []byte(`{"nftables": [{"metainfo": {"version": "1.0.9"}}, {"set": {"family": "inet", "name": "g1_a0_d4", "table": "susanoo_egress",
		"type": "ipv4_addr", "flags": ["timeout"], "elem": [
		{"elem": {"val": "192.0.2.10", "timeout": 330, "expires": 312}}, "192.0.2.11", {"prefix": {"addr": "192.0.2.0", "len": 24}}]}}]}`)
	elems, err := parseSetJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []Element{{netip.MustParseAddr("192.0.2.10"), 312 * time.Second}, {netip.MustParseAddr("192.0.2.11"), 0}}
	if !slices.Equal(elems, want) {
		t.Errorf("要素 = %+v", elems)
	}
	if _, err := parseSetJSON([]byte("not json")); err == nil {
		t.Error("JSON でない出力を受け付けた")
	}
	if _, err := (Command{}).ListSet(context.Background(), "x; flush ruleset", "s"); err == nil {
		t.Error("不正なテーブルの名前を受け付けた")
	}
}

func TestIntelScript(t *testing.T) {
	s, err := Intel{LAN: "lan0", Group: 101, Block: []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("203.0.113.5/32"), netip.MustParsePrefix("2001:db8::/32"),
	}}.Script()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet susanoo_intel", "elements = { 203.0.113.0/24 }", "elements = { 2001:db8::/32 }",
		`iifname "lan0" ip daddr @block4 limit rate 20/second burst 40 packets log group 101`, `iifname "lan0" ip daddr @block4 drop`,
		`iifname "lan0" ip6 daddr @block6 drop`, "hook forward priority -10",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("%q がない:\n%s", want, s)
		}
	}
	// 範囲がなければテーブルを消す。
	if s, err := (Intel{LAN: "lan0"}).Script(); err != nil || s != DeleteTable(IntelTable) {
		t.Errorf("空のとき = %q %v", s, err)
	}
	if _, err := (Intel{LAN: "lan0; flush ruleset", Block: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}).Script(); err == nil {
		t.Error("不正なインターフェースの名前を受け付けた")
	}
}

// 重なりを除くのは、大きな一覧でも速い。
func TestMergePrefixesLarge(t *testing.T) {
	var ps []string
	for i := range 60000 {
		ps = append(ps, netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}).String()+"/32")
	}
	ps = append(ps, "10.0.0.0/8")
	if got := mergePrefixes(ps); len(got) != 1 || got[0] != "10.0.0.0/8" {
		t.Errorf("重なりを除いた範囲 = %d 個", len(got))
	}
}

func TestAppControlScript(t *testing.T) {
	s, err := AppControl{Queue: 4242, Exempt: []netip.Addr{netip.MustParseAddr("10.77.0.1"), netip.MustParseAddr("fd00::1"), netip.MustParseAddr("10.77.0.1")}}.Script()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet susanoo_apps {}\ndelete table inet susanoo_apps\n",
		"meta mark 0x53550001 meta l4proto tcp reject with tcp reset",
		`oif "lo" accept`,
		"ip daddr { 10.77.0.1 } accept",
		"ip6 daddr { fd00::1 } accept",
		"meta l4proto { tcp, udp } ct state new queue num 4242 bypass",
		"type filter hook output priority 5; policy accept;",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("スクリプトに %q がありません:\n%s", want, s)
		}
	}
	// 拒否の印のルールは、ほかのどのルールより先に評価する（NF_REPEAT で戻したパケットを拒否するため）。
	if strings.Index(s, "meta mark") > strings.Index(s, `oif "lo"`) {
		t.Errorf("拒否の印のルールが先頭にない:\n%s", s)
	}
	if _, err := (AppControl{}).Script(); err == nil {
		t.Error("NFQUEUE の番号がないのにスクリプトを作った")
	}
}
