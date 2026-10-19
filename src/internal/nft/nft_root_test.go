package nft

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"susanoo/internal/policy"
)

// TestScriptsWithRealNFT は、生成したルールを実際の nft で確認する（nft -c なので適用はしない）。
// root 権限が必要で、ホストのネットワーク名前空間では実行しない（make lab-test で実行する）。
func TestScriptsWithRealNFT(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root 権限が必要（make lab-test で実行する）")
	}
	self, err1 := os.Readlink("/proc/self/ns/net")
	host, err2 := os.Readlink("/proc/1/ns/net")
	if err1 != nil || err2 != nil || self == host {
		t.Skip("ホストのネットワーク名前空間では実行しない")
	}
	check := Command{Args: []string{"-c"}}

	mgmt4 := netip.MustParseAddrPort("10.77.0.1:8443")
	mgmt6 := netip.MustParseAddrPort("[fd00::1]:8443")
	up4 := netip.MustParsePrefix("192.0.2.0/24")
	up6 := netip.MustParsePrefix("2001:db8::/32")

	scripts := map[string]func() (string, error){
		"CLIENT の自己隔離（IPv4）": ClientIsolation{Management: []netip.AddrPort{mgmt4}, AllowDHCP: true}.Script,
		"CLIENT の自己隔離（IPv6 と更新サーバー）": ClientIsolation{
			Management: []netip.AddrPort{mgmt4, mgmt6}, Updates: []netip.Prefix{up4, up6}, AllowDHCP: true,
		}.Script,
		"GW の遮断（空）":            GWIsolation{ManagementPort: 8443}.Script,
		"CLIENT のプロセス単位の通信の制御": AppControl{Queue: AppsQueue, Exempt: []netip.Addr{mgmt4.Addr(), mgmt6.Addr()}}.Script,
		"GW の遮断（全段階）": GWIsolation{
			ManagementPort: 8443,
			MACs: map[string]policy.IsolationLevel{
				"02:00:00:00:00:11": policy.IsolateFull,
				"02:00:00:00:00:12": policy.IsolateManagement,
				"02:00:00:00:00:13": policy.IsolateManagementAndUpdates,
			},
			Addrs: map[netip.Addr]policy.IsolationLevel{
				netip.MustParseAddr("10.77.0.11"):   policy.IsolateFull,
				netip.MustParseAddr("10.77.0.12"):   policy.IsolateManagement,
				netip.MustParseAddr("10.77.0.13"):   policy.IsolateManagementAndUpdates,
				netip.MustParseAddr("fd00::11"):     policy.IsolateFull,
				netip.MustParseAddr("fd00::12"):     policy.IsolateManagement,
				netip.MustParseAddr("fd00::13"):     policy.IsolateManagementAndUpdates,
				netip.MustParseAddr("10.77.0.14"):   policy.IsolateManagement,
				netip.MustParseAddr("2001:db8::14"): policy.IsolateManagement,
			},
			Updates: []netip.Prefix{up4, up6, netip.MustParsePrefix("192.0.2.128/25")},
		}.Script,
		"ルーター方式":  Router{LAN: "lan0", WAN: "wan0", ManagementPort: 8443, AdminPorts: []uint16{22}, DHCP: true, DNS: true, WANDHCP: true}.Script,
		"テーブルの削除": func() (string, error) { return DeleteTable(ClientTable), nil },
		"外部通信の制御と、DNS で得たアドレスの追加": func() (string, error) {
			s, err := testEgress.Script()
			if err != nil {
				return "", err
			}
			m, err := testEgress.MembersScript()
			add := AddWithTimeout(EgressTable, AllowSet(1, 1, false), []netip.Addr{netip.MustParseAddr("192.0.2.10")}, time.Minute)
			add6 := AddWithTimeout(EgressTable, AllowSet(1, 1, true), []netip.Addr{netip.MustParseAddr("2001:db8::10")}, time.Minute)
			return s + m + add + add + add6, err
		},
		"通信の記録": FlowLog{LAN: "lan0", Group: 100, Ports: []uint16{80, 443, 8443}}.Script,
		"脅威情報のアドレスの遮断": Intel{LAN: "lan0", Group: 101, Block: []netip.Prefix{
			netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("203.0.113.5/32"), netip.MustParsePrefix("198.51.100.7/32"),
			netip.MustParsePrefix("2001:db8:bad::/48"),
		}}.Script,
		"障害時に通す": func() (string, error) {
			return FailOpenScript("lan0", netip.MustParseAddr("10.77.0.1"), netip.MustParseAddrPort("192.0.2.53:53"))
		},
		"ブリッジ方式": BridgeRules{Bridge: "br0", LAN: "lan0", WAN: "wan0", ManagementPort: 8443, AdminPorts: []uint16{22}, WANDHCP: true,
			DNS: netip.MustParseAddr("10.77.0.1"), MAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, TrustedRouters: []string{"02:00:00:00:00:fe"}}.Script,
		"ブリッジ方式（DNS なし）": BridgeRules{Bridge: "br0", LAN: "lan0", WAN: "wan0", ManagementPort: 8443}.Script,
		"ブリッジ方式の外部通信の制御": func() (string, error) {
			e := testEgress
			e.Family = Bridge
			s, err := e.Script()
			if err != nil {
				return "", err
			}
			m, err := e.MembersScript()
			add := AddWithTimeoutIn(Bridge, EgressTable, AllowSet(1, 1, false), []netip.Addr{netip.MustParseAddr("192.0.2.10")}, time.Minute)
			return s + m + add, err
		},
		"ブリッジ方式の遮断": func() (string, error) {
			g := GWIsolation{Family: Bridge, ManagementPort: 8443, MACs: map[string]policy.IsolationLevel{"02:00:00:00:00:21": policy.IsolateManagementAndUpdates},
				Addrs: map[netip.Addr]policy.IsolationLevel{netip.MustParseAddr("10.77.0.11"): policy.IsolateFull}, Updates: []netip.Prefix{up4}}
			full, err := g.Script()
			if err != nil {
				return "", err
			}
			sets, err := g.SetsScript()
			return full + sets, err
		},
		"ブリッジ方式の通信の記録": FlowLog{Family: Bridge, LAN: "lan0", Group: 100}.Script,
		"ブリッジ方式の脅威情報":  Intel{Family: Bridge, LAN: "lan0", Group: 101, Block: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8:bad::/48")}}.Script,
		"GW の遮断の集合の入れ替え": func() (string, error) {
			g := GWIsolation{ManagementPort: 8443, MACs: map[string]policy.IsolationLevel{"02:00:00:00:00:21": policy.IsolateManagementAndUpdates}, Updates: []netip.Prefix{up4}}
			full, err := g.Script()
			if err != nil {
				return "", err
			}
			sets, err := g.SetsScript()
			dyn := AddWithTimeout(GWTable, UpdatesDynamicSet(false), []netip.Addr{netip.MustParseAddr("192.0.2.20")}, time.Minute)
			return full + dyn + sets, err
		},
	}
	for name, script := range scripts {
		t.Run(name, func(t *testing.T) {
			s, err := script()
			if err != nil {
				t.Fatal(err)
			}
			if err := check.Run(context.Background(), s); err != nil {
				t.Errorf("nft が受け付けない: %v\n%s", err, s)
			}
		})
	}
}

// TestListSetWithRealNFT は、DNS で得たアドレスを集合に加え、その中身を実際の nft で読み出す（ポリシーを切り替えるときに
// 引き継ぐため）。テーブルは実際に作るので、検証環境の使い捨ての名前空間の中だけで動かす。
func TestListSetWithRealNFT(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root 権限が必要（make lab-test で実行する）")
	}
	self, err1 := os.Readlink("/proc/self/ns/net")
	host, err2 := os.Readlink("/proc/1/ns/net")
	if err1 != nil || err2 != nil || self == host {
		t.Skip("ホストのネットワーク名前空間では実行しない")
	}
	ctx := context.Background()
	var c Command
	script, err := testEgress.Script()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Run(ctx, script); err != nil {
		t.Fatal(err)
	}
	defer c.Run(ctx, DeleteTable(EgressTable))
	set := AllowSet(1, 0, false)
	add := AddWithTimeout(EgressTable, set, []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")}, 5*time.Minute)
	if err := c.Run(ctx, add); err != nil {
		t.Fatal(err)
	}
	elems, err := c.ListSet(ctx, EgressTable, set)
	if err != nil {
		t.Fatal(err)
	}
	if len(elems) != 2 {
		t.Fatalf("集合の要素 = %+v", elems)
	}
	for _, e := range elems {
		if (e.Addr != netip.MustParseAddr("192.0.2.10") && e.Addr != netip.MustParseAddr("192.0.2.11")) || e.Expires <= 4*time.Minute || e.Expires > 5*time.Minute {
			t.Errorf("要素 = %+v", e)
		}
	}
	if _, err := c.ListSet(ctx, EgressTable, "no_such_set"); err == nil {
		t.Error("ない集合を読めた")
	}
}
