package controller

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/policy"
)

var (
	macPC6   = net.HardwareAddr{2, 0, 0, 0, 0, 0x61}
	macEvil6 = net.HardwareAddr{2, 0, 0, 0, 0, 0x66}
	llPC6    = netip.MustParseAddr("fe80::61")
	llEvil6  = netip.MustParseAddr("fe80::66")
)

func waitWithdrawals(t *testing.T, lan *fakeLAN, n int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(lan.withdrawals()) < n {
		if time.Now().After(deadline) {
			t.Fatalf("広告の取り消しが %d 回しかない", len(lan.withdrawals()))
		}
		time.Sleep(10 * time.Millisecond)
	}
	return lan.withdrawals()
}

// 近隣探索で見えた IPv6 アドレスを機器の台帳に載せ、GW の IPv6 アドレスやほかの機器のアドレスを名乗る機器を検知する。
func TestNDAddressesAndSpoofing(t *testing.T) {
	lan := &fakeLAN{}
	f := startWith(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false), lan)
	admin := f.peer(pki.RoleAdmin, "admin")

	// GW 自身が送ったものは見ない。重複の確認（送信元が未指定）のアドレスは載せない。
	f.ctrl.ObserveND(NDObservation{Frame: gwMAC, Type: 136, Src: gwLinkLocal, Target: gwLinkLocal})
	f.ctrl.ObserveND(NDObservation{Frame: macPC6, Type: 135, Src: netip.IPv6Unspecified(), Target: netip.MustParseAddr("2001:db8::99")})
	f.ctrl.ObserveND(NDObservation{Frame: macPC6, Type: 135, Src: llPC6, Target: gwLinkLocal})
	f.ctrl.ObserveND(NDObservation{Frame: macPC6, Type: 136, Src: llPC6, Target: netip.MustParseAddr("2001:db8::61")})
	hosts := f.hosts(admin)
	if _, ok := hosts[gwMAC.String()]; ok {
		t.Error("GW 自身を機器として台帳に載せた")
	}
	if h := hosts[macPC6.String()]; !slices.Equal(h.IPv6, []string{"fe80::61", "2001:db8::61"}) {
		t.Errorf("機器の IPv6 アドレス = %v", h.IPv6)
	}

	// ほかの機器が最近使ったアドレスを名乗ると、アドレスのなりすまし。
	f.ctrl.ObserveND(NDObservation{Frame: macEvil6, Type: 136, Src: llEvil6, Target: llPC6, Override: true})
	h := f.hosts(admin)[macEvil6.String()]
	if h.Isolation == "" || h.Reason != ReasonIPSpoofing || slices.Contains(h.IPv6, "fe80::61") {
		t.Fatalf("アドレスのなりすまし = %+v", h)
	}
	// GW のアドレスを名乗ると、ゲートウェイのなりすまし（検知結果は 1 分に 1 回）。
	other := net.HardwareAddr{2, 0, 0, 0, 0, 0x67}
	f.ctrl.ObserveND(NDObservation{Frame: other, Type: 136, Src: gwLinkLocal, Target: gwLinkLocal, Override: true})
	f.ctrl.ObserveND(NDObservation{Frame: other, Type: 136, Src: gwLinkLocal, Target: gwLinkLocal, Override: true})
	if h := f.hosts(admin)[other.String()]; h.Reason != ReasonGatewaySpoofing || len(h.IPv6) != 0 {
		t.Errorf("ゲートウェイのなりすまし = %+v", h)
	}
	if n := strings.Count(eventsText(t, f.dir), `"gateway_spoofing"`); n != 1 {
		t.Errorf("ゲートウェイのなりすましの検知結果 = %d 件", n)
	}
	// 機器の IPv6 アドレスは、数の上限を超えたら古いものを忘れる。保存して読み直しても残る。
	for i := range maxHostIPv6 + 2 {
		f.clock.advance(time.Second)
		f.ctrl.ObserveND(NDObservation{Frame: macPC6, Type: 135, Src: netip.MustParseAddr(fmt.Sprintf("2001:db8::1:%x", i+1)), Target: gwLinkLocal})
	}
	if h := f.hosts(admin)[macPC6.String()]; len(h.IPv6) != maxHostIPv6 || slices.Contains(h.IPv6, "fe80::61") {
		t.Errorf("上限を超えた IPv6 アドレス = %v", h.IPv6)
	}
}

// LAN の機器のルーター広告は不正なルーターとして隔離し、隔離したら GW がその広告を取り消す。認めたルーターは除く。
func TestRogueRouter(t *testing.T) {
	lan := &fakeLAN{}
	dir := t.TempDir()
	f := startWith(t, pkitest.New(t), dir, testPolicy(policy.ResponseEnforce, false), lan)
	admin := f.peer(pki.RoleAdmin, "admin")
	ra := NDObservation{Frame: macEvil6, Type: 134, Src: llEvil6, RouterLifetime: 1800,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8:bad::/64")}, RDNSS: []netip.Addr{llEvil6}}
	f.ctrl.ObserveND(ra)
	h := f.hosts(admin)[macEvil6.String()]
	if h.Isolation == "" || h.Reason != ReasonRogueRouter {
		t.Fatalf("不正なルーター = %+v", h)
	}
	if got := waitWithdrawals(t, lan, 1); got[0] != "fe80::66 02:00:00:00:00:66 [2001:db8:bad::/64] [fe80::66]" {
		t.Errorf("取り消し = %v", got)
	}
	// 隔離中に広告を続けると、間をおいて取り消し直す（検知結果は 1 分に 1 回）。
	f.ctrl.ObserveND(ra)
	time.Sleep(50 * time.Millisecond)
	if n := len(lan.withdrawals()); n != 1 {
		t.Errorf("間をおかずに取り消した: %d 回", n)
	}
	f.clock.advance(raWithdrawGap)
	f.ctrl.ObserveND(ra)
	waitWithdrawals(t, lan, 2)
	if n := strings.Count(eventsText(t, dir), `"rogue_router"`); n != 1 {
		t.Errorf("不正なルーターの検知結果 = %d 件", n)
	}

	// 試験運用（monitor）なら隔離も取り消しもしない。
	g := startWith(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseMonitor, false), &fakeLAN{})
	g.ctrl.ObserveND(ra)
	if h := g.hosts(g.peer(pki.RoleAdmin, "admin"))[macEvil6.String()]; h.Isolation != "" {
		t.Errorf("監視モードで隔離した: %+v", h)
	}
	if n := len(g.lan.withdrawals()); n != 0 {
		t.Errorf("監視モードで取り消した: %d 回", n)
	}
}

// 認めたルーターの広告と DHCPv6 は不正としない。GW の問い合わせに答えた DHCPv6 のサーバーは隔離する。
func TestTrustedRouterAndRogueDHCPv6(t *testing.T) {
	lan := &fakeLAN{}
	f := startWith(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false), lan)
	f.ctrl.cfg.TrustedRouters = []string{"02:00:00:00:00:61"}
	admin := f.peer(pki.RoleAdmin, "admin")
	f.ctrl.ObserveND(NDObservation{Frame: macPC6, Type: 134, Src: llPC6, RouterLifetime: 1800})
	f.ctrl.ObserveDHCPv6(DHCPv6Observation{Frame: macPC6, Src: llPC6})
	if h := f.hosts(admin)[macPC6.String()]; h.Isolation != "" {
		t.Errorf("認めたルーターを隔離した: %+v", h)
	}
	f.ctrl.ObserveDHCPv6(DHCPv6Observation{Frame: macEvil6, Src: llEvil6, DNS: []netip.Addr{llEvil6}, Address: []netip.Addr{netip.MustParseAddr("2001:db8:bad::10")}})
	h := f.hosts(admin)[macEvil6.String()]
	if h.Isolation == "" || h.Reason != ReasonRogueDHCPv6 || !slices.Contains(h.IPv6, "fe80::66") {
		t.Fatalf("不正な DHCPv6 サーバー = %+v", h)
	}
	if !strings.Contains(eventsText(t, f.dir), "2001:db8:bad::10") {
		t.Error("検知結果に割り当てようとしたアドレスがない")
	}
}
