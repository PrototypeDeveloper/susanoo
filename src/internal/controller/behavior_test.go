package controller

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/policy"
	"susanoo/internal/sign"
)

const behaviorRules = `{"version": %d, "name": "振る舞い", "issued_at": "2026-10-18T00:00:00Z",
  "behavior": {"internal_scan": {"targets": 5, "window": "1m"}, "new_destinations": {"count": 3, "window": "10m", "baseline": "1m"}},
  "rules": [{"id": "internal-scan", "name": "LAN 内のスキャン", "finding": "internal_scan", "mode": "enforce", "score": 100}]}`

// GW の観測から振る舞いを検知して検知結果にし、検知ルールで評価する。加点にしたスキャンでは隔離し、
// 既定のまま（試験運用）の新しい宛先の急増と周期的な通信は記録だけする。
func TestBehaviorDetection(t *testing.T) {
	env := pkitest.New(t)
	signer := newPolicySigner(t)
	dir := t.TempDir()
	f := startRules(t, env, dir, testPolicy(policy.ResponseEnforce, false), signer)
	admin := f.peer(pki.RoleAdmin, "admin")
	if status, body := admin.do(http.MethodPost, api.PathRules, api.RulesPush{Envelope: signRules(t, signer, sign.PurposeRules, rulesSet(1, behaviorRules))}); status != http.StatusOK {
		t.Fatalf("配布の応答 = %d %s", status, body)
	}
	scanner := netip.MustParseAddr("127.0.0.66")
	f.ctrl.ObserveLease(macBad.String(), scanner, "scanner", f.clock.now().Add(time.Hour), false)

	// GW 自身と、LAN の外のアドレスは数えない。
	for i := range 10 {
		f.ctrl.ObserveARPRequest(gwMAC, netip.AddrFrom4([4]byte{127, 0, 1, byte(i)}))
		f.ctrl.ObserveARPRequest(macBad, netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}))
	}
	if h := f.hosts(admin)[macBad.String()]; h.Isolation != "" {
		t.Fatalf("数えない ARP で隔離した: %+v", h)
	}
	for i := range 5 {
		f.ctrl.ObserveARPRequest(macBad, netip.AddrFrom4([4]byte{127, 0, 2, byte(i)}))
	}
	if h := f.hosts(admin)[macBad.String()]; h.Isolation != policy.IsolateManagementAndUpdates || h.Reason != "LAN 内のスキャン" {
		t.Fatalf("スキャンした機器 = %+v", h)
	}
	if ev := eventsText(t, f.dir); !strings.Contains(ev, `"internal_scan"`) || !strings.Contains(ev, `"targets":5`) {
		t.Errorf("スキャンの検知結果がない")
	}

	// 学習の期間（1 分）の後に、初めての宛先が 3 つ続くと知らせる（既定のルールは試験運用）。
	f.dns(scanner, "www.usual.example")
	f.clock.advance(2 * time.Minute)
	for i := range 3 {
		f.dns(scanner, fmt.Sprintf("x.new%d.example", i))
	}
	f.dns(scanner, "api.usual.example") // 覚えた宛先
	// 周期的な通信：SNI を引き継ぎ、10 秒より長い一定の間隔の接続が 8 回続く。
	src, dst := netip.AddrPortFrom(scanner, 40000), netip.MustParseAddrPort("203.0.113.9:443")
	for i := range 8 {
		at := f.clock.now().Add(time.Duration(i) * 30 * time.Second)
		f.ctrl.RecordFlow(FlowRecord{Open: true, Time: at, Proto: 6, Src: src, Dst: dst, SNI: "beacon.example.test"})
		f.ctrl.RecordFlow(FlowRecord{Time: at.Add(time.Second), Proto: 6, Src: src, Dst: dst, BytesOut: 300, Start: at, End: at.Add(time.Second)})
	}
	ev := eventsText(t, f.dir)
	if strings.Count(ev, `"new_destinations"`) != 1 || !strings.Contains(ev, "new0.example") || strings.Contains(ev, "usual.example、") {
		t.Errorf("新しい宛先の急増の検知結果 = %d 件", strings.Count(ev, `"new_destinations"`))
	}
	if !strings.Contains(ev, `"beacon"`) || !strings.Contains(ev, `"hostname":"beacon.example.test"`) {
		t.Error("周期的な通信の検知結果がない")
	}
	info := f.rulesInfo(admin)
	for id, want := range map[string]api.RuleStatus{"internal-scan": {Hits: 1}, "new-destinations": {Monitored: 1}, "beacon": {Monitored: 1}} {
		if r := ruleStatus(info, id); r.Hits != want.Hits || r.Monitored != want.Monitored {
			t.Errorf("%s の回数 = %+v", id, r)
		}
	}

	// 覚えた宛先は、起動し直しても使う。
	f.stop()
	g := startRules(t, env, dir, testPolicy(policy.ResponseEnforce, false), signer)
	g.clock.advance(time.Hour)
	for i := range 3 {
		g.dns(scanner, fmt.Sprintf("y.new%d.example", i))
	}
	if n := strings.Count(eventsText(t, dir), `"new_destinations"`); n != 1 {
		t.Errorf("起動し直した後に覚えた宛先を新しい宛先とした（検知結果 %d 件）", n)
	}

	// ルールを off にした種類は検知しない。
	off := strings.Replace(rulesSet(2, behaviorRules), `"mode": "enforce", "score": 100`, `"mode": "off", "score": 100`, 1)
	admin = g.peer(pki.RoleAdmin, "admin")
	if status, body := admin.do(http.MethodPost, api.PathRules, api.RulesPush{Envelope: signRules(t, signer, sign.PurposeRules, off)}); status != http.StatusOK {
		t.Fatalf("配布の応答 = %d %s", status, body)
	}
	other := net.HardwareAddr{2, 0, 0, 0, 0, 0x77}
	g.ctrl.ObserveNeighbor(other, netip.MustParseAddr("127.0.0.77"))
	for i := range 10 {
		g.ctrl.ObserveARPRequest(other, netip.AddrFrom4([4]byte{127, 0, 3, byte(i)}))
	}
	if n := strings.Count(eventsText(t, dir), `"internal_scan"`); n != 1 {
		t.Errorf("止めた種類を検知した（検知結果 %d 件）", n)
	}
}
