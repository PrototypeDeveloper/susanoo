package controller

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/intel"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/policy"
	"susanoo/internal/sign"
)

// fakeIntel は執行部の代わりに、脅威情報の配布を受け付ける。
type fakeIntel struct {
	mu      sync.Mutex
	applied []sign.Envelope
	fail    error
}

func (f *fakeIntel) ApplyIntel(_ context.Context, env sign.Envelope) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.applied = append(f.applied, env)
	return nil
}

func startIntel(t *testing.T, signer *sign.Signer, mgr IntelManager, initial *intel.Set) *fixture {
	t.Helper()
	env := pkitest.New(t)
	f := &fixture{t: t, env: env, dir: t.TempDir(), enf: &fakeEnforcer{}, lan: &fakeLAN{}, clock: &clock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}}
	ctrl, err := New(Config{
		Dir: f.dir, CA: env.CA.Pool(), Cert: env.Leaf(t, pki.RoleController, "main"), Signer: env.Signer,
		Policy: testPolicy(policy.ResponseEnforce, false), Enforcer: f.enf, LAN: f.lan, RulesKey: signer.PublicKey(),
		Intel: mgr, IntelSet: initial, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: f.clock.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.ctrl = ctrl
	f.serve()
	return f
}

func intelSet(version int) *intel.Set {
	return &intel.Set{Version: version, IssuedAt: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC), Lists: []intel.List{
		{Name: "phishing", Action: intel.ActionBlock, Domains: []string{"phish.test"}, CIDRs: []string{"203.0.113.66/32"}},
		{Name: "watch", Action: intel.ActionAlert, Domains: []string{"watch.test"}, CIDRs: []string{"198.51.100.0/24"}},
	}}
}

func signIntel(t *testing.T, s *sign.Signer, p sign.Purpose, set *intel.Set) sign.Envelope {
	t.Helper()
	data, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return s.Sign(p, data)
}

// 署名を確かめてから執行部に反映させ、DNS の問い合わせと通信の宛先を照合して検知結果にする。
func TestIntelPushAndMatch(t *testing.T) {
	signer := newPolicySigner(t)
	mgr := &fakeIntel{}
	f := startIntel(t, signer, mgr, nil)
	admin := f.peer(pki.RoleAdmin, "admin")
	pc := netip.MustParseAddr("127.0.0.5")
	f.ctrl.ObserveLease(macPC.String(), pc, "pc", f.clock.now().Add(time.Hour), false)

	if status, _ := admin.do(http.MethodGet, api.PathIntel+"/payload", nil); status != http.StatusNotFound {
		t.Errorf("配布前の中身の応答 = %d", status)
	}
	status, body := admin.do(http.MethodPost, api.PathIntel, api.IntelPush{Envelope: signIntel(t, signer, sign.PurposeIntel, intelSet(1))})
	if status != http.StatusOK || len(mgr.applied) != 1 {
		t.Fatalf("配布の応答 = %d %s（執行部への反映 %d 回）", status, body, len(mgr.applied))
	}
	var info api.IntelInfo
	json.Unmarshal(body, &info)
	if info.Version != 1 || len(info.Lists) != 2 || info.Lists[0].Domains != 1 || info.Lists[0].CIDRs != 1 {
		t.Errorf("脅威情報の状態 = %+v", info)
	}

	// 遮断の一覧の名前の問い合わせ（GW の DNS が遮断した）、検知だけの一覧の名前、一覧のアドレスへの応答。
	f.ctrl.RecordDNS(DNSRecord{Time: f.clock.now(), Client: pc, Name: "login.phish.test", Type: 1, Rcode: 3, Action: "block", Reason: "脅威情報（phishing）"})
	f.ctrl.RecordDNS(DNSRecord{Time: f.clock.now(), Client: pc, Name: "a.watch.test", Type: 1, Action: "forward"})
	f.ctrl.RecordDNS(DNSRecord{Time: f.clock.now(), Client: pc, Name: "cdn.example", Type: 1, Action: "forward", Answers: []string{"198.51.100.7"}})
	// 一覧のアドレスへの接続（GW が落とした）と、一覧の名前の SNI。
	src := netip.AddrPortFrom(pc, 40000)
	f.ctrl.RecordFlow(FlowRecord{Blocked: true, Time: f.clock.now(), Proto: 6, Src: src, Dst: netip.MustParseAddrPort("203.0.113.66:443")})
	f.ctrl.RecordFlow(FlowRecord{Open: true, Time: f.clock.now(), Proto: 6, Src: src, Dst: netip.MustParseAddrPort("192.0.2.10:443"), SNI: "x.watch.test"})
	// 同じ機器と項目は 10 分に 1 回にまとめる。
	f.ctrl.RecordDNS(DNSRecord{Time: f.clock.now(), Client: pc, Name: "login.phish.test", Type: 1, Rcode: 3, Action: "block"})

	ev := eventsText(t, f.dir)
	if n := strings.Count(ev, `"threat_intel"`); n != 4 {
		t.Errorf("脅威情報の検知結果 = %d 件\n%s", n, ev)
	}
	for _, want := range []string{
		`"list":"phishing"`, `"indicator":"phish.test"`, `"blocked":true`, `"indicator":"198.51.100.0/24"`,
		"GW で遮断しました", `"type_uid":400105`, "x.watch.test",
	} {
		if !strings.Contains(ev, want) {
			t.Errorf("%s が記録されていない", want)
		}
	}
	if r := ruleStatus(f.rulesInfo(admin), "threat-intel"); r.Monitored != 4 || r.Hits != 0 {
		t.Errorf("既定のルール（試験運用）の回数 = %+v", r)
	}
	f.clock.advance(11 * time.Minute)
	f.ctrl.RecordDNS(DNSRecord{Time: f.clock.now(), Client: pc, Name: "login.phish.test", Type: 1, Rcode: 3, Action: "block"})
	if n := strings.Count(eventsText(t, f.dir), `"threat_intel"`); n != 5 {
		t.Errorf("10 分後の検知結果 = %d 件", n)
	}

	// 照合と中身と全体の状態。
	var ms []api.IntelMatch
	_, body = admin.do(http.MethodGet, api.PathIntel+"/check?q=a.phish.test", nil)
	json.Unmarshal(body, &ms)
	if len(ms) != 1 || ms[0].List != "phishing" || ms[0].Action != "block" {
		t.Errorf("照合 = %s", body)
	}
	_, body = admin.do(http.MethodGet, api.PathIntel+"/check?q=203.0.113.66", nil)
	if !strings.Contains(string(body), `"203.0.113.66/32"`) {
		t.Errorf("アドレスの照合 = %s", body)
	}
	if status, _ := admin.do(http.MethodGet, api.PathIntel+"/check?q=bad%20name", nil); status != http.StatusBadRequest {
		t.Errorf("不正な照合の応答 = %d", status)
	}
	if status, body := admin.do(http.MethodGet, api.PathIntel+"/payload", nil); status != http.StatusOK || !strings.Contains(string(body), `"watch.test"`) {
		t.Errorf("中身 = %d %s", status, body)
	}
	var st api.Status
	_, body = admin.do(http.MethodGet, api.PathStatus, nil)
	json.Unmarshal(body, &st)
	if st.Intel.Version != 1 || len(st.Intel.Lists) != 2 {
		t.Errorf("全体の状態の脅威情報 = %+v", st.Intel)
	}
	if !slices.Contains(auditActions(t, f.dir), "intel.apply:1") {
		t.Errorf("監査ログ = %v", auditActions(t, f.dir))
	}
}

// 署名、用途、版数が正しくない脅威情報と、執行部が断った脅威情報は使わない。
func TestIntelPushRejects(t *testing.T) {
	signer := newPolicySigner(t)
	mgr := &fakeIntel{}
	f := startIntel(t, signer, mgr, intelSet(5))
	admin := f.peer(pki.RoleAdmin, "admin")
	for name, env := range map[string]sign.Envelope{
		"古い版":      signIntel(t, signer, sign.PurposeIntel, intelSet(5)),
		"検知ルールの用途": signIntel(t, signer, sign.PurposeRules, intelSet(6)),
		"ほかの鍵":     signIntel(t, newPolicySigner(t), sign.PurposeIntel, intelSet(6)),
		"不正な内容":    signer.Sign(sign.PurposeIntel, []byte(`{"version": 6}`)),
	} {
		if status, _ := admin.do(http.MethodPost, api.PathIntel, api.IntelPush{Envelope: env}); status != http.StatusBadRequest {
			t.Errorf("%s の応答 = %d", name, status)
		}
	}
	mgr.fail = errors.New("nft に入れられません")
	if status, body := admin.do(http.MethodPost, api.PathIntel, api.IntelPush{Envelope: signIntel(t, signer, sign.PurposeIntel, intelSet(6))}); status != http.StatusBadRequest || !strings.Contains(string(body), "nft") {
		t.Errorf("執行部が断った配布の応答 = %d %s", status, body)
	}
	if len(mgr.applied) != 0 {
		t.Errorf("断るべき配布を執行部に渡した: %d 回", len(mgr.applied))
	}
	var info api.IntelInfo
	_, body := admin.do(http.MethodGet, api.PathIntel, nil)
	json.Unmarshal(body, &info)
	if info.Version != 5 {
		t.Errorf("断った後の版 = %d", info.Version)
	}
	if status, _ := f.peer(pki.RoleClient, "pc-001").do(http.MethodPost, api.PathIntel, api.IntelPush{}); status != http.StatusForbidden {
		t.Errorf("端末の配布の応答 = %d", status)
	}
	// 執行部がない CONTROLLER は配布を受け付けない。
	g := start(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	if status, _ := g.peer(pki.RoleAdmin, "admin").do(http.MethodPost, api.PathIntel, api.IntelPush{Envelope: signIntel(t, signer, sign.PurposeIntel, intelSet(1))}); status != http.StatusServiceUnavailable {
		t.Errorf("執行部がない CONTROLLER の応答 = %d", status)
	}
}
