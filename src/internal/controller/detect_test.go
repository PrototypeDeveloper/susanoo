package controller

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/policy"
	"susanoo/internal/rules"
	"susanoo/internal/sign"
)

// startRules は、検知ルールの配布を受け付ける（rulesKey の署名を確かめる）CONTROLLER を、GW の LAN とともに起動する。
func startRules(t *testing.T, env *pkitest.Env, dir string, pol *policy.Policy, signer *sign.Signer) *fixture {
	t.Helper()
	f := &fixture{t: t, env: env, dir: dir, enf: &fakeEnforcer{}, lan: &fakeLAN{}, clock: &clock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}}
	ctrl, err := New(Config{
		Dir: dir, CA: env.CA.Pool(), Cert: env.Leaf(t, pki.RoleController, "main"), Signer: env.Signer, Policy: pol,
		Enforcer: f.enf, LAN: f.lan, RulesKey: signer.PublicKey(), HeartbeatTimeout: 30 * time.Second,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: f.clock.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.ctrl = ctrl
	f.serve()
	return f
}

const testRules = `{
  "version": %d, "name": "試験のルール", "issued_at": "2026-10-18T00:00:00Z",
  "rules": [
    {"id": "dns-bad", "name": "悪い名前の問い合わせ", "class": "dns", "mode": "enforce", "score": 60,
     "match": {"field": "query.hostname", "op": "suffix", "value": ".bad.test"}},
    {"id": "dns-watch", "name": "見張る名前", "class": "dns", "mode": "monitor", "score": 100,
     "match": {"field": "query.hostname", "op": "eq", "value": "watch.test"}}
  ],
  "exceptions": [{"rules": ["dns-bad"], "devices": ["` + "02:00:00:00:00:02" + `"], "reason": "検証用の機器"}]
}`

func signRules(t *testing.T, s *sign.Signer, p sign.Purpose, data string) sign.Envelope {
	t.Helper()
	return s.Sign(p, []byte(data))
}

// rulesSet は検知ルールの版数を version にする。
func rulesSet(version int, body string) string {
	return strings.Replace(body, "%d", strconv.Itoa(version), 1)
}

func (f *fixture) rulesInfo(admin *peer) api.RulesInfo {
	f.t.Helper()
	status, body := admin.do(http.MethodGet, api.PathRules, nil)
	if status != http.StatusOK {
		f.t.Fatalf("検知ルールの状態 = %d %s", status, body)
	}
	var info api.RulesInfo
	if err := json.Unmarshal(body, &info); err != nil {
		f.t.Fatal(err)
	}
	return info
}

func ruleStatus(info api.RulesInfo, id string) api.RuleStatus {
	for _, r := range info.Rules {
		if r.ID == id {
			return r
		}
	}
	return api.RuleStatus{}
}

func (f *fixture) dns(client netip.Addr, name string) {
	f.ctrl.RecordDNS(DNSRecord{Time: f.clock.now(), Client: client, Name: name, Type: 1, Action: "forward"})
}

// 配布した条件のルールに当てはまると検知結果を作り、点を危険度に加える。しきい値を超えたら隔離し、解除で 0 に戻す。
// 例外に当てはまる機器と、試験運用のルールでは、危険度に加えない。
func TestRulesScoreAndIsolate(t *testing.T) {
	env := pkitest.New(t)
	signer := newPolicySigner(t)
	f := startRules(t, env, t.TempDir(), testPolicy(policy.ResponseEnforce, false), signer)
	admin := f.peer(pki.RoleAdmin, "admin")
	pc := f.peer(pki.RoleClient, "pc-001")
	f.ctrl.ObserveLease(macPC.String(), loopback, "pc-001", f.clock.now().Add(time.Hour), false)
	pc.heartbeat()
	other := netip.MustParseAddr("127.0.0.2")
	f.ctrl.ObserveLease(macPC2.String(), other, "lab-box", f.clock.now().Add(time.Hour), false)

	if info := f.rulesInfo(admin); info.Current.Version != 0 || len(info.Rules) != len(rules.Defaults) || !info.Rules[0].Default {
		t.Fatalf("配布前の状態 = %+v", info)
	}
	status, body := admin.do(http.MethodPost, api.PathRules, api.RulesPush{Envelope: signRules(t, signer, sign.PurposeRules, rulesSet(1, testRules))})
	if status != http.StatusOK {
		t.Fatalf("配布の応答 = %d %s", status, body)
	}

	// 1 回目は 60 点で、しきい値（100）に届かない。
	f.dns(loopback, "a.bad.test")
	if d := f.devices(admin)["pc-001"]; d.Risk != 60 || d.Isolation != "" {
		t.Fatalf("1 回目の後の端末 = %+v", d)
	}
	ev := eventsText(t, f.dir)
	if !strings.Contains(ev, `"rule_match"`) || !strings.Contains(ev, `"analytic":{"uid":"dns-bad","name":"悪い名前の問い合わせ","type_id":1}`) {
		t.Errorf("条件のルールの検知結果がない: %s", ev)
	}
	// 半減期（24 時間）が過ぎると半分になる。
	f.clock.advance(24 * time.Hour)
	if d := f.devices(admin)["pc-001"]; d.Risk != 30 {
		t.Errorf("半減期の後の危険度 = %d", d.Risk)
	}
	// 2 回目で 90、3 回目で 150 になり、隔離する。理由には危険度とルールを書く。
	// 間の数秒で少し減った値（149.99...）は丸める。
	f.dns(loopback, "b.bad.test")
	f.clock.advance(5 * time.Second)
	f.dns(loopback, "c.bad.test")
	d := f.devices(admin)["pc-001"]
	if d.Isolation != policy.IsolateManagementAndUpdates || !strings.HasPrefix(d.Reason, "危険度 150") || !strings.Contains(d.Reason, "悪い名前の問い合わせ") {
		t.Fatalf("隔離 = %+v", d)
	}
	var st api.Status
	_, body = admin.do(http.MethodGet, api.PathStatus, nil)
	json.Unmarshal(body, &st)
	if len(st.Risky) != 1 || st.Risky[0].Target != "pc-001" || st.Risky[0].Score != 150 || st.Risky[0].Threshold != 100 || st.Rules.Version != 1 {
		t.Errorf("全体の状態の危険度 = %+v %+v", st.Risky, st.Rules)
	}
	admin.do(http.MethodPost, api.PathDevices+"/pc-001/release", nil)
	if d := f.devices(admin)["pc-001"]; d.Risk != 0 || d.Isolation != "" {
		t.Errorf("解除の後の端末 = %+v", d)
	}

	// 例外の機器（CLIENT のない機器）は危険度に加えず、検知結果も作らない。
	before := strings.Count(eventsText(t, f.dir), `"rule_match"`)
	for range 3 {
		f.dns(other, "x.bad.test")
	}
	if h := f.hosts(admin)[macPC2.String()]; h.Risk != 0 || h.Isolation != "" {
		t.Errorf("例外の機器 = %+v", h)
	}
	if n := strings.Count(eventsText(t, f.dir), `"rule_match"`); n != before {
		t.Errorf("例外の検知結果を作った（%d → %d）", before, n)
	}
	// 試験運用のルールは、検知結果を作るが危険度に加えない。
	f.dns(loopback, "watch.test")
	if d := f.devices(admin)["pc-001"]; d.Risk != 0 || d.Isolation != "" {
		t.Errorf("試験運用のルールで危険度が上がった: %+v", d)
	}
	if !strings.Contains(eventsText(t, f.dir), "見張る名前（試験運用）") {
		t.Error("試験運用の検知結果がない")
	}
	info := f.rulesInfo(admin)
	if r := ruleStatus(info, "dns-bad"); r.Hits != 3 || r.Excepted != 3 || r.Last.IsZero() {
		t.Errorf("dns-bad の回数 = %+v", r)
	}
	if r := ruleStatus(info, "dns-watch"); r.Monitored != 1 || r.Hits != 0 {
		t.Errorf("dns-watch の回数 = %+v", r)
	}
	if info.Current.Version != 1 || info.Exceptions != 1 || len(info.Versions) != 1 {
		t.Errorf("版 = %+v", info)
	}
	if !slices.Contains(auditActions(t, f.dir), "rules.apply:1") {
		t.Errorf("監査ログ = %v", auditActions(t, f.dir))
	}
}

// 既定のルールを配布したルールで置き換えられる（おとりへの接触を試験運用にすると隔離しない）。
// グループのしきい値を下げると、1 回の検知の点が既定より小さくても隔離する。
func TestRulesOverrideDefaultsAndGroupThreshold(t *testing.T) {
	env := pkitest.New(t)
	signer := newPolicySigner(t)
	pol := testPolicy(policy.ResponseEnforce, false)
	pol.Groups[0].RiskThreshold = 50
	f := startRules(t, env, t.TempDir(), pol, signer)
	admin := f.peer(pki.RoleAdmin, "admin")
	pc := f.peer(pki.RoleClient, "pc-001")
	pc.heartbeat()

	set := `{"version": 1, "name": "x", "issued_at": "2026-10-18T00:00:00Z", "rules": [
	  {"id": "honeytoken", "name": "おとり（試験運用）", "finding": "honeytoken", "mode": "monitor", "score": 100},
	  {"id": "dns-bad", "name": "悪い名前の問い合わせ", "class": "dns", "mode": "enforce", "score": 60,
	   "match": {"field": "query.hostname", "op": "suffix", "value": ".bad.test"}}]}`
	if status, body := admin.do(http.MethodPost, api.PathRules, api.RulesPush{Envelope: signRules(t, signer, sign.PurposeRules, set)}); status != http.StatusOK {
		t.Fatalf("配布の応答 = %d %s", status, body)
	}
	pc.touchHoneytoken()
	if d := f.devices(admin)["pc-001"]; d.Isolation != "" || d.Risk != 0 {
		t.Errorf("試験運用にしたおとりで隔離した: %+v", d)
	}
	f.dns(loopback, "a.bad.test")
	if d := f.devices(admin)["pc-001"]; d.Isolation == "" || d.Reason != "悪い名前の問い合わせ" {
		t.Errorf("しきい値 50 で 60 点の検知 = %+v", d)
	}
	info := f.rulesInfo(admin)
	if r := ruleStatus(info, "honeytoken"); r.Default || r.Monitored != 1 {
		t.Errorf("置き換えた既定のルール = %+v", r)
	}
	if r := ruleStatus(info, "mass-change"); !r.Default {
		t.Errorf("残した既定のルール = %+v", r)
	}
}

// 署名、用途、版数が正しくない検知ルールは受け付けない。管理者以外は配布できない。
func TestRulesPushRejects(t *testing.T) {
	env := pkitest.New(t)
	signer := newPolicySigner(t)
	f := startRules(t, env, t.TempDir(), testPolicy(policy.ResponseEnforce, false), signer)
	admin := f.peer(pki.RoleAdmin, "admin")
	if status, body := admin.do(http.MethodPost, api.PathRules, api.RulesPush{Envelope: signRules(t, signer, sign.PurposeRules, rulesSet(2, testRules))}); status != http.StatusOK {
		t.Fatalf("配布の応答 = %d %s", status, body)
	}
	for name, env := range map[string]sign.Envelope{
		"古い版":              signRules(t, signer, sign.PurposeRules, rulesSet(1, testRules)),
		"ポリシーの用途":          signRules(t, signer, sign.PurposePolicy, rulesSet(3, testRules)),
		"ほかの鍵":             signRules(t, newPolicySigner(t), sign.PurposeRules, rulesSet(3, testRules)),
		"CONTROLLER の指示の鍵": signRules(t, f.env.Signer, sign.PurposeRules, rulesSet(3, testRules)),
		"不正な内容":            signRules(t, signer, sign.PurposeRules, `{"version": 3}`),
	} {
		if status, _ := admin.do(http.MethodPost, api.PathRules, api.RulesPush{Envelope: env}); status != http.StatusBadRequest {
			t.Errorf("%s の応答 = %d", name, status)
		}
	}
	pc := f.peer(pki.RoleClient, "pc-001")
	if status, _ := pc.do(http.MethodPost, api.PathRules, api.RulesPush{Envelope: signRules(t, signer, sign.PurposeRules, rulesSet(3, testRules))}); status != http.StatusForbidden {
		t.Errorf("端末の配布の応答 = %d", status)
	}
	status, body := admin.do(http.MethodGet, api.PathRules+"/versions/2", nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"dns-bad"`) {
		t.Errorf("版 2 の中身 = %d %s", status, body)
	}
	if status, _ := admin.do(http.MethodGet, api.PathRules+"/versions/1", nil); status != http.StatusNotFound {
		t.Errorf("ない版の応答 = %d", status)
	}

	// 公開鍵がない CONTROLLER は配布を受け付けない（既定のルールだけで動く）。
	g := start(t, env, t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	if status, _ := g.peer(pki.RoleAdmin, "admin").do(http.MethodPost, api.PathRules, api.RulesPush{Envelope: signRules(t, signer, sign.PurposeRules, rulesSet(1, testRules))}); status != http.StatusServiceUnavailable {
		t.Errorf("公開鍵がない CONTROLLER の応答 = %d", status)
	}
}

// 検知ルールの版、危険度、当てはまった回数は、CONTROLLER を起動し直しても続く。定義を変えたルールは数え直す。
func TestRulesPersist(t *testing.T) {
	env := pkitest.New(t)
	signer := newPolicySigner(t)
	dir := t.TempDir()
	f := startRules(t, env, dir, testPolicy(policy.ResponseEnforce, false), signer)
	admin := f.peer(pki.RoleAdmin, "admin")
	f.peer(pki.RoleClient, "pc-001").heartbeat()
	admin.do(http.MethodPost, api.PathRules, api.RulesPush{Envelope: signRules(t, signer, sign.PurposeRules, rulesSet(1, testRules))})
	f.dns(loopback, "a.bad.test")
	f.dns(loopback, "watch.test")
	f.stop()

	g := startRules(t, env, dir, testPolicy(policy.ResponseEnforce, false), signer)
	admin = g.peer(pki.RoleAdmin, "admin")
	info := g.rulesInfo(admin)
	if info.Current.Version != 1 || ruleStatus(info, "dns-bad").Hits != 1 || ruleStatus(info, "dns-watch").Monitored != 1 {
		t.Fatalf("起動し直した後の検知ルール = %+v", info)
	}
	if d := g.devices(admin)["pc-001"]; d.Risk != 60 {
		t.Errorf("起動し直した後の危険度 = %d", d.Risk)
	}
	// dns-watch の点だけを変えた版を配布すると、dns-watch だけ数え直す。
	changed := strings.Replace(rulesSet(2, testRules), `"monitor", "score": 100`, `"monitor", "score": 90`, 1)
	if status, body := admin.do(http.MethodPost, api.PathRules, api.RulesPush{Envelope: signRules(t, signer, sign.PurposeRules, changed)}); status != http.StatusOK {
		t.Fatalf("配布の応答 = %d %s", status, body)
	}
	info = g.rulesInfo(admin)
	if ruleStatus(info, "dns-bad").Hits != 1 || ruleStatus(info, "dns-watch").Monitored != 0 || ruleStatus(info, "dns-watch").Score != 90 {
		t.Errorf("定義を変えた後の回数 = %+v", info.Rules)
	}
}

// CLIENT のイベントの機器の情報（MAC アドレスなど）は信用せず、証明書の端末だけを対象にする。
func TestRulesSubjectFromCertificate(t *testing.T) {
	env := pkitest.New(t)
	signer := newPolicySigner(t)
	f := startRules(t, env, t.TempDir(), testPolicy(policy.ResponseEnforce, false), signer)
	admin := f.peer(pki.RoleAdmin, "admin")
	f.ctrl.ObserveLease(macPC2.String(), netip.MustParseAddr("127.0.0.2"), "victim", f.clock.now().Add(time.Hour), false)
	pc := f.peer(pki.RoleClient, "pc-001")
	pc.heartbeat()

	e := event.New(event.ClassDetectionFinding, event.FindingCreate, event.SeverityHigh, time.Now())
	e.FindingInfo = &event.FindingInfo{UID: "x", Title: "おとり", Types: []string{event.FindingTypeHoneytoken}}
	e.Message = "x"
	e.Device = &event.Device{UID: "victim", MAC: macPC2.String(), IP: "127.0.0.2"}
	if status, _ := pc.do(http.MethodPost, api.PathEvents, api.EventBatch{Events: []event.Event{*e}}); status != http.StatusOK {
		t.Fatal(status)
	}
	if h := f.hosts(admin)[macPC2.String()]; h.Isolation != "" || h.Risk != 0 {
		t.Errorf("ほかの機器を隔離した: %+v", h)
	}
	if d := f.devices(admin)["pc-001"]; d.Isolation == "" || d.Reason != ReasonHoneytoken {
		t.Errorf("証明書の端末 = %+v", d)
	}
}

// 同じルールと対象の当てはまりのログは、1 分に 1 回にまとめる。
func TestHitLogLimit(t *testing.T) {
	c := &Controller{}
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	pc := target{key: "device:pc-001"}
	if n, ok := c.logHitLocked("monitor", "r", pc, now); !ok || n != 0 {
		t.Errorf("1 回目 = %d %v", n, ok)
	}
	for i := range 3 {
		if _, ok := c.logHitLocked("monitor", "r", pc, now.Add(time.Duration(i+1)*time.Second)); ok {
			t.Error("1 分の間に 2 回書いた")
		}
	}
	if _, ok := c.logHitLocked("monitor", "r", target{key: "device:pc-002"}, now); !ok {
		t.Error("ほかの対象をまとめた")
	}
	if n, ok := c.logHitLocked("monitor", "r", pc, now.Add(time.Minute)); !ok || n != 3 {
		t.Errorf("1 分後 = %d %v", n, ok)
	}
}
