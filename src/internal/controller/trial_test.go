package controller

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/policy"
	"susanoo/internal/sign"
)

// sendFinding は、端末が種類 typ の検知結果を送る。
func (d *peer) sendFinding(typ string, at time.Time) {
	d.f.t.Helper()
	e := event.New(event.ClassDetectionFinding, event.FindingCreate, event.SeverityMedium, at)
	e.Message = "試験の検知結果"
	e.FindingInfo = &event.FindingInfo{UID: "f-" + typ + at.Format("150405.000"), Title: typ, Types: []string{typ}}
	if status, body := d.do(http.MethodPost, api.PathEvents, api.EventBatch{Events: []event.Event{*e}}); status != http.StatusOK {
		d.f.t.Fatalf("イベントの応答 = %d %s", status, body)
	}
}

func (f *fixture) trial(admin *peer, q url.Values) api.TrialReport {
	f.t.Helper()
	status, body := admin.do(http.MethodGet, api.PathTrial+"?"+q.Encode(), nil)
	if status != http.StatusOK {
		f.t.Fatalf("試行の評価の応答 = %d %s", status, body)
	}
	var rep api.TrialReport
	if err := json.Unmarshal(body, &rep); err != nil {
		f.t.Fatal(err)
	}
	return rep
}

// 監視モードで隔離しなかった判断を記録し、保存したイベントを今のルールと例外で評価し直して、隔離していた回数を数える。
// 試験運用のルールもすべて加点にした場合も数え、端末ごとの回数を基準と比べる。
func TestTrialReport(t *testing.T) {
	env := pkitest.New(t)
	signer := newPolicySigner(t)
	f := startRules(t, env, t.TempDir(), testPolicy(policy.ResponseMonitor, false), signer)
	f.clock.set(time.Now())
	pc1, pc2 := f.peer(pki.RoleClient, "pc-001"), f.peer(pki.RoleClient, "pc-002")
	admin := f.peer(pki.RoleAdmin, "admin")
	pc1.heartbeat()
	pc2.heartbeat()
	// pc-001 はおとりに触る（既定のルールで 100 点。監視モードなので隔離しない）。2 回目は同じ判断なので記録しない。
	pc1.touchHoneytoken()
	pc1.touchHoneytoken()
	if d := f.devices(admin)["pc-001"]; d.Isolation != "" {
		t.Fatalf("監視モードで隔離しました: %+v", d)
	}
	text := eventsText(t, f.dir)
	if n := strings.Count(text, `"types":["would_isolate"]`); n != 1 {
		t.Fatalf("隔離しなかった判断の記録 = %d 件", n)
	}
	// pc-002 は試験運用（40 点）の永続化の検知結果を 3 回出す。今のルールでは隔離しないが、加点にしたら隔離していた。
	for i := range 3 {
		pc2.sendFinding(event.FindingTypePersistence, time.Now().Add(time.Duration(i)*time.Second))
	}
	f.clock.advance(time.Minute)

	rep := f.trial(admin, url.Values{})
	if rep.Suppressed != 1 || rep.Response != policy.ResponseMonitor || rep.Events < 5 {
		t.Errorf("評価 = 隔離しなかった判断 %d、対応 %s、イベント %d", rep.Suppressed, rep.Response, rep.Events)
	}
	if len(rep.Isolations) != 1 || rep.Isolations[0].Target != "pc-001" || !slices.Contains(rep.Isolations[0].Rules, "honeytoken") {
		t.Errorf("今のルールで隔離していたもの = %+v", rep.Isolations)
	}
	// 加点にしたら、pc-001 のおとり（2 回目は隔離していた後の 1 時間の中なので同じ件）と pc-002 の 3 回目。
	var ifTargets []string
	for _, iso := range rep.IfEnforced {
		ifTargets = append(ifTargets, iso.Target)
	}
	slices.Sort(ifTargets)
	if !slices.Equal(ifTargets, []string{"pc-001", "pc-002"}) {
		t.Errorf("加点にしたら隔離していたもの = %v", ifTargets)
	}
	var hp, ps api.TrialRule
	for _, r := range rep.ByRule {
		switch r.ID {
		case "honeytoken":
			hp = r
		case "persistence":
			ps = r
		}
	}
	if hp.Hits != 2 || hp.Targets != 1 || ps.Hits != 3 || ps.Mode != "monitor" || ps.Top[0].Target != "pc-002" {
		t.Errorf("ルールごと = %+v %+v", hp, ps)
	}
	// 基準：2 週間で 1 回までなら合格。0 回なら、今のルールでは pc-001、加点にしたら pc-001 と pc-002 が超える。
	if g := rep.Gate; !g.Pass || !g.IfEnforcedPass || g.Allowed != 1 || g.Weeks != 2 {
		t.Errorf("判定 = %+v", g)
	}
	if g := f.trial(admin, url.Values{"max_per_week": {"0"}}).Gate; g.Pass || !slices.Equal(g.Over, []string{"pc-001"}) || !slices.Equal(g.IfEnforcedOver, []string{"pc-001", "pc-002"}) {
		t.Errorf("基準 0 回の判定 = %+v", g)
	}
	// 隔離していた後の 1 時間を過ぎた検知は、別の件として数える。
	f.clock.advance(3 * time.Hour)
	pc1.sendFinding(event.FindingTypeHoneytoken, time.Now().Add(2*time.Hour))
	if rep := f.trial(admin, url.Values{}); len(rep.Isolations) != 2 || rep.Suppressed != 2 {
		t.Errorf("1 時間を過ぎた検知 = 隔離 %d 回、隔離しなかった判断 %d 回", len(rep.Isolations), rep.Suppressed)
	}
	// 期間の外のイベントは評価しない。
	if rep := f.trial(admin, url.Values{"since": {time.Now().Add(-48 * time.Hour).Format(time.RFC3339)}, "until": {time.Now().Add(-24 * time.Hour).Format(time.RFC3339)}}); rep.Events != 0 || len(rep.Isolations) != 0 {
		t.Errorf("期間の外 = イベント %d、隔離 %d", rep.Events, len(rep.Isolations))
	}

	// 誤検知の例外を配布すると、評価し直した結果に効く（新しい試行を待たずに確かめられる）。
	rulesBody := `{"version": 1, "name": "例外", "issued_at": "2026-10-18T00:00:00Z", "rules": [],
	  "exceptions": [{"rules": ["honeytoken"], "devices": ["pc-001"], "reason": "試験の操作"}]}`
	if status, body := admin.do(http.MethodPost, api.PathRules, api.RulesPush{Envelope: signRules(t, signer, sign.PurposeRules, rulesBody)}); status != http.StatusOK {
		t.Fatalf("検知ルールの配布 = %d %s", status, body)
	}
	rep = f.trial(admin, url.Values{})
	if len(rep.Isolations) != 0 || rep.Rules.Version != 1 {
		t.Errorf("例外を配布した後の隔離 = %+v（ルールの版 %d）", rep.Isolations, rep.Rules.Version)
	}
	for _, r := range rep.ByRule {
		if r.ID == "honeytoken" && (r.Excepted != 3 || r.Hits != 0) {
			t.Errorf("例外で除いた回数 = %+v", r)
		}
	}
	for name, q := range map[string]url.Values{
		"不正な時刻": {"since": {"yesterday"}},
		"逆の期間":  {"since": {time.Now().Format(time.RFC3339)}, "until": {time.Now().Add(-time.Hour).Format(time.RFC3339)}},
		"負の基準":  {"max_per_week": {"-1"}},
	} {
		if status, _ := admin.do(http.MethodGet, api.PathTrial+"?"+q.Encode(), nil); status != http.StatusBadRequest {
			t.Errorf("%s の応答 = %d", name, status)
		}
	}
	if status, _ := pc1.do(http.MethodGet, api.PathTrial, nil); status != http.StatusForbidden {
		t.Errorf("端末からの要求 = %d", status)
	}
}
