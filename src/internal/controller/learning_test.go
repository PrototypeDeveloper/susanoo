package controller

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/config"
	"susanoo/internal/intel"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/policy"
)

func learnPolicy(version int, period time.Duration, def policy.EgressDefault) *policy.Policy {
	p := testPolicy(policy.ResponseEnforce, false)
	p.Version = version
	p.Groups[0].Egress = policy.Egress{Default: def}
	if def == policy.EgressLearn {
		p.Groups[0].Egress.LearnPeriod = config.Duration(period)
	}
	return p
}

func (f *fixture) status(admin *peer) api.Status {
	f.t.Helper()
	status, body := admin.do(http.MethodGet, api.PathStatus, nil)
	var st api.Status
	if status != http.StatusOK || json.Unmarshal(body, &st) != nil {
		f.t.Fatalf("全体の状態 = %d %s", status, body)
	}
	return st
}

// 学習モードのグループの期間を数え、期間が終わったら 1 回だけ知らせる。期間はポリシーで変えられ、学習モードでなくなれば数えるのをやめる（G2）。
func TestLearningPeriod(t *testing.T) {
	h, n := newHookNotifier(t)
	f := startNotify(t, pkitest.New(t), t.TempDir(), learnPolicy(1, 0, policy.EgressLearn), nil, nil, n)
	admin := f.peer(pki.RoleAdmin, "admin")
	start := f.clock.now()
	st := f.status(admin)
	if len(st.Learning) != 1 || st.Learning[0].Group != policy.DefaultGroup || !st.Learning[0].Ends.Equal(start.Add(policy.DefaultLearnPeriod)) || st.Learning[0].Due {
		t.Fatalf("学習モード = %+v", st.Learning)
	}
	// 期間を 1 時間にした版に切り替えると、数え始めた時刻はそのままで、終わりが早まる。
	apply := func(p *policy.Policy) {
		data, _ := json.Marshal(p)
		f.ctrl.mu.Lock()
		defer f.ctrl.mu.Unlock()
		if err := f.ctrl.applyPolicyStateLocked(PolicyState{Current: data}); err != nil {
			t.Fatal(err)
		}
	}
	apply(learnPolicy(2, time.Hour, policy.EgressLearn))
	f.clock.advance(2 * time.Hour)
	st = f.status(admin)
	if !st.Learning[0].Due || !st.Learning[0].Started.Equal(start) {
		t.Errorf("期間が終わった後 = %+v", st.Learning)
	}
	f.ctrl.checkLearning()
	f.ctrl.checkLearning()
	b := h.wait(t, "learning")
	if b["target"] != policy.DefaultGroup || !strings.Contains(b["title"].(string), "学習モードの期間が終わりました") {
		t.Errorf("知らせ = %v", b)
	}
	time.Sleep(50 * time.Millisecond)
	h.mu.Lock()
	if n := len(h.bodies); n != 1 {
		t.Errorf("知らせ = %d 件", n)
	}
	h.mu.Unlock()
	// 原則拒否に移ると、数えるのをやめる。再起動しても数え直さない。
	apply(learnPolicy(3, 0, policy.EgressDeny))
	if st := f.status(admin); len(st.Learning) != 0 {
		t.Errorf("原則拒否に移った後 = %+v", st.Learning)
	}
}

// 学習した名前から許可リストの案を作る。回数の少ない名前、名前の形でないもの、脅威情報の名前は入れず、
// 同じ登録できる単位の下の多くの名前は「*.」にまとめる。
func TestSuggestAllow(t *testing.T) {
	f := start(t, pkitest.New(t), t.TempDir(), learnPolicy(1, 0, policy.EgressLearn))
	admin := f.peer(pki.RoleAdmin, "admin")
	record := func(group, name string, n int, blocked bool) {
		for range n {
			f.ctrl.RecordLearned(group, name, blocked)
		}
	}
	record("default", "a.example.jp", 3, false)
	record("default", "b.example.jp", 2, false)
	record("default", "c.example.jp", 2, false)
	record("default", "example.jp", 5, false)
	record("default", "once.test", 1, false)
	record("default", "bad_name.test", 5, false)
	record("default", "evil.test", 5, false)
	record("default", "x.blocked.test", 9, true)
	record("default"+policy.CanarySuffix, "x.other.test", 2, false)
	record("strict", "elsewhere.test", 9, false)
	f.ctrl.intelM.Store(intel.NewMatcher(&intel.Set{Version: 1, Lists: []intel.List{{Name: "lab-list", Action: intel.ActionAlert, Domains: []string{"evil.test"}}}}))

	status, body := admin.do(http.MethodGet, api.PathLearnedSuggest+"?group=default", nil)
	var s api.AllowSuggestion
	if status != http.StatusOK || json.Unmarshal(body, &s) != nil {
		t.Fatalf("案 = %d %s", status, body)
	}
	got := map[string]api.SuggestedDestination{}
	for _, a := range s.Allow {
		got[a.Domain] = a
	}
	if w := got["*.example.jp"]; w.Names != 4 || w.Count != 12 || len(w.Examples) != 3 {
		t.Errorf("*.example.jp = %+v", w)
	}
	if got["example.jp"].Count != 5 || got["x.other.test"].Count != 2 {
		t.Errorf("案 = %+v", s.Allow)
	}
	for _, name := range []string{"a.example.jp", "once.test", "bad_name.test", "evil.test", "x.blocked.test", "elsewhere.test"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s を案に入れた", name)
		}
	}
	reasons := map[string]string{}
	for _, x := range s.Excluded {
		reasons[x.Domain] = x.Reason
	}
	if !strings.Contains(reasons["evil.test"], "lab-list") || !strings.Contains(reasons["bad_name.test"], "形") {
		t.Errorf("入れなかった名前 = %+v", s.Excluded)
	}
	if s.Allow[0].Domain != "*.example.jp" || s.MinCount != defaultSuggestMin || s.Started.IsZero() {
		t.Errorf("並びか項目 = %+v", s)
	}
	// 回数の下限を 1 にすると、1 回だけの名前も入る。ないグループは断る。
	_, body = admin.do(http.MethodGet, api.PathLearnedSuggest+"?group=default&min=1", nil)
	json.Unmarshal(body, &s)
	if !slices.ContainsFunc(s.Allow, func(a api.SuggestedDestination) bool { return a.Domain == "once.test" }) {
		t.Errorf("min=1 の案 = %+v", s.Allow)
	}
	if status, _ := admin.do(http.MethodGet, api.PathLearnedSuggest+"?group=nothing", nil); status != http.StatusNotFound {
		t.Errorf("ないグループの応答 = %d", status)
	}
	if status, _ := admin.do(http.MethodGet, api.PathLearnedSuggest+"?group=default&min=0", nil); status != http.StatusBadRequest {
		t.Errorf("min=0 の応答 = %d", status)
	}
}
