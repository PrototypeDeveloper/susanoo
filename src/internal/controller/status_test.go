package controller

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/policy"
)

// 全体の状態に、端末の台数、ポリシー、証明書の期限が近い端末、最近の検知が載る。
func TestStatus(t *testing.T) {
	env := pkitest.New(t)
	f := start(t, env, t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	f.clock.set(time.Now())
	pc1 := f.peer(pki.RoleClient, "pc-001")
	pc1.heartbeat()
	if status, _ := pc1.touchHoneytoken(); status != http.StatusOK {
		t.Fatalf("おとりの検知の応答 = %d", status)
	}
	short := f.peerWith(shortCert(t, env, "pc-002", time.Hour), "pc-002")
	short.heartbeat()

	admin := f.peer(pki.RoleAdmin, "admin")
	status, body := admin.do(http.MethodGet, api.PathStatus, nil)
	if status != http.StatusOK {
		t.Fatalf("状態の応答 = %d %s", status, body)
	}
	var st api.Status
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	if st.Devices.Total != 2 || st.Devices.Online != 2 || st.Devices.Isolated != 1 || st.Policy.Version != 1 || st.Response != policy.ResponseEnforce {
		t.Errorf("状態 = %+v", st)
	}
	if st.CertExpiry.IsZero() || st.Version == "" || st.StartedAt.IsZero() {
		t.Errorf("CONTROLLER の情報 = %v %q %v", st.CertExpiry, st.Version, st.StartedAt)
	}
	if len(st.ExpiringCerts) != 1 || st.ExpiringCerts[0].ID != "pc-002" {
		t.Errorf("証明書の期限が近い端末 = %+v", st.ExpiringCerts)
	}
	if len(st.RecentFindings) == 0 || !st.RecentFindings[len(st.RecentFindings)-1].FindingInfo.HasType(event.FindingTypeHoneytoken) {
		t.Errorf("最近の検知 = %+v", st.RecentFindings)
	}
	// 端末は状態を見られない。
	if status, _ := pc1.do(http.MethodGet, api.PathStatus, nil); status != http.StatusForbidden {
		t.Errorf("端末の状態の要求 = %d", status)
	}
}

// イベントは、端末、種類、重大度、期間、文字列で検索できる。
func TestSearchEvents(t *testing.T) {
	env := pkitest.New(t)
	f := start(t, env, t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	pc1 := f.peer(pki.RoleClient, "pc-001")
	pc1.heartbeat()
	pc1.touchHoneytoken()
	pc2 := f.peer(pki.RoleClient, "pc-002")
	pc2.heartbeat()
	admin := f.peer(pki.RoleAdmin, "admin")

	search := func(q api.EventQuery) (int, []event.Event) {
		t.Helper()
		status, body := admin.do(http.MethodGet, api.PathEvents+"?"+q.Values().Encode(), nil)
		var events []event.Event
		json.Unmarshal(body, &events)
		return status, events
	}
	status, events := search(api.EventQuery{Device: "pc-001", Class: "finding"})
	if status != http.StatusOK || len(events) == 0 {
		t.Fatalf("pc-001 の検知 = %d %d 件", status, len(events))
	}
	for _, e := range events {
		if e.ClassUID != event.ClassDetectionFinding || e.Device.UID != "pc-001" {
			t.Errorf("条件に合わないイベント = %+v", e)
		}
	}
	for name, q := range map[string]api.EventQuery{
		"ほかの端末":   {Device: "pc-002", Class: "finding"},
		"重大度が上":   {Class: "finding", Severity: "critical"},
		"これから先":   {Class: "finding", Since: time.Now().Add(time.Hour)},
		"含まない文字列": {Class: "finding", Text: "存在しない文字列"},
	} {
		if status, events := search(q); status != http.StatusOK || len(events) != 0 {
			t.Errorf("%s の検索 = %d %d 件", name, status, len(events))
		}
	}
	if _, events := search(api.EventQuery{Class: "2004", Severity: "high", Text: "おとり"}); len(events) == 0 {
		t.Error("番号と重大度と文字列で検索できない")
	}
	for name, v := range map[string]url.Values{
		"知らない種類":   {"class": {"login"}},
		"知らない重大度":  {"severity": {"urgent"}},
		"上限を超える件数": {"limit": {"5000"}},
		"不正な時刻":    {"since": {"yesterday"}},
	} {
		if status, _ := admin.do(http.MethodGet, api.PathEvents+"?"+v.Encode(), nil); status != http.StatusBadRequest {
			t.Errorf("%s の応答 = %d", name, status)
		}
	}
}
