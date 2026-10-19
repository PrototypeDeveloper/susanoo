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

func logonEvent(user string, status int, remote bool, host string) event.Event {
	e := event.New(event.ClassAuthentication, event.AuthLogon, event.SeverityLow, time.Now())
	e.User = &event.User{Name: user}
	e.StatusID = status
	e.IsRemote = &remote
	e.Service = &event.Service{Name: "sshd"}
	if host != "" {
		e.SrcEndpoint = &event.Endpoint{IP: host}
	}
	return *e
}

// 端末のログオンのイベントを保存して検索でき、既定のルール（ログオンの失敗の連続、root での遠隔ログオン）を試験運用で評価する。
func TestLogonRules(t *testing.T) {
	env := pkitest.New(t)
	f := start(t, env, t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	admin := f.peer(pki.RoleAdmin, "admin")
	pc := f.peer(pki.RoleClient, "pc-001")
	pc.heartbeat()
	send := func(evs ...event.Event) {
		t.Helper()
		if status, body := pc.do(http.MethodPost, api.PathEvents, api.EventBatch{Events: evs}); status != http.StatusOK {
			t.Fatalf("イベントの送信 = %d %s", status, body)
		}
	}
	var fails []event.Event
	for range 9 {
		fails = append(fails, logonEvent("admin", event.StatusFailure, true, "192.0.2.66"))
	}
	send(fails...)
	if s := ruleStatus(f.rulesInfo(admin), "logon-failures"); s.Monitored != 0 || s.Mode != "monitor" {
		t.Errorf("9 回の失敗 = %+v", s)
	}
	send(logonEvent("admin", event.StatusFailure, true, "192.0.2.66"))
	if s := ruleStatus(f.rulesInfo(admin), "logon-failures"); s.Monitored != 1 {
		t.Errorf("10 回の失敗 = %+v", s)
	}
	send(logonEvent("root", event.StatusSuccess, false, ""), logonEvent("alice", event.StatusSuccess, true, "192.0.2.1"))
	if s := ruleStatus(f.rulesInfo(admin), "remote-root-logon"); s.Monitored != 0 {
		t.Errorf("端末の前の root と、遠隔の一般の利用者 = %+v", s)
	}
	send(logonEvent("root", event.StatusSuccess, true, "192.0.2.9"))
	if s := ruleStatus(f.rulesInfo(admin), "remote-root-logon"); s.Monitored != 1 {
		t.Errorf("root での遠隔ログオン = %+v", s)
	}
	// 種類 logon で検索できる。試験運用なので危険度は上がらない。
	q := url.Values{"class": {"logon"}, "device": {"pc-001"}, "limit": {"100"}}
	status, body := admin.do(http.MethodGet, api.PathEvents+"?"+q.Encode(), nil)
	var found []json.RawMessage
	if status != http.StatusOK || json.Unmarshal(body, &found) != nil || len(found) != 13 {
		t.Errorf("ログオンの検索 = %d、%d 件", status, len(found))
	}
	if d := f.devices(admin)["pc-001"]; d.Isolation != "" {
		t.Errorf("試験運用のルールで隔離した: %+v", d)
	}
}
