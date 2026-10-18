package controller

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/notify"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/policy"
)

// hookRecorder は偽の webhook の受け口（ループバック）に届いた通知を記録する。
type hookRecorder struct {
	mu     sync.Mutex
	bodies []map[string]any
}

func (h *hookRecorder) find(kind string) map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, b := range h.bodies {
		if b["kind"] == kind {
			return b
		}
	}
	return nil
}

func (h *hookRecorder) wait(t *testing.T, kind string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b := h.find(kind); b != nil {
			return b
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s の通知が届かない（届いた通知 %v）", kind, h.bodies)
	return nil
}

func newHookNotifier(t *testing.T) (*hookRecorder, *notify.Notifier) {
	t.Helper()
	h := &hookRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		h.mu.Lock()
		h.bodies = append(h.bodies, b)
		h.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	n, err := notify.New(notify.Config{Destinations: []notify.Destination{{Name: "hook", Type: "webhook", URL: srv.URL, MinSeverity: "medium"}}},
		notify.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return h, n
}

// 承認待ち、警告モードの検知、加点したが隔離に至らなかった検知結果を知らせる。試験運用のルールの当てはまりは知らせない。
func TestNotifications(t *testing.T) {
	env := pkitest.New(t)
	t.Run("承認待ち", func(t *testing.T) {
		h, n := newHookNotifier(t)
		f := startNotify(t, env, t.TempDir(), testPolicy(policy.ResponseEnforce, true), nil, nil, n)
		pc := f.peer(pki.RoleClient, "pc-001")
		pc.heartbeat()
		pc.touchHoneytoken()
		b := h.wait(t, "pending")
		if b["target"] != "pc-001" || !strings.Contains(b["title"].(string), "承認を待っています") {
			t.Errorf("通知 = %v", b)
		}
		if fields, _ := b["fields"].(map[string]any); !strings.Contains(fields["対処"].(string), "ctl isolate pc-001") {
			t.Errorf("対処 = %v", b["fields"])
		}
	})
	t.Run("警告モード", func(t *testing.T) {
		h, n := newHookNotifier(t)
		f := startNotify(t, env, t.TempDir(), testPolicy(policy.ResponseAlert, false), nil, nil, n)
		pc := f.peer(pki.RoleClient, "pc-001")
		pc.heartbeat()
		pc.touchHoneytoken()
		if b := h.wait(t, "alert"); b["target"] != "pc-001" || !strings.Contains(b["title"].(string), "警告モード") {
			t.Errorf("通知 = %v", b)
		}
		if h.find("isolate") != nil {
			t.Error("警告モードで隔離の通知を送った")
		}
	})
	t.Run("隔離に至らない検知結果", func(t *testing.T) {
		h, n := newHookNotifier(t)
		f := startNotify(t, env, t.TempDir(), testPolicy(policy.ResponseEnforce, false), nil, nil, n)
		pc := f.peer(pki.RoleClient, "pc-001")
		admin := f.peer(pki.RoleAdmin, "admin")
		pc.heartbeat()
		send := func(typ, title string, sev event.Severity) {
			e := event.New(event.ClassDetectionFinding, event.FindingCreate, sev, time.Now())
			e.Message = title + "の試験"
			e.FindingInfo = &event.FindingInfo{UID: "x-" + typ, Title: title, Types: []string{typ}}
			if status, body := pc.do(http.MethodPost, api.PathEvents, api.EventBatch{Events: []event.Event{*e}}); status != http.StatusOK {
				t.Fatalf("イベントの送信 = %d %s", status, body)
			}
		}
		send(event.FindingTypeCredentialAccess, "認証情報へのアクセス", event.SeverityMedium) // 既定は試験運用なので知らせない
		send(event.FindingTypeTamper, "防御の仕組みの改ざん", event.SeverityHigh)             // 加点（0 点）なので知らせる
		b := h.wait(t, "finding")
		if b["target"] != "pc-001" || b["severity"] != "high" || !strings.Contains(b["title"].(string), "防御の仕組みの改ざん") {
			t.Errorf("通知 = %v", b)
		}
		time.Sleep(100 * time.Millisecond)
		h.mu.Lock()
		if slices.ContainsFunc(h.bodies, func(b map[string]any) bool { return strings.Contains(b["title"].(string), "認証情報") }) {
			t.Error("試験運用のルールの当てはまりを知らせた")
		}
		h.mu.Unlock()

		// 試験の通知と、全体の状態の送信の状況。
		status, body := admin.do(http.MethodPost, api.PathNotifyTest, nil)
		var res []api.NotifyResult
		json.Unmarshal(body, &res)
		if status != http.StatusOK || len(res) != 1 || res[0].Name != "hook" || res[0].Error != "" {
			t.Errorf("試験の通知 = %d %s", status, body)
		}
		h.wait(t, "test")
		status, body = admin.do(http.MethodGet, api.PathStatus, nil)
		var st api.Status
		json.Unmarshal(body, &st)
		if status != http.StatusOK || len(st.Notify) != 1 || st.Notify[0].Sent < 1 || st.Notify[0].Type != "webhook" {
			t.Errorf("全体の状態の通知 = %+v", st.Notify)
		}
	})
	t.Run("通知の宛先がない", func(t *testing.T) {
		f := start(t, env, t.TempDir(), testPolicy(policy.ResponseEnforce, false))
		admin := f.peer(pki.RoleAdmin, "admin")
		if status, _ := admin.do(http.MethodPost, api.PathNotifyTest, nil); status != http.StatusServiceUnavailable {
			t.Errorf("試験の通知の応答 = %d", status)
		}
	})
}
