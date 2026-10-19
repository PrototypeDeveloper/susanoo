package main

import (
	"encoding/json"
	"testing"
	"time"

	"susanoo/internal/event"
)

func TestSummarizeApps(t *testing.T) {
	mk := func(device, exe, agent, ip string, port int, action string, at time.Time) json.RawMessage {
		e := event.New(event.ClassDetectionFinding, event.FindingCreate, event.SeverityLow, at)
		e.Device = &event.Device{UID: device}
		e.FindingInfo = &event.FindingInfo{UID: "x", Title: "t", Types: []string{event.FindingTypeAppControl}}
		e.DstEndpoint = &event.Endpoint{IP: ip, Port: port}
		e.Connection = &event.Connection{ProtocolName: "tcp"}
		e.Unmapped = map[string]any{"app_control": map[string]any{"action": action, "rule": "既定", "exe": exe}}
		if agent != "" {
			e.Unmapped["agent"] = map[string]any{"name": agent}
		}
		b, _ := json.Marshal(e)
		return b
	}
	now := time.Now()
	raw := []json.RawMessage{
		mk("pc-001", "/usr/bin/curl", "", "203.0.113.5", 443, "would_deny", now.Add(-time.Hour)),
		mk("pc-002", "/usr/bin/curl", "", "203.0.113.5", 443, "would_deny", now),
		mk("pc-001", "/usr/bin/node", "claude", "198.51.100.7", 443, "deny", now),
		json.RawMessage(`{"class_uid":2004}`), // 中身のない検知結果は飛ばす
	}
	got := summarizeApps(raw)
	if len(got) != 2 {
		t.Fatalf("まとめ = %+v", got)
	}
	if s := got[0]; s.Exe != "/usr/bin/curl" || s.Count != 2 || len(s.Devices) != 2 || s.Dst != "203.0.113.5:443" || !s.Last.Equal(time.UnixMilli(now.UnixMilli())) {
		t.Errorf("1 件目 = %+v", s)
	}
	if s := got[1]; s.Agent != "claude" || s.Action != "deny" || s.Count != 1 {
		t.Errorf("2 件目 = %+v", s)
	}
}
