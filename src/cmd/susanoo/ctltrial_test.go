package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"susanoo/internal/api"
)

func TestParseTrialWhen(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.Local)
	for in, want := range map[string]time.Time{
		"14d":        now.AddDate(0, 0, -14),
		"36h":        now.Add(-36 * time.Hour),
		"2026-10-05": time.Date(2026, 10, 5, 0, 0, 0, 0, time.Local),
	} {
		if got, err := parseTrialWhen(in, now); err != nil || !got.Equal(want) {
			t.Errorf("parseTrialWhen(%q) = %v, %v（%v のはず）", in, got, err, want)
		}
	}
	for _, bad := range []string{"0d", "-3d", "xd", "いつか"} {
		if _, err := parseTrialWhen(bad, now); err == nil {
			t.Errorf("parseTrialWhen(%q) がエラーになりません", bad)
		}
	}
}

// ctl trial は、動いている GW の CONTROLLER に評価を求めて表示する。
func TestTrialCommand(t *testing.T) {
	dir := t.TempDir()
	ctrlDir, addr := startTestGW(t, dir)
	code, out, errOut := runCmd(t, "ctl", "trial", "-since", "7d", "-max-per-week", "1", "-json", "-dir", ctrlDir, "-server", addr)
	var rep api.TrialReport
	if code != exitOK || json.Unmarshal([]byte(out), &rep) != nil {
		t.Fatalf("ctl trial -json: %s %s", out, errOut)
	}
	if rep.Gate.MaxPerWeek != 1 || rep.Gate.Weeks != 1 || !rep.Gate.Pass {
		t.Errorf("評価 = %+v", rep.Gate)
	}
	code, out, errOut = runCmd(t, "ctl", "trial", "-dir", ctrlDir, "-server", addr)
	if code != exitOK || !strings.Contains(out, "今のルールと例外: 隔離していた 0 回 … 合格") || !strings.Contains(out, "2.0 週") {
		t.Errorf("ctl trial:\n%s %s", out, errOut)
	}
	if code, _, _ := runCmd(t, "ctl", "trial", "-since", "いつか", "-dir", ctrlDir, "-server", addr); code == exitOK {
		t.Error("不正な期間を受け付けました")
	}
}
