//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestTrial は、学習モードの試行の評価（2o。フェーズ2のゲートの判断）を確かめる：監視モードで隔離しなかった判断の記録と、
// 保存したイベントを今の検知ルールと例外で評価し直した、端末ごとの隔離していた回数と基準による判定。
func TestTrial(t *testing.T) {
	if *susanooBin == "" {
		t.Fatal("-susanoo で susanoo の実行ファイルを指定してください")
	}
	pc1 := &machine{ns: "sus-c1", id: "pc-001", agent: true, port: "p-c1"}
	machines := []*machine{pc1}
	l := &lab{t: t, dir: t.TempDir()}
	buildTopology(t, machines)
	l.setup(machines)
	// 試行は、対応の方式を監視（monitor。隔離しない）にして行う。
	writeJSON(t, filepath.Join(l.dir, "policy.json"), map[string]any{
		"version": 1, "name": "試行", "issued_at": time.Now().UTC(), "response": "monitor", "on_failure": "fail_open",
		"groups": []map[string]any{{"name": "default", "egress": map[string]any{"default": "learn"}, "isolation": "management"}},
	})
	start(t, "GW", nsGW, nil, *susanooBin, "gw", "-config", filepath.Join(l.dir, "gw.json"))
	waitFor(t, "GW の起動", 10*time.Second, func() bool { return l.devices() != nil })
	l.dhcp(pc1)
	start(t, "CLIENT "+pc1.id, pc1.ns, nil, *susanooBin, "client", "-config", filepath.Join(l.dir, pc1.id+".json"))
	waitFor(t, "端末の登録", 15*time.Second, func() bool { return !l.devices()[pc1.id].LastSeen.IsZero() })
	type trialRule struct {
		ID       string `json:"id"`
		Hits     int    `json:"hits"`
		Excepted int    `json:"excepted"`
	}
	type report struct {
		Suppressed int `json:"suppressed"`
		Isolations []struct {
			Target string   `json:"target"`
			Rules  []string `json:"rules"`
		} `json:"isolations"`
		ByRule []trialRule `json:"by_rule"`
		Gate   struct {
			Pass bool     `json:"pass"`
			Over []string `json:"over"`
		} `json:"gate"`
	}
	trial := func(args ...string) report {
		t.Helper()
		var rep report
		if !l.ctlJSON(&rep, append([]string{"trial"}, args...)...) {
			t.Fatal("ctl trial -json に失敗しました")
		}
		return rep
	}

	t.Log("段階1: 監視モードでは、隔離が必要な検知があっても隔離せず、隔離しなかった判断を記録する")
	if _, err := os.ReadFile(l.token(pc1.id)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "隔離しなかった判断の記録", 15*time.Second, func() bool {
		return eventLine(l.events(), `"types":["would_isolate"]`, `"uid":"`+pc1.id+`"`)
	})
	time.Sleep(2 * time.Second)
	if d := l.devices()[pc1.id]; d.Isolation != "" {
		t.Errorf("監視モードで隔離しました: %s", d.Isolation)
	}

	t.Log("段階2: 試行の評価は、保存したイベントを今の検知ルールで評価し直し、隔離していた回数を基準と比べる")
	rep := trial("-since", "1d", "-max-per-week", "0")
	if rep.Suppressed < 1 || len(rep.Isolations) != 1 || rep.Isolations[0].Target != pc1.id || !slices.Contains(rep.Isolations[0].Rules, "honeytoken") {
		t.Errorf("試行の評価 = %+v", rep)
	}
	if rep.Gate.Pass || !slices.Equal(rep.Gate.Over, []string{pc1.id}) {
		t.Errorf("基準 0 回の判定 = %+v", rep.Gate)
	}
	out, err := inNS(nsGW, *susanooBin, "ctl", "trial", "-since", "1d", "-dir", l.ctrlDir, "-server", controllerAddr).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "今のルールと例外: 隔離していた 1 回") || !strings.Contains(string(out), pc1.id) {
		t.Errorf("ctl trial（%v）:\n%s", err, out)
	}

	t.Log("段階3: 誤検知と判断した当たりを例外にして配布すると、新しい試行を待たずに、評価し直した結果に効く")
	writeJSON(t, filepath.Join(l.dir, "rules.json"), map[string]any{
		"name": "試行の例外", "rules": []any{}, // 版数と発行の時刻は ctl rules push が付ける
		"exceptions": []map[string]any{{"rules": []string{"honeytoken"}, "devices": []string{pc1.id}, "reason": "試行の操作"}},
	})
	sh(t, "ip", "netns", "exec", nsGW, *susanooBin, "ctl", "rules", "push", filepath.Join(l.dir, "rules.json"), "-dir", l.ctrlDir, "-server", controllerAddr)
	rep = trial("-since", "1d", "-max-per-week", "0")
	if len(rep.Isolations) != 0 || !rep.Gate.Pass {
		t.Errorf("例外を配布した後の評価 = %+v", rep)
	}
	for _, r := range rep.ByRule {
		if r.ID == "honeytoken" && (r.Excepted < 1 || r.Hits != 0) {
			t.Errorf("例外で除いた回数 = %+v", r)
		}
	}
}
