//go:build lab

package lab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAppControl はプロセス単位の通信の制御（C7）と、AI エージェントの通信先の制限（C9）を確かめる。
// GW と端末 1 台を名前空間で作り、ポリシーのグループの apps で、試験のプログラムと AI エージェントの接続を制御する。
func TestAppControl(t *testing.T) {
	if *susanooBin == "" {
		t.Fatal("-susanoo で susanoo の実行ファイルを指定してください")
	}
	pc := &machine{ns: "sus-c1", id: "pc-001", agent: true, port: "p-c1"}
	l := &lab{t: t, dir: t.TempDir()}
	buildTopology(t, []*machine{pc})
	l.setup([]*machine{pc})

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start(t, "試験用サーバー（8080）", nsInet, []string{helperEnv + "=serve:" + serverAddr}, self)
	start(t, "試験用サーバー（9090）", nsInet, []string{helperEnv + "=sink:203.0.113.2:9090"}, self)
	start(t, "GW", nsGW, nil, *susanooBin, "gw", "-config", filepath.Join(l.dir, "gw.json"))
	waitFor(t, "GW の起動", 10*time.Second, func() bool { return l.devices() != nil })
	l.dhcp(pc)
	start(t, "CLIENT "+pc.id, pc.ns, nil, *susanooBin, "client", "-config", filepath.Join(l.dir, pc.id+".json"))
	waitFor(t, "端末の登録と機能の申告", 15*time.Second, func() bool {
		return strings.Contains(strings.Join(l.devices()[pc.id].Features, ","), "app_control")
	})

	ctlPolicy := func(args ...string) string {
		t.Helper()
		return sh(t, "ip", append(append([]string{"netns", "exec", nsGW, *susanooBin, "ctl", "policy"}, args...), "-dir", l.ctrlDir, "-server", controllerAddr)...)
	}
	pushApps := func(name string, apps map[string]any) {
		t.Helper()
		group := map[string]any{"name": "default", "egress": map[string]any{"default": "allow"}, "isolation": "management"}
		if apps != nil {
			group["apps"] = apps
		}
		path := filepath.Join(l.dir, name+".json")
		writeJSON(t, path, map[string]any{
			"version": 1, "name": name, "issued_at": time.Now().UTC(), "response": "enforce", "on_failure": "fail_open",
			"groups": []map[string]any{group},
		})
		ctlPolicy("push", path)
	}
	// helperRun は端末で補助のプログラムを動かし、成功したかと、かかった時間を返す。agent なら、名前を claude にした bash の子として動かす。
	// bash は -c に単純なコマンドが 1 つだけだと fork せずに exec するので、「; exit $?」を足して fork させ、補助のプログラムの
	// 終了コードを返させる（claude の名前の bash を親として残す）。
	helperRun := func(spec string, agent bool) (bool, time.Duration) {
		t.Helper()
		cmd := inNS(pc.ns, self)
		if agent {
			cmd = inNS(pc.ns, "/bin/bash", "-c", "exec -a claude /bin/bash -c '"+self+"; exit $?'")
		}
		cmd.Env = append(os.Environ(), helperEnv+"="+spec)
		begin := time.Now()
		err := cmd.Run()
		return err == nil, time.Since(begin)
	}
	rules := []map[string]any{
		{"name": "試験のプログラムの 9090 番", "exe": []string{self}, "dst": []map[string]any{{"cidr": "203.0.113.2/32", "ports": []int{9090}}}, "action": "deny"},
		{"name": "AI エージェントの外への接続", "agents": []string{"*"}, "dst": []map[string]any{{"cidr": "203.0.113.0/24"}}, "action": "deny"},
	}

	t.Log("段階1: 制御のないうちは、どのプログラムも接続できる")
	if ok, _ := helperRun("hold:203.0.113.2:9090:0", false); !ok {
		t.Fatal("制御の前に 9090 番に接続できません")
	}
	if ok, _ := helperRun("dial:"+serverAddr, true); !ok {
		t.Fatal("制御の前に AI エージェントの配下から接続できません")
	}

	t.Log("段階2: 試験のプログラムの 9090 番への接続と、AI エージェントの外への接続を拒否する（enforce）。拒否はすぐに失敗し、検知結果になる")
	pushApps("apps-enforce", map[string]any{"mode": "enforce", "default": "allow", "rules": rules})
	waitFor(t, "制御の適用", 15*time.Second, func() bool { return l.devices()[pc.id].AppControl == "enforce" })
	if err := inNS(pc.ns, "nft", "list", "table", "inet", "susanoo_apps").Run(); err != nil {
		t.Errorf("端末に制御のテーブルがありません: %v", err)
	}
	if ok, took := helperRun("hold:203.0.113.2:9090:0", false); ok || took > 1500*time.Millisecond {
		t.Errorf("拒否した接続 = 成功 %v、%v（すぐに失敗するはず）", ok, took)
	}
	if ok, _ := helperRun("dial:"+serverAddr, false); !ok {
		t.Error("拒否していない宛先（8080 番）に接続できません")
	}
	if ok, _ := helperRun("dial:"+serverAddr, true); ok {
		t.Error("AI エージェントの配下から、拒否した宛先に接続できました")
	}
	waitFor(t, "拒否の検知結果", 15*time.Second, func() bool {
		ev := l.events()
		return eventLine(ev, `"app_control"`, `"action":"deny"`, `"port":9090`, "試験のプログラムの 9090 番") &&
			eventLine(ev, `"app_control"`, `"action":"deny"`, `"agent":{"name":"claude"`, "AI エージェントの外への接続")
	})
	waitFor(t, "AI エージェントによる要注意の操作（CONTROLLER の既定のルール）", 15*time.Second, func() bool {
		return eventLine(l.events(), `"rule_match"`, `"uid":"agent-sensitive-action"`)
	})

	t.Log("段階3: 試験運用（monitor）では接続を通し、拒否に当たったことだけを記録する。ctl apps learned でまとめて見られる")
	pushApps("apps-monitor", map[string]any{"mode": "monitor", "default": "allow", "rules": rules})
	waitFor(t, "試験運用の適用", 15*time.Second, func() bool { return l.devices()[pc.id].AppControl == "monitor" })
	if ok, _ := helperRun("hold:203.0.113.2:9090:0", false); !ok {
		t.Error("試験運用なのに接続できません")
	}
	waitFor(t, "拒否に当たった記録", 15*time.Second, func() bool {
		return eventLine(l.events(), `"app_control"`, `"action":"would_deny"`, `"port":9090`)
	})
	out := sh(t, "ip", "netns", "exec", nsGW, *susanooBin, "ctl", "apps", "learned", "-json", "-dir", l.ctrlDir, "-server", controllerAddr)
	var learned []struct{ Exe, Action, Dst string }
	if err := json.Unmarshal([]byte(out), &learned); err != nil {
		t.Fatalf("ctl apps learned: %v %s", err, out)
	}
	actions := map[string]bool{}
	for _, s := range learned {
		if s.Exe == self && s.Dst == "203.0.113.2:9090" {
			actions[s.Action] = true
		}
	}
	if !actions["deny"] || !actions["would_deny"] {
		t.Errorf("ctl apps learned = %+v", learned)
	}

	t.Log("段階4: ポリシーから制御を外すと、端末のテーブルを消して元に戻る")
	pushApps("apps-off", nil)
	waitFor(t, "制御をやめる", 15*time.Second, func() bool { return l.devices()[pc.id].AppControl == "" })
	waitFor(t, "制御のテーブルの削除", 10*time.Second, func() bool {
		return inNS(pc.ns, "nft", "list", "table", "inet", "susanoo_apps").Run() != nil
	})
	if ok, _ := helperRun("dial:"+serverAddr, true); !ok {
		t.Error("制御をやめた後に、AI エージェントの配下から接続できません")
	}
}
