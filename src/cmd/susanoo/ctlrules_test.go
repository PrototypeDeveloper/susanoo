package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"susanoo/internal/api"
)

// startTestGW は、遮断を無効にした GW を起動し、ctl の操作に使う CONTROLLER のディレクトリとアドレスを返す。
func startTestGW(t *testing.T, dir string) (ctrlDir, addr string) {
	t.Helper()
	ctrlDir, _ = setup(t, dir)
	addr = freePort(t)
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "policy.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	no := false
	writeJSON(t, filepath.Join(dir, "gw.json"), gwConfig{Listen: addr, PKIDir: "controller", StateDir: "gw-state", Policy: "policy.json", Enforce: &no})
	ctx, cancel := context.WithCancel(context.Background())
	var gwErr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"gw", "-config", filepath.Join(dir, "gw.json")}, &bytes.Buffer{}, &gwErr)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		if t.Failed() {
			t.Logf("GW のログ:\n%s", gwErr.String())
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for code, _, _ := runCmd(t, "ctl", "status", "-dir", ctrlDir, "-server", addr); code != exitOK; code, _, _ = runCmd(t, "ctl", "status", "-dir", ctrlDir, "-server", addr) {
		if time.Now().After(deadline) {
			t.Fatal("GW が起動しない")
		}
		time.Sleep(50 * time.Millisecond)
	}
	return ctrlDir, addr
}

// 検知ルールの配布、一覧、中身の表示、巻き戻し、当てはまった回数の表示。
func TestRulesCommands(t *testing.T) {
	dir := t.TempDir()
	ctrlDir, addr := startTestGW(t, dir)
	ctl := func(args ...string) (int, string, string) {
		t.Helper()
		return runCmd(t, append(append([]string{"ctl", "rules"}, args...), "-dir", ctrlDir, "-server", addr)...)
	}
	info := func() api.RulesInfo {
		t.Helper()
		code, out, errOut := ctl("stats", "-json")
		var info api.RulesInfo
		if code != exitOK || json.Unmarshal([]byte(out), &info) != nil {
			t.Fatalf("ctl rules stats: %s %s", out, errOut)
		}
		return info
	}
	if code, out, _ := ctl("list"); code != exitOK || !strings.Contains(out, "既定のルール") {
		t.Errorf("配布前の一覧 = %s", out)
	}
	if code, _, errOut := ctl("show"); code == exitOK || !strings.Contains(errOut, "配布した版はありません") {
		t.Errorf("配布前の中身の表示 = %s", errOut)
	}

	example := filepath.Join("..", "..", "..", "config", "rules.example.json")
	if code, out, errOut := ctl("push", example); code != exitOK || !strings.Contains(out, "版 1") {
		t.Fatalf("配布: %s %s", out, errOut)
	}
	i := info()
	if i.Current.Version != 1 || i.Current.Name != "標準（試験運用）" || i.Exceptions != 3 || len(i.Rules) < 15 {
		t.Errorf("配布した後の状態 = %+v", i)
	}
	code, out, _ := ctl("stats")
	for _, want := range []string{"download-and-run", "試験運用", "honeytoken", "おとりへの接触（既定）", "加点"} {
		if code != exitOK || !strings.Contains(out, want) {
			t.Errorf("当てはまった回数の表示に %q がない: %s", want, out)
		}
	}
	if code, out, _ := ctl("show", "1"); code != exitOK || !strings.Contains(out, `"version": 1`) || !strings.Contains(out, "reverse-shell") {
		t.Errorf("版 1 の中身 = %s", out)
	}

	// 名前を変えた版を配布してから、版 1 の中身に戻す（版数は 3 になる）。
	data, _ := os.ReadFile(example)
	renamed := strings.Replace(string(data), "標準（試験運用）", "検証の版", 1)
	os.WriteFile(filepath.Join(dir, "rules2.json"), []byte(renamed), 0o600)
	if code, _, errOut := ctl("push", filepath.Join(dir, "rules2.json")); code != exitOK {
		t.Fatalf("2 回目の配布: %s", errOut)
	}
	if code, out, errOut := ctl("rollback", "1"); code != exitOK || !strings.Contains(out, "版 3") {
		t.Fatalf("巻き戻し: %s %s", out, errOut)
	}
	if i := info(); i.Current.Version != 3 || len(i.Versions) != 3 || i.Current.Name != "標準（試験運用）" {
		t.Errorf("巻き戻した後の状態 = %+v", i)
	}
	if code, out, _ := ctl("list"); code != exitOK || strings.Count(out, "\n") != 4 || !strings.Contains(out, "適用中") {
		t.Errorf("版の一覧 = %s", out)
	}
	if code, out, _ := runCmd(t, "ctl", "status", "-dir", ctrlDir, "-server", addr); code != exitOK || !strings.Contains(out, "検知ルール") || !strings.Contains(out, "版 3") {
		t.Errorf("全体の状態 = %s", out)
	}

	// 検証に通らないファイルは配布しない。
	os.WriteFile(filepath.Join(dir, "bad.json"), []byte(`{"name": "x", "rules": [{"id": "a", "name": "x", "mode": "enforce"}]}`), 0o600)
	if code, _, errOut := ctl("push", filepath.Join(dir, "bad.json")); code == exitOK || !strings.Contains(errOut, "finding か") {
		t.Errorf("不正なファイルの配布 = %s", errOut)
	}
}
