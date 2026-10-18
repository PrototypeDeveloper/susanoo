package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gwTree は GW の設定、鍵、状態に似たディレクトリを作る。
func gwTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, content string, mode os.FileMode) {
		p := filepath.Join(dir, rel)
		os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	writeJSON(t, filepath.Join(dir, "gw.json"), gwConfig{Listen: "127.0.0.1:1", PKIDir: "pki", StateDir: "state", Policy: "policy.json"})
	write("policy.json", `{"version":1}`, 0o600)
	write("pki/ca.key", "PRIVATE", 0o600)
	write("pki/ca.crt", "CERT", 0o644)
	write("state/policy/v1.json", "{}", 0o600)
	write("state/controller/devices.json", `{"devices":[]}`, 0o600)
	write("state/controller/audit.log", "{\"seq\":1}\n", 0o600)
	write("state/controller/.devices.json.tmp-123", "half written", 0o600)
	write("state/controller/events/events-2026-10-19.jsonl", "{}\n", 0o600)
	write("state/controller/evidence/pc-001/1-AAAA.json", "{}", 0o600)
	write("state/lan/leases.json", "[]", 0o600)
	return dir
}

func TestBackupCommands(t *testing.T) {
	dir := gwTree(t)
	cfg := filepath.Join(dir, "gw.json")
	passFile := filepath.Join(dir, "pass")
	os.WriteFile(passFile, []byte("long enough passphrase"), 0o644)
	out := filepath.Join(dir, "b.backup")
	if code, _, stderr := runCmd(t, "backup", "create", "-config", cfg, "-out", out, "-passphrase-file", passFile); code != exitError || !strings.Contains(stderr, "chmod 600") {
		t.Errorf("ほかの利用者も読めるパスフレーズのファイル = %d %s", code, stderr)
	}
	os.Chmod(passFile, 0o600)
	if code, _, stderr := runCmd(t, "backup", "create", "-config", cfg, "-out", out); code != exitError || !strings.Contains(stderr, "パスフレーズ") {
		t.Errorf("パスフレーズなし = %d %s", code, stderr)
	}
	code, stdout, stderr := runCmd(t, "backup", "create", "-config", cfg, "-out", out, "-passphrase-file", passFile)
	if code != exitOK || !strings.Contains(stdout, "入れなかったもの: イベント") || !strings.Contains(stdout, "入れなかったもの: 証拠") {
		t.Fatalf("backup create: %s %s", stdout, stderr)
	}
	if data, _ := os.ReadFile(out); strings.Contains(string(data), "PRIVATE") {
		t.Error("暗号化したのに秘密鍵が読める")
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
		t.Errorf("バックアップの権限 = %v", st.Mode())
	}
	if code, stdout, _ = runCmd(t, "backup", "verify", "-in", out, "-passphrase-file", passFile); code != exitOK || !strings.Contains(stdout, "鍵と証明書 2") {
		t.Errorf("backup verify: %s", stdout)
	}

	// 新しい場所に戻す。一時ファイル、イベント、証拠は入っていない。
	dst := filepath.Join(t.TempDir(), "restored")
	dstCfg := filepath.Join(dst, "gw.json")
	if code, stdout, stderr = runCmd(t, "backup", "restore", "-config", dstCfg, "-in", out, "-passphrase-file", passFile); code != exitOK {
		t.Fatalf("backup restore: %s %s", stdout, stderr)
	}
	for rel, want := range map[string]string{"gw.json": "", "policy.json": `{"version":1}`, "pki/ca.key": "PRIVATE", "state/controller/audit.log": "{\"seq\":1}\n", "state/lan/leases.json": "[]"} {
		got, err := os.ReadFile(filepath.Join(dst, rel))
		if err != nil || (want != "" && string(got) != want) {
			t.Errorf("%s = %q, %v", rel, got, err)
		}
	}
	for _, rel := range []string{"state/controller/.devices.json.tmp-123", "state/controller/events", "state/controller/evidence"} {
		if _, err := os.Stat(filepath.Join(dst, rel)); err == nil {
			t.Errorf("%s を入れた", rel)
		}
	}
	if st, _ := os.Stat(filepath.Join(dst, "pki/ca.key")); st.Mode().Perm() != 0o600 {
		t.Errorf("鍵の権限 = %v", st.Mode())
	}
	entries, _ := os.ReadDir(dst)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".susanoo-restore-") {
			t.Errorf("取り出しの作業場所が残っている: %s", e.Name())
		}
	}

	// 今のものがあれば、-force がないと戻さない。-force なら退かしてから戻す。
	os.WriteFile(filepath.Join(dst, "state/controller/devices.json"), []byte("changed"), 0o600)
	if code, _, stderr = runCmd(t, "backup", "restore", "-config", dstCfg, "-in", out, "-passphrase-file", passFile); code != exitError || !strings.Contains(stderr, "-force") {
		t.Errorf("上書きの確認 = %d %s", code, stderr)
	}
	if code, stdout, stderr = runCmd(t, "backup", "restore", "-config", dstCfg, "-in", out, "-passphrase-file", passFile, "-force"); code != exitOK || !strings.Contains(stdout, "退かしました") {
		t.Fatalf("backup restore -force: %s %s", stdout, stderr)
	}
	if got, _ := os.ReadFile(filepath.Join(dst, "state/controller/devices.json")); string(got) != `{"devices":[]}` {
		t.Errorf("戻した台帳 = %q", got)
	}
	moved, _ := filepath.Glob(filepath.Join(dst, "state.before-restore-*", "controller", "devices.json"))
	if len(moved) != 1 {
		t.Errorf("退かした状態 = %v", moved)
	} else if got, _ := os.ReadFile(moved[0]); string(got) != "changed" {
		t.Errorf("退かした台帳 = %q", got)
	}

	// -events と -evidence で入れる。違うパスフレーズでは戻せない。
	full := filepath.Join(dir, "full.backup")
	if code, stdout, stderr = runCmd(t, "backup", "create", "-config", cfg, "-out", full, "-passphrase-file", passFile, "-events", "-evidence"); code != exitOK || strings.Contains(stdout, "入れなかったもの") {
		t.Fatalf("backup create -events -evidence: %s %s", stdout, stderr)
	}
	t.Setenv(passphraseEnv, "a different passphrase")
	if code, _, stderr = runCmd(t, "backup", "verify", "-in", full); code != exitError || !strings.Contains(stderr, "パスフレーズが違う") {
		t.Errorf("違うパスフレーズ = %d %s", code, stderr)
	}
}
