package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"susanoo/internal/api"
)

// ctl upgrade で、署名したリリースを作り、CONTROLLER に送り、状態を見て、全体に広げ、やめられる。
// ctl upgrade verify で、実行ファイルが署名した目録と合うかを確かめられる。
func TestUpgradeCommands(t *testing.T) {
	dir := t.TempDir()
	ctrlDir, addr := startTestGW(t, dir)
	clientDir := filepath.Join(dir, "client")
	// ctl issue は、リリースの公開鍵（ポリシーの署名の公開鍵）を端末に配る。
	policyPub, _ := os.ReadFile(filepath.Join(ctrlDir, filePolicyPub))
	if releasePub, err := os.ReadFile(filepath.Join(clientDir, fileReleasePub)); err != nil || !bytes.Equal(policyPub, releasePub) {
		t.Errorf("端末のリリースの公開鍵 = %v", err)
	}
	bin := filepath.Join(dir, "susanoo-next")
	os.WriteFile(bin, []byte("#!/bin/sh\necho 'susanoo 0.9.0'\n"), 0o755)
	rel := filepath.Join(dir, "rel")
	ctl := func(args ...string) (int, string, string) {
		t.Helper()
		return runCmd(t, append(append([]string{"ctl", "upgrade"}, args...), "-dir", ctrlDir, "-server", addr)...)
	}
	if code, stdout, stderr := runCmd(t, "ctl", "upgrade", "sign", "-dir", ctrlDir, "-version", "0.9.0", "-bin", "linux/amd64="+bin, "-out", rel); code != exitOK {
		t.Fatalf("ctl upgrade sign: %s %s", stdout, stderr)
	}
	if code, _, stderr := ctl("status"); code == exitOK || !strings.Contains(stderr, "404") {
		t.Errorf("配布していないときの status: %s", stderr)
	}
	if code, stdout, stderr := ctl("push", rel, "-canary", "pc-001"); code != exitOK || !strings.Contains(stdout, "先行適用") {
		t.Fatalf("ctl upgrade push: %s %s", stdout, stderr)
	}
	code, stdout, stderr := ctl("status", "-json")
	var info api.ReleaseInfo
	if code != exitOK || json.Unmarshal([]byte(stdout), &info) != nil || info.Version != "0.9.0" || len(info.Missing) != 0 || !slices.Equal(info.Canary, []string{"pc-001"}) {
		t.Fatalf("ctl upgrade status: %s %s", stdout, stderr)
	}
	verify := func(binPath string) (int, string, string) {
		return runCmd(t, "ctl", "upgrade", "verify", "-manifest", filepath.Join(rel, "manifest.json"), "-key", filepath.Join(ctrlDir, filePolicyPub), "-bin", binPath, "-os", "linux", "-arch", "amd64")
	}
	if code, stdout, stderr := verify(bin); code != exitOK || !strings.Contains(stdout, "合います") {
		t.Errorf("ctl upgrade verify: %s %s", stdout, stderr)
	}
	tampered := filepath.Join(dir, "tampered")
	os.WriteFile(tampered, []byte("#!/bin/sh\necho evil\n"), 0o755)
	if code, _, _ := verify(tampered); code == exitOK {
		t.Error("目録と合わない実行ファイルを合うとした")
	}
	// 同じ版は配り直せない。
	if code, _, _ := ctl("push", rel); code == exitOK {
		t.Error("同じ版を配り直せた")
	}
	if code, stdout, _ := ctl("promote"); code != exitOK || !strings.Contains(stdout, "全体") {
		t.Errorf("ctl upgrade promote: %s", stdout)
	}
	if code, stdout, _ := ctl("abort"); code != exitOK || !strings.Contains(stdout, "やめました") {
		t.Errorf("ctl upgrade abort: %s", stdout)
	}
}
