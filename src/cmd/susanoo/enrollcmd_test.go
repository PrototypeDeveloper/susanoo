package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"susanoo/internal/api"
)

// ctl enroll create で作ったコードで、client enroll が鍵を作って証明書と認証局と指示の公開鍵を受け取る。
func TestEnrollCommands(t *testing.T) {
	dir := t.TempDir()
	ctrlDir, addr := startTestGW(t, dir)
	clientDir := filepath.Join(dir, "enrolled")

	// コードがない間は、端末は接続できない。
	if code, _, stderr := runCmd(t, "client", "enroll", "-controller", addr, "-id", "pc-001", "-code", "0000-0000-0000-0000", "-dir", clientDir); code == exitOK || !strings.Contains(stderr, "断りました") {
		t.Errorf("コードがないときの登録: %d %s", code, stderr)
	}
	code, stdout, stderr := runCmd(t, "ctl", "enroll", "create", "pc-001", "-ttl", "1h", "-dir", ctrlDir, "-server", addr, "-json")
	var ec api.EnrollCode
	if code != exitOK || json.Unmarshal([]byte(stdout), &ec) != nil || ec.Code == "" {
		t.Fatalf("ctl enroll create: %s %s", stdout, stderr)
	}
	if _, stdout, _ := runCmd(t, "ctl", "enroll", "create", "pc-002", "-dir", ctrlDir, "-server", addr); !strings.Contains(stdout, "susanoo client enroll -controller") {
		t.Errorf("ctl enroll create の案内: %s", stdout)
	}
	if _, stdout, _ := runCmd(t, "ctl", "enroll", "list", "-dir", ctrlDir, "-server", addr); !strings.Contains(stdout, "pc-001") || strings.Contains(stdout, ec.Code) {
		t.Errorf("ctl enroll list: %s", stdout)
	}
	if code, stdout, stderr := runCmd(t, "client", "enroll", "-controller", addr, "-id", "pc-001", "-code", ec.Code, "-dir", clientDir); code != exitOK || !strings.Contains(stdout, "登録しました") {
		t.Fatalf("client enroll: %s %s", stdout, stderr)
	}
	if st, err := os.Stat(filepath.Join(clientDir, fileClientKey)); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("端末の秘密鍵 = %v %v", st, err)
	}
	verifyChain(t, clientDir, filepath.Join(clientDir, fileClientCert))
	signPub, _ := os.ReadFile(filepath.Join(ctrlDir, fileSignPub))
	commandPub, _ := os.ReadFile(filepath.Join(clientDir, fileCommandPub))
	if !bytes.Equal(signPub, commandPub) {
		t.Error("指示の公開鍵が CONTROLLER の署名の鍵と違う")
	}
	caCtrl, _ := os.ReadFile(filepath.Join(ctrlDir, fileCACert))
	caClient, _ := os.ReadFile(filepath.Join(clientDir, fileCACert))
	if !bytes.Equal(caCtrl, caClient) {
		t.Error("受け取った認証局の証明書が違う")
	}
	// 既にある証明書は -force がなければ置き換えない。コードは一度しか使えない。
	if code, _, stderr := runCmd(t, "client", "enroll", "-controller", addr, "-id", "pc-001", "-code", ec.Code, "-dir", clientDir); code == exitOK || !strings.Contains(stderr, "-force") {
		t.Errorf("二度目の登録: %s", stderr)
	}
	if code, _, _ := runCmd(t, "client", "enroll", "-controller", addr, "-id", "pc-001", "-code", ec.Code, "-dir", clientDir, "-force"); code == exitOK {
		t.Error("使ったコードで登録できた")
	}
	if code, _, _ := runCmd(t, "ctl", "enroll", "delete", "pc-002", "-dir", ctrlDir, "-server", addr); code != exitOK {
		t.Error("コードを取り消せない")
	}
	if _, stdout, _ := runCmd(t, "ctl", "enroll", "list", "-dir", ctrlDir, "-server", addr); !strings.Contains(stdout, "ありません") {
		t.Errorf("取り消した後の一覧: %s", stdout)
	}
	if code, _, stderr := runCmd(t, "client", "enroll", "-controller", addr, "-id", "pc-003", "-code", "bad", "-dir", t.TempDir()); code == exitOK || !strings.Contains(stderr, "形") {
		t.Errorf("形の正しくないコード: %s", stderr)
	}
}
