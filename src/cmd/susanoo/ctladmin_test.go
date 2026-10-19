package main

import (
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/pki"
)

// 管理者ごとの証明書の発行と失効、認証局の証明書の更新。
func TestAdminCommands(t *testing.T) {
	dir := t.TempDir()
	ctrlDir, addr := startTestGW(t, dir)
	as := func(adminDir string, args ...string) (int, string, string) {
		t.Helper()
		return runCmd(t, append(append([]string{"ctl"}, args...), "-dir", adminDir, "-server", addr)...)
	}
	newAdmin := func(id string) string {
		t.Helper()
		d := filepath.Join(dir, "admin-"+id+"-"+strings.ReplaceAll(time.Now().Format("150405.000"), ".", ""))
		if code, out, errOut := runCmd(t, "ctl", "admin", "keygen", "-dir", d); code != exitOK {
			t.Fatalf("鍵を作れません: %s %s", out, errOut)
		}
		if code, _, _ := runCmd(t, "ctl", "admin", "keygen", "-dir", d); code == exitOK {
			t.Error("既にある鍵を作り直しました")
		}
		if code, out, errOut := runCmd(t, "ctl", "admin", "issue", "-dir", ctrlDir, "-id", id, "-pub", filepath.Join(d, fileAdminPub), "-out", d); code != exitOK {
			t.Fatalf("証明書を発行できません: %s %s", out, errOut)
		}
		return d
	}
	alice := newAdmin("alice")
	if code, out, errOut := as(alice, "status"); code != exitOK {
		t.Fatalf("alice の ctl status: %s %s", out, errOut)
	}
	if code, out, errOut := as(ctrlDir, "admin", "revoke", "alice"); code != exitOK || !strings.Contains(out, "alice") {
		t.Fatalf("alice の失効: %s %s", out, errOut)
	}
	if code, _, _ := as(alice, "status"); code == exitOK {
		t.Error("失効させた管理者の証明書で操作できました")
	}
	// 今使っている証明書まで失効させる操作は断る。
	if code, _, errOut := as(ctrlDir, "admin", "revoke", "admin", "-before", time.Now().Add(time.Hour).Format(time.RFC3339)); code == exitOK || !strings.Contains(errOut, "新しい証明書を発行してから") {
		t.Errorf("自分の証明書まで失効させる操作 = %d %s", code, errOut)
	}
	// 同じ ID で発行し直した証明書で、前の証明書を失効させる（証明書の時刻は秒単位）。
	time.Sleep(1100 * time.Millisecond)
	admin2 := newAdmin("admin")
	if code, out, errOut := as(admin2, "admin", "revoke", "admin"); code != exitOK {
		t.Fatalf("前の証明書の失効: %s %s", out, errOut)
	}
	if code, _, _ := as(ctrlDir, "status"); code == exitOK {
		t.Error("前の管理者の証明書で操作できました")
	}
	code, out, errOut := as(admin2, "admin", "list", "-json")
	var list api.AdminList
	if code != exitOK || json.Unmarshal([]byte(out), &list) != nil {
		t.Fatalf("ctl admin list: %s %s", out, errOut)
	}
	var ids []string
	for _, r := range list.Revoked {
		ids = append(ids, r.ID)
	}
	if list.Self != "admin" || !slices.Equal(ids, []string{"admin", "alice"}) {
		t.Errorf("失効の一覧 = %+v", list)
	}

	// 認証局の証明書を同じ鍵のまま発行し直す。動いている GW には前の証明書のままでも接続できる。
	before, err := pki.ReadCertFile(filepath.Join(ctrlDir, fileCACert))
	if err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := runCmd(t, "ctl", "ca", "renew", "-dir", ctrlDir); code != exitOK || !strings.Contains(out, "GW を起動し直してください") {
		t.Fatalf("ctl ca renew: %s %s", out, errOut)
	}
	after, err := pki.ReadCertFile(filepath.Join(ctrlDir, fileCACert))
	if err != nil || !after.NotAfter.After(before.NotAfter) || !after.PublicKey.(ed25519.PublicKey).Equal(before.PublicKey) {
		t.Errorf("発行し直した認証局の証明書 = %v → %v（%v）", before.NotAfter, after.NotAfter, err)
	}
	if code, out, errOut := as(admin2, "status"); code != exitOK || !strings.Contains(out, "認証局の期限") {
		t.Errorf("認証局の証明書を発行し直した後の ctl status: %s %s", out, errOut)
	}
	// 二段構えの GW のディレクトリでは、管理者の証明書も認証局の証明書も作れない。
	twoTier := filepath.Join(dir, "two-tier")
	if code, out, errOut := runCmd(t, "ctl", "init", "-two-tier", "-dir", twoTier); code != exitOK {
		t.Fatalf("ctl init -two-tier: %s %s", out, errOut)
	}
	if code, _, _ := runCmd(t, "ctl", "ca", "renew", "-dir", twoTier); code == exitOK {
		t.Error("発行用の認証局の鍵しかないディレクトリで認証局の証明書を作りました")
	}
}

// 二段構えでは、ルートの認証局の証明書をルートのディレクトリで発行し直し、発行用の認証局に署名し直して GW に渡す。
// GW は、同じ鍵と名前で期限の延びたルートの証明書だけを受け入れる。発行済みの端末の証明書はそのまま検証に通る。
func TestRenewRootTwoTier(t *testing.T) {
	dir := t.TempDir()
	rootDir, ctrlDir, clientDir := setupTwoTier(t, dir)
	before, _ := pki.ReadCertFile(filepath.Join(ctrlDir, fileCACert))
	if code, out, errOut := runCmd(t, "ctl", "ca", "renew", "-dir", rootDir); code != exitOK || !strings.Contains(out, "sign-issuer") {
		t.Fatalf("ルートの ctl ca renew: %s %s", out, errOut)
	}
	out := filepath.Join(dir, "renewed")
	if code, _, errOut := runCmd(t, "ctl", "root", "sign-issuer", "-dir", rootDir, "-pub", filepath.Join(ctrlDir, pki.IssuerPubFile), "-out", out); code != exitOK {
		t.Fatalf("sign-issuer: %s", errOut)
	}
	if code, stdout, errOut := runCmd(t, "ctl", "init", "-issuer", out, "-dir", ctrlDir); code != exitOK || !strings.Contains(stdout, "発行し直したもの") {
		t.Fatalf("ctl init -issuer: %s %s", stdout, errOut)
	}
	after, _ := pki.ReadCertFile(filepath.Join(ctrlDir, fileCACert))
	if !after.NotAfter.After(before.NotAfter) {
		t.Errorf("GW のルートの証明書の期限 = %v → %v", before.NotAfter, after.NotAfter)
	}
	verifyChain(t, ctrlDir, filepath.Join(clientDir, fileClientCert)) // 前のルートのときに発行した端末の証明書
}
