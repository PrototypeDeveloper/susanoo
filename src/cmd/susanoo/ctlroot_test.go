package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"susanoo/internal/keys"
	"susanoo/internal/pki"
	"susanoo/internal/policy"
)

// setupTwoTier は二段構えの鍵を、ルートのディレクトリ（管理者の手元）と GW のディレクトリに作り、端末の証明書を発行する。
func setupTwoTier(t *testing.T, dir string) (rootDir, ctrlDir, clientDir string) {
	t.Helper()
	rootDir, ctrlDir, clientDir = filepath.Join(dir, "root"), filepath.Join(dir, "controller"), filepath.Join(dir, "client")
	toGW := filepath.Join(dir, "to-gw")
	for _, args := range [][]string{
		{"ctl", "root", "init", "-dir", rootDir},
		{"ctl", "init", "-two-tier", "-dir", ctrlDir},
		{"ctl", "root", "sign-issuer", "-dir", rootDir, "-pub", filepath.Join(ctrlDir, pki.IssuerPubFile), "-out", toGW},
		{"ctl", "init", "-issuer", toGW, "-dir", ctrlDir},
		{"client", "keygen", "-dir", clientDir},
		{"ctl", "issue", "-dir", ctrlDir, "-id", "pc-001", "-pub", filepath.Join(clientDir, fileClientPub), "-out", clientDir},
	} {
		if code, _, stderr := runCmd(t, args...); code != exitOK {
			t.Fatalf("%v: %s", args, stderr)
		}
	}
	return rootDir, ctrlDir, clientDir
}

// verifyChain は、ディレクトリ dir の ca.crt を根に、証明書のファイル file の連なりを確かめる。
func verifyChain(t *testing.T, caDir, file string) []*x509.Certificate {
	t.Helper()
	chain, err := pki.ReadChainFile(file)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := loadPool(caDir)
	if err != nil {
		t.Fatal(err)
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("%s の連なりを確かめられない: %v", file, err)
	}
	return chain
}

// ctl root と ctl init -two-tier、-issuer で、ルートの認証局の鍵とポリシーの署名の鍵を GW の外に置ける。
func TestTwoTierCommands(t *testing.T) {
	dir := t.TempDir()
	rootDir, ctrlDir, clientDir := setupTwoTier(t, dir)

	// GW には、ルートの認証局の鍵、ポリシーの署名の鍵、管理者の鍵がない。
	for _, f := range []string{fileCAKey, filePolicyKey, fileAdminKey, fileAdminCert} {
		if _, err := os.Stat(filepath.Join(ctrlDir, f)); err == nil {
			t.Errorf("GW のディレクトリに %s がある", f)
		}
	}
	for _, f := range []string{fileCACert, pki.IssuerCertFile, pki.IssuerKeyFile, fileSignKey, filePolicyPub, fileControllerCert, fileControllerKey} {
		if _, err := os.Stat(filepath.Join(ctrlDir, f)); err != nil {
			t.Errorf("GW のディレクトリに %s がない", f)
		}
	}
	rootPolicy, _ := os.ReadFile(filepath.Join(rootDir, filePolicyPub))
	gwPolicy, _ := os.ReadFile(filepath.Join(ctrlDir, filePolicyPub))
	if !bytes.Equal(rootPolicy, gwPolicy) {
		t.Error("GW のポリシーの公開鍵が、管理者の手元のものと違う")
	}
	if c := verifyChain(t, rootDir, filepath.Join(ctrlDir, fileControllerCert)); len(c) != 2 {
		t.Errorf("CONTROLLER の証明書の連なり = %d", len(c))
	}
	if c := verifyChain(t, rootDir, filepath.Join(clientDir, fileClientCert)); len(c) != 2 {
		t.Errorf("端末の証明書の連なり = %d", len(c))
	}
	verifyChain(t, rootDir, filepath.Join(rootDir, fileAdminCert))
	root, _ := pki.ReadCertFile(filepath.Join(rootDir, fileCACert))
	if got, _ := pki.ReadCertFile(filepath.Join(clientDir, fileCACert)); !got.Equal(root) {
		t.Error("端末に配った ca.crt がルートの認証局ではない")
	}

	// 取り違えを断る。
	for name, args := range map[string][]string{
		"GW を一段で作り直す":         {"ctl", "init", "-dir", ctrlDir},
		"GW の鍵でルートの署名":        {"ctl", "root", "sign-issuer", "-dir", ctrlDir, "-pub", filepath.Join(ctrlDir, pki.IssuerPubFile), "-out", t.TempDir()},
		"一段の認証局でルートの署名":       {"ctl", "root", "sign-issuer", "-dir", setupSingle(t), "-pub", filepath.Join(ctrlDir, pki.IssuerPubFile), "-out", t.TempDir()},
		"ルートを作り直す":            {"ctl", "root", "init", "-dir", rootDir},
		"1 年より長い発行用の認証局":      {"ctl", "root", "sign-issuer", "-dir", rootDir, "-pub", filepath.Join(ctrlDir, pki.IssuerPubFile), "-out", t.TempDir(), "-validity", "9000h"},
		"-two-tier と -issuer": {"ctl", "init", "-two-tier", "-issuer", rootDir, "-dir", ctrlDir},
	} {
		if code, _, _ := runCmd(t, args...); code == exitOK {
			t.Errorf("%s を受け付けた", name)
		}
	}
	// 別のルートが署名した発行用の認証局の証明書は受け取らない。
	otherRoot := filepath.Join(dir, "other-root")
	otherOut := filepath.Join(dir, "other-out")
	runCmd(t, "ctl", "root", "init", "-dir", otherRoot)
	runCmd(t, "ctl", "root", "sign-issuer", "-dir", otherRoot, "-pub", filepath.Join(ctrlDir, pki.IssuerPubFile), "-out", otherOut)
	if code, _, stderr := runCmd(t, "ctl", "init", "-issuer", otherOut, "-dir", ctrlDir); code == exitOK || !strings.Contains(stderr, "違います") {
		t.Errorf("別のルートの署名を受け取った: %s", stderr)
	}
	// 別の鍵に署名した発行用の認証局の証明書は受け取らない。
	k, _ := keys.Generate()
	keys.SavePublic(filepath.Join(dir, "stranger.pub"), k.Public().(ed25519.PublicKey))
	strangerOut := filepath.Join(dir, "stranger-out")
	runCmd(t, "ctl", "root", "sign-issuer", "-dir", rootDir, "-pub", filepath.Join(dir, "stranger.pub"), "-out", strangerOut)
	if code, _, _ := runCmd(t, "ctl", "init", "-issuer", strangerOut, "-dir", ctrlDir); code == exitOK {
		t.Error("別の鍵の発行用の認証局の証明書を受け取った")
	}

	// 管理者の証明書は、ルートで発行し直す。
	before, _ := pki.ReadCertFile(filepath.Join(rootDir, fileAdminCert))
	if code, stdout, stderr := runCmd(t, "ctl", "root", "admin", "-dir", rootDir); code != exitOK || !strings.Contains(stdout, "発行し直しました") {
		t.Fatalf("ctl root admin: %s %s", stdout, stderr)
	}
	after := verifyChain(t, rootDir, filepath.Join(rootDir, fileAdminCert))[0]
	if after.Equal(before) || !after.PublicKey.(ed25519.PublicKey).Equal(before.PublicKey) {
		t.Error("管理者の証明書を同じ鍵で発行し直していない")
	}
}

// setupSingle は一段の認証局のディレクトリを作る。
func setupSingle(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "single")
	if code, _, stderr := runCmd(t, "ctl", "init", "-dir", d); code != exitOK {
		t.Fatal(stderr)
	}
	return d
}

// 二段構えの GW は、管理者の証明書を更新しない（ルートで更新する）。発行用の認証局の証明書を差し替えたら、
// CONTROLLER の証明書を今の連なりで発行し直す。
func TestRenewOwnCertsTwoTier(t *testing.T) {
	dir := t.TempDir()
	rootDir, ctrlDir, _ := setupTwoTier(t, dir)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	// 管理者の証明書を GW のディレクトリに置いても、発行用の認証局では更新しない。
	adminData, _ := os.ReadFile(filepath.Join(rootDir, fileAdminCert))
	os.WriteFile(filepath.Join(ctrlDir, fileAdminCert), adminData, 0o644)
	ca, err := pki.LoadCA(ctrlDir)
	if err != nil {
		t.Fatal(err)
	}
	if renewed, err := renewOwnCerts(ca, ctrlDir, time.Now(), quiet); err != nil || renewed != nil {
		t.Fatalf("新しい証明書を更新した: %v %v", renewed, err)
	}
	later := time.Now().Add(61 * 24 * time.Hour)
	if renewed, err := renewOwnCerts(ca, ctrlDir, later, quiet); err != nil || renewed == nil {
		t.Fatalf("CONTROLLER の証明書を更新しない: %v %v", renewed, err)
	}
	if data, _ := os.ReadFile(filepath.Join(ctrlDir, fileAdminCert)); !bytes.Equal(data, adminData) {
		t.Error("発行用の認証局で管理者の証明書を更新した")
	}
	if chain, err := pki.ReadChainFile(filepath.Join(ctrlDir, fileControllerCert)); err != nil || len(chain) != 2 || !chain[1].Equal(ca.Cert) {
		t.Errorf("更新した CONTROLLER の証明書の連なり = %d、%v", len(chain), err) // 未来の時刻で発行したので、今の時刻では検証しない
	}

	// 発行用の認証局の証明書を差し替える（同じ鍵に署名し直す）。
	out := filepath.Join(dir, "to-gw-2")
	time.Sleep(1100 * time.Millisecond) // 発行の時刻を変え、新しい証明書にする
	if code, _, stderr := runCmd(t, "ctl", "root", "sign-issuer", "-dir", rootDir, "-pub", filepath.Join(ctrlDir, pki.IssuerPubFile), "-out", out, "-validity", "2000h"); code != exitOK {
		t.Fatal(stderr)
	}
	if code, stdout, stderr := runCmd(t, "ctl", "init", "-issuer", out, "-dir", ctrlDir); code != exitOK || !strings.Contains(stdout, "差し替えました") {
		t.Fatalf("差し替え: %s %s", stdout, stderr)
	}
	ca, err = pki.LoadCA(ctrlDir)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := renewOwnCerts(ca, ctrlDir, time.Now(), quiet)
	if err != nil || renewed == nil {
		t.Fatalf("差し替えの後に CONTROLLER の証明書を発行し直さない: %v %v", renewed, err)
	}
	chain := verifyChain(t, rootDir, filepath.Join(ctrlDir, fileControllerCert))
	if !chain[1].Equal(ca.Cert) || renewed.NotAfter.After(ca.Cert.NotAfter) {
		t.Errorf("連なり = %v、期限 %v", chain[1].NotAfter, renewed.NotAfter)
	}
	// 期限が近いと知らせる。
	if warnIssuerExpiry(ca, time.Now(), quiet) || !warnIssuerExpiry(ca, ca.Cert.NotAfter.Add(-24*time.Hour), quiet) {
		t.Error("発行用の認証局の期限の知らせ")
	}
}

// 二段構えの GW に、ルートの発行した管理者の証明書で操作できる。発行用の認証局の鍵で作った管理者の証明書は断る。
func TestTwoTierGW(t *testing.T) {
	dir := t.TempDir()
	rootDir, ctrlDir, _ := setupTwoTier(t, dir)
	addr := freePort(t)
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "policy.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(dir, "policy.json"), pol)
	no := false
	writeJSON(t, filepath.Join(dir, "gw.json"), gwConfig{Listen: addr, PKIDir: "controller", StateDir: "gw-state", Policy: "policy.json", Enforce: &no})
	ctx, cancel := context.WithCancel(context.Background())
	var gwErr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"gw", "-config", filepath.Join(dir, "gw.json")}, &bytes.Buffer{}, &gwErr)
	}()
	defer func() {
		cancel()
		<-done
		if t.Failed() {
			t.Logf("GW のログ:\n%s", gwErr.String())
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	var stdout, stderr string
	for code := -1; code != exitOK; code, stdout, stderr = runCmd(t, "ctl", "status", "-dir", rootDir, "-server", addr) {
		if time.Now().After(deadline) {
			t.Fatalf("ルートの管理者の証明書で操作できない: %s", stderr)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(stdout, "発行用の認証局の期限") {
		t.Errorf("ctl status に発行用の認証局の期限がない: %s", stdout)
	}

	// GW を乗っ取った者が、発行用の認証局の鍵で管理者の証明書を作っても、操作できない。
	forgedDir := filepath.Join(dir, "forged")
	os.MkdirAll(forgedDir, 0o700)
	issuerKey, err := keys.LoadPrivate(filepath.Join(ctrlDir, pki.IssuerKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	issuerCert, _ := pki.ReadCertFile(filepath.Join(ctrlDir, pki.IssuerCertFile))
	adminKey, _ := keys.Generate()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: "evil", OrganizationalUnit: []string{string(pki.RoleAdmin)}, Organization: []string{"susanoo"}},
		NotBefore:    time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{pki.Identity{Role: pki.RoleAdmin, ID: "evil"}.URI()},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuerCert, adminKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	forged, _ := x509.ParseCertificate(der)
	pki.WriteChainFile(filepath.Join(forgedDir, fileAdminCert), forged, issuerCert)
	keys.SavePrivate(filepath.Join(forgedDir, fileAdminKey), adminKey)
	rootData, _ := os.ReadFile(filepath.Join(rootDir, fileCACert)) // サーバーの検証には本物のルートを使う
	os.WriteFile(filepath.Join(forgedDir, fileCACert), rootData, 0o644)
	if code, stdout, stderr := runCmd(t, "ctl", "status", "-dir", forgedDir, "-server", addr); code == exitOK {
		t.Errorf("偽の管理者の証明書で操作できた: %s", stdout)
	} else if strings.Contains(stderr, "403") {
		t.Errorf("TLS で断らず、HTTP で断った: %s", stderr)
	}
}
