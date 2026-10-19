//go:build lab

package lab

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// readChain は PEM 形式の証明書の連なりを読む。
func readChain(t *testing.T, path string) []*x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var chain []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		t.Fatalf("%s に証明書がありません", path)
	}
	return chain
}

// TestTwoTierPKI は、二段構えの鍵（M1。ルートの認証局の鍵とポリシーの署名の鍵を GW の外に置く）を確かめる。
// GW は発行用の認証局の鍵だけを持ち、その鍵で管理者の証明書を作っても操作できない。端末の証明書は連なりごと配り、更新する。
func TestTwoTierPKI(t *testing.T) {
	if *susanooBin == "" {
		t.Fatal("-susanoo で susanoo の実行ファイルを指定してください")
	}
	pc := &machine{ns: "sus-c1", id: "pc-001", agent: true, port: "p-c1"}
	l := &lab{t: t, dir: t.TempDir()}
	buildTopology(t, []*machine{pc})
	l.init() // DHCP のスクリプトなど。一段の認証局は使わない
	rootDir := filepath.Join(l.dir, "root")
	l.ctrlDir = filepath.Join(l.dir, "controller2")
	l.adminDir = rootDir
	toGW := filepath.Join(l.dir, "to-gw")

	t.Log("段階1: 管理者の手元でルートの認証局を作り、GW の発行用の認証局の公開鍵に署名する。GW にはルートの鍵もポリシーの署名の鍵も置かない")
	l.susanoo("ctl", "root", "init", "-dir", rootDir)
	l.susanoo("ctl", "init", "-two-tier", "-dir", l.ctrlDir)
	l.susanoo("ctl", "root", "sign-issuer", "-dir", rootDir, "-pub", filepath.Join(l.ctrlDir, "issuer.pub"), "-out", toGW)
	l.susanoo("ctl", "init", "-issuer", toGW, "-dir", l.ctrlDir)
	for _, f := range []string{"ca.key", "policy.key", "admin.key", "admin.crt"} {
		if _, err := os.Stat(filepath.Join(l.ctrlDir, f)); err == nil {
			t.Errorf("GW のディレクトリに %s があります", f)
		}
	}
	if c := readChain(t, filepath.Join(l.ctrlDir, "controller.crt")); len(c) != 2 {
		t.Errorf("CONTROLLER の証明書の連なり = %d 個", len(c))
	}
	l.writeGW([]map[string]any{{"name": "default", "egress": map[string]any{"default": "allow"}, "isolation": "management"}}, map[string]any{"pki_dir": "controller2"})
	keyDir := filepath.Join(l.dir, pc.id)
	l.susanoo("client", "keygen", "-dir", keyDir)
	l.susanoo("ctl", "issue", "-dir", l.ctrlDir, "-id", pc.id, "-pub", filepath.Join(keyDir, "client.pub"), "-out", keyDir, "-validity", "40s")
	if c := readChain(t, filepath.Join(keyDir, "client.crt")); len(c) != 2 {
		t.Errorf("端末の証明書の連なり = %d 個", len(c))
	}
	writeJSON(t, filepath.Join(l.dir, pc.id+".json"), map[string]any{
		"controller": controllerAddr, "pki_dir": pc.id, "state_dir": pc.id + "-state", "heartbeat_interval": "1s",
		"files":          map[string]any{"watch": []string{}, "persistence": []string{}, "privilege": []string{}, "sensitive": []map[string]any{}, "protect": []string{}},
		"kernel_modules": false,
	})

	t.Log("段階2: 権限を分けた GW が二段構えの鍵で起動し、ルートの発行した管理者の証明書で操作できる。端末は連なりを示して登録する")
	gw := start(t, "GW", nsGW, nil, *susanooBin, "gw", "-config", filepath.Join(l.dir, "gw.json"))
	waitFor(t, "GW の起動", 10*time.Second, func() bool { return l.devices() != nil })
	l.dhcp(pc)
	agent := start(t, "CLIENT "+pc.id, pc.ns, nil, *susanooBin, "client", "-config", filepath.Join(l.dir, pc.id+".json"))
	waitFor(t, "端末の登録", 15*time.Second, func() bool { return !l.devices()[pc.id].LastSeen.IsZero() })
	status := func() string {
		out, err := inNS(nsGW, *susanooBin, "ctl", "status", "-dir", rootDir, "-server", controllerAddr).CombinedOutput()
		if err != nil {
			t.Fatalf("ctl status: %v %s", err, out)
		}
		return string(out)
	}
	if out := status(); !strings.Contains(out, "発行用の認証局の期限") {
		t.Errorf("ctl status に発行用の認証局の期限がありません:\n%s", out)
	}

	t.Log("段階3: ポリシーは管理者の手元の鍵で署名して配布できる。GW のディレクトリには署名の鍵がないので配布できない")
	policyPath := filepath.Join(l.dir, "policy-v2.json")
	writeJSON(t, policyPath, map[string]any{
		"version": 1, "name": "二段構え", "issued_at": time.Now().UTC(), "response": "enforce", "on_failure": "fail_open",
		"groups": []map[string]any{{"name": "default", "egress": map[string]any{"default": "allow"}, "isolation": "management"}},
	})
	if out, err := inNS(nsGW, *susanooBin, "ctl", "policy", "push", policyPath, "-dir", rootDir, "-server", controllerAddr).CombinedOutput(); err != nil {
		t.Fatalf("管理者の手元から配布できません: %v %s", err, out)
	}
	if out, err := inNS(nsGW, *susanooBin, "ctl", "policy", "push", policyPath, "-dir", l.ctrlDir, "-server", controllerAddr).CombinedOutput(); err == nil {
		t.Errorf("GW のディレクトリから配布できました: %s", out)
	}
	if out := status(); !strings.Contains(out, "二段構え") {
		t.Errorf("配布したポリシーが今の版になっていません:\n%s", out)
	}

	t.Log("段階4: GW を乗っ取った者が発行用の認証局の鍵で管理者の証明書を作っても、名前の制約で TLS の段階で断られる")
	forgedDir := filepath.Join(l.dir, "forged")
	if err := os.MkdirAll(forgedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPEM, _ := pem.Decode(mustRead(t, filepath.Join(l.ctrlDir, "issuer.key")))
	if keyPEM == nil {
		t.Fatal("issuer.key を読めません")
	}
	k, err := x509.ParsePKCS8PrivateKey(keyPEM.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	issuerKey := k.(ed25519.PrivateKey)
	issuerCert := readChain(t, filepath.Join(l.ctrlDir, "issuer.crt"))[0]
	adminPub, adminPriv, _ := ed25519.GenerateKey(rand.Reader)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "evil", OrganizationalUnit: []string{"admin"}, Organization: []string{"susanoo"}},
		NotBefore:    time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{{Scheme: "susanoo", Host: "admin", Path: "/evil"}},
	}, issuerCert, adminPub, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	var certPEM []byte
	certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerCert.Raw})...)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(adminPriv)
	for name, data := range map[string][]byte{
		"admin.crt": certPEM,
		"admin.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
		"ca.crt":    mustRead(t, filepath.Join(rootDir, "ca.crt")),
	} {
		if err := os.WriteFile(filepath.Join(forgedDir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, err := inNS(nsGW, *susanooBin, "ctl", "status", "-dir", forgedDir, "-server", controllerAddr).CombinedOutput()
	if err == nil {
		t.Errorf("偽の管理者の証明書で操作できました:\n%s", out)
	} else if strings.Contains(string(out), "403") {
		t.Errorf("TLS の段階で断らず、HTTP で断りました: %s", out)
	}
	if _, err := inNS(nsGW, *susanooBin, "ctl", "init", "-dir", l.ctrlDir).CombinedOutput(); err == nil {
		t.Error("二段構えの GW のディレクトリに一段の認証局を作れました")
	}

	t.Log("段階5: 有効期間の短い端末の証明書は、発行用の認証局の証明書を連ねて更新し、起動し直した CLIENT もその連なりで接続できる")
	farFuture := time.Now().Add(80 * 24 * time.Hour)
	waitFor(t, "証明書の更新", 40*time.Second, func() bool { return l.devices()[pc.id].CertExpiry.After(farFuture) })
	chain := readChain(t, filepath.Join(keyDir, "client.crt"))
	if len(chain) != 2 || !chain[0].NotAfter.After(farFuture) || !chain[1].Equal(issuerCert) {
		t.Errorf("更新した端末の証明書のファイル = %d 個、期限 %v", len(chain), chain[0].NotAfter)
	}
	if actions := l.auditActions(); !slices.Contains(actions, "device.renew:"+pc.id) {
		t.Errorf("監査ログに device.renew:%s がありません: %v", pc.id, actions)
	}
	agent.stop(syscall.SIGTERM)
	restarted := time.Now()
	agent = start(t, "CLIENT "+pc.id+"（起動し直し）", pc.ns, nil, *susanooBin, "client", "-config", filepath.Join(l.dir, pc.id+".json"))
	waitFor(t, "起動し直した CLIENT の接続", 15*time.Second, func() bool { return l.devices()[pc.id].LastSeen.After(restarted) })

	t.Log("段階6: 発行用の認証局の証明書を署名し直して差し替え、GW を起動し直すと、CONTROLLER の証明書を新しい連なりで発行し直す")
	toGW2 := filepath.Join(l.dir, "to-gw-2")
	l.susanoo("ctl", "root", "sign-issuer", "-dir", rootDir, "-pub", filepath.Join(l.ctrlDir, "issuer.pub"), "-out", toGW2, "-validity", "2000h")
	if out := l.susanoo("ctl", "init", "-issuer", toGW2, "-dir", l.ctrlDir); !strings.Contains(out, "差し替えました") {
		t.Errorf("ctl init -issuer の出力: %s", out)
	}
	newIssuer := readChain(t, filepath.Join(l.ctrlDir, "issuer.crt"))[0]
	gw.stop(syscall.SIGTERM)
	gwRestarted := time.Now()
	start(t, "GW（起動し直し）", nsGW, nil, *susanooBin, "gw", "-config", filepath.Join(l.dir, "gw.json"))
	waitFor(t, "GW の起動し直し", 10*time.Second, func() bool { return l.devices() != nil })
	if c := readChain(t, filepath.Join(l.ctrlDir, "controller.crt")); len(c) != 2 || !c[1].Equal(newIssuer) {
		t.Errorf("CONTROLLER の証明書が新しい連なりになっていません（%d 個）", len(c))
	}
	if out := status(); !strings.Contains(out, newIssuer.NotAfter.Local().Format("2006-01-02")) {
		t.Errorf("ctl status の発行用の認証局の期限が新しくなっていません:\n%s", out)
	}
	// 端末は、古い発行用の認証局の証明書を連ねた証明書のまま接続を続ける（古い証明書も期限内）。
	waitFor(t, "GW を起動し直した後の端末の接続", 20*time.Second, func() bool { return l.devices()[pc.id].LastSeen.After(gwRestarted) })
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
