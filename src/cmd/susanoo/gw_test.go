//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/keys"
	"susanoo/internal/pki"
	"susanoo/internal/policy"
	"susanoo/internal/privsep"
)

// GW の執行部と CONTROLLER のプロセスを、同じプロセスの中で socketpair でつなぐ（setuid と capability の絞り込みと、
// LAN 側の処理は make lab-test で確かめる）。CONTROLLER は、執行部から受け取った設定、鍵、受け継いだ待ち受けで動く。
func TestGWControllerOverPrivsep(t *testing.T) {
	dir := t.TempDir()
	ctrlDir, _ := setup(t, dir)
	addr := freePort(t)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	policyData, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "policy.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Parse(policyData)
	if err != nil {
		t.Fatal(err)
	}
	no := false
	cfg := gwConfig{Listen: addr, PKIDir: "controller", StateDir: "gw-state", Policy: "policy.json", Enforce: &no}
	stateDir := filepath.Join(dir, "gw-state")
	for _, d := range []string{controllerDir(stateDir), lanDir(stateDir)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 執行部の準備（ルーター方式を使わないので root は要らない）。
	g, err := prepareGW(ctx, cfg, pol, netip.MustParseAddrPort(addr), quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer g.files.close()
	ca, err := loadCA(ctrlDir)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := loadLeaf(ctrlDir, fileControllerCert, fileControllerKey)
	if err != nil {
		t.Fatal(err)
	}
	signKey, err := keys.LoadPrivate(filepath.Join(ctrlDir, fileSignKey))
	if err != nil {
		t.Fatal(err)
	}
	rulesKey, err := keys.LoadPublic(filepath.Join(ctrlDir, filePolicyPub))
	if err != nil {
		t.Fatal(err)
	}
	hello := gwControllerHello{
		Config: cfg, Policy: policyData, CA: ca.Raw, Chain: cert.Certificate, Key: cert.PrivateKey.(ed25519.PrivateKey),
		SignKey: signKey, RulesKey: rulesKey, StateDir: stateDir, Files: map[string]int{},
	}
	// 同じプロセスの中では、受け継ぐ fd の番号として、複製した fd の番号を渡す。
	for _, e := range g.files.controllerEntries() {
		if *e.file != nil {
			fd, err := syscall.Dup(int((*e.file).Fd()))
			if err != nil {
				t.Fatal(err)
			}
			hello.Files[e.name] = fd
		}
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	ours, theirs := os.NewFile(uintptr(fds[0]), "executor"), os.NewFile(uintptr(fds[1]), "worker")
	changes := make(chan string, 1)
	exDone := make(chan error, 1)
	go func() {
		exDone <- privsep.ServeGW(ctx, ours, privsep.GWExecutor{}, hello, privsep.GWNotices{Changes: changes}, quiet)
	}()
	workerDone := make(chan error, 1)
	go func() { workerDone <- serveGWController(theirs, quiet) }()

	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("%s を待ちきれない", what)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	waitFor("CONTROLLER の起動", func() bool {
		code, _, _ := runCmd(t, "ctl", "devices", "-dir", ctrlDir, "-server", addr, "-json")
		return code == exitOK
	})

	// 執行部が見つけた設定ファイルの変更は、CONTROLLER が監査ログに残す。
	changes <- filepath.Join(dir, "gw.json")
	auditLog := filepath.Join(controllerDir(stateDir), "audit.log")
	waitFor("設定の変更の記録", func() bool {
		_, out, _ := runCmd(t, "ctl", "audit", "-file", auditLog, "-json")
		return strings.Contains(out, "gw.json")
	})

	// 執行部が止まると、CONTROLLER も止まる。
	cancel()
	if err := <-exDone; err != nil {
		t.Errorf("ServeGW の結果 = %v", err)
	}
	select {
	case err := <-workerDone:
		if err != nil {
			t.Errorf("CONTROLLER の結果 = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("執行部が止まっても CONTROLLER が止まらない")
	}
}

// GW は、CONTROLLER と管理者の証明書の有効期間の残りが 3 分の 1 を切ったら、同じ鍵で更新する。
func TestRenewOwnCerts(t *testing.T) {
	dir := t.TempDir()
	ctrlDir, _ := setup(t, dir)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	ca, err := pki.LoadCA(ctrlDir)
	if err != nil {
		t.Fatal(err)
	}
	// ctl init が作った証明書は新しいので、更新しない。
	if renewed, err := renewOwnCerts(ca, ctrlDir, time.Now(), quiet); err != nil || renewed != nil {
		t.Fatalf("更新した証明書 = %v、エラー %v", renewed, err)
	}
	before, err := pki.ReadCertFile(filepath.Join(ctrlDir, fileControllerCert))
	if err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(61 * 24 * time.Hour)
	renewed, err := renewOwnCerts(ca, ctrlDir, later, quiet)
	if err != nil || renewed == nil {
		t.Fatalf("更新した証明書 = %v、エラー %v", renewed, err)
	}
	for _, file := range []string{fileControllerCert, fileAdminCert} {
		c, err := pki.ReadCertFile(filepath.Join(ctrlDir, file))
		if err != nil {
			t.Fatal(err)
		}
		if !c.NotAfter.After(later.Add(80 * 24 * time.Hour)) {
			t.Errorf("%s の期限 = %v", file, c.NotAfter)
		}
	}
	if !renewed.PublicKey.(ed25519.PublicKey).Equal(before.PublicKey) {
		t.Error("CONTROLLER の鍵が変わった")
	}
	// 更新した後も、CONTROLLER の証明書と鍵は組で読める。
	if _, err := loadLeaf(ctrlDir, fileControllerCert, fileControllerKey); err != nil {
		t.Error(err)
	}
}

// ctl policy で、ポリシーを署名して配布し、先行適用、全体への適用、過去の版への巻き戻しができる。
// GW は、ポリシーの署名の鍵で署名していない版と、受け付けた版数以下の版を受け付けない。
func TestPolicyCommands(t *testing.T) {
	dir := t.TempDir()
	ctrlDir, _ := setup(t, dir)
	addr := freePort(t)
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
	defer func() {
		cancel()
		<-done
		if t.Failed() {
			t.Logf("GW のログ:\n%s", gwErr.String())
		}
	}()
	ctl := func(args ...string) (int, string, string) {
		t.Helper()
		return runCmd(t, append(append([]string{"ctl", "policy"}, args...), "-dir", ctrlDir, "-server", addr)...)
	}
	deadline := time.Now().Add(10 * time.Second)
	for code, _, _ := ctl("list"); code != exitOK; code, _, _ = ctl("list") {
		if time.Now().After(deadline) {
			t.Fatal("GW が起動しない")
		}
		time.Sleep(50 * time.Millisecond)
	}
	info := func() api.PolicyInfo {
		t.Helper()
		code, out, errOut := ctl("list", "-json")
		var info api.PolicyInfo
		if code != exitOK || json.Unmarshal([]byte(out), &info) != nil {
			t.Fatalf("ctl policy list: %s %s", out, errOut)
		}
		return info
	}

	// 名前を変えた版を pc-001 にだけ先に適用し、全体に広げる。
	renamed := strings.Replace(string(data), `"name": "標準（学習モード）"`, `"name": "検証の版"`, 1)
	if renamed == string(data) {
		t.Fatal("例のポリシーの名前が変わった")
	}
	if err := os.WriteFile(filepath.Join(dir, "v2.json"), []byte(renamed), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := ctl("push", filepath.Join(dir, "v2.json"), "-canary", "pc-001"); code != exitOK || !strings.Contains(out, "先行適用") {
		t.Fatalf("先行適用: %s %s", out, errOut)
	}
	if i := info(); i.Current.Version != 1 || i.Canary == nil || i.Canary.Version != 2 {
		t.Fatalf("先行適用の後の状態 = %+v", i)
	}
	if code, _, errOut := ctl("promote"); code != exitOK {
		t.Fatalf("全体への適用: %s", errOut)
	}
	if code, out, _ := ctl("show"); code != exitOK || !strings.Contains(out, "検証の版") || !strings.Contains(out, `"version": 2`) {
		t.Errorf("今の版の中身 = %s", out)
	}

	// 過去の版の中身に戻す（版数は 3 になる）。
	if code, out, errOut := ctl("rollback", "1"); code != exitOK || !strings.Contains(out, "版 3") {
		t.Fatalf("巻き戻し: %s %s", out, errOut)
	}
	if i := info(); i.Current.Version != 3 || len(i.Versions) != 3 || i.Current.Name != "標準（学習モード）" {
		t.Errorf("巻き戻した後の状態 = %+v", i)
	}

	// ポリシーの署名の鍵を別のものに替えると、GW は受け付けない。
	os.Remove(filepath.Join(ctrlDir, filePolicyKey))
	os.Rename(filepath.Join(ctrlDir, filePolicyPub), filepath.Join(ctrlDir, filePolicyPub+".orig"))
	if code, _, _ := runCmd(t, "ctl", "policy", "keygen", "-dir", ctrlDir); code != exitOK {
		t.Fatal("鍵を作れない")
	}
	if code, _, errOut := ctl("push", filepath.Join(dir, "v2.json")); code == exitOK || !strings.Contains(errOut, "署名") {
		t.Errorf("別の鍵の署名を受け付けた: %s", errOut)
	}
	if i := info(); i.Current.Version != 3 {
		t.Errorf("断った後の版 = %d", i.Current.Version)
	}
}
