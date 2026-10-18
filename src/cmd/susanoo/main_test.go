package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/config"
	"susanoo/internal/pki"
	"susanoo/internal/policy"
)

func runCmd(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{"引数なし", nil, exitUsage, "", "使い方:"},
		{"版数", []string{"version"}, exitOK, "susanoo ", ""},
		{"説明", []string{"help"}, exitOK, "使い方:", ""},
		{"CONTROLLER 単独", []string{"controller"}, exitError, "", "susanoo gw"},
		{"不明なモード", []string{"router"}, exitUsage, "", "不明なモードです: router"},
		{"不明な ctl の操作", []string{"ctl", "x"}, exitUsage, "", "不明な操作です"},
		{"設定ファイルなし", []string{"gw", "-config", "/nonexistent/gw.json"}, exitError, "", "no such file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runCmd(t, tt.args...)
			if code != tt.wantCode {
				t.Errorf("終了コード = %d, 期待値 %d", code, tt.wantCode)
			}
			if !strings.Contains(stdout, tt.wantStdout) {
				t.Errorf("標準出力 = %q, %q を含むはず", stdout, tt.wantStdout)
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("標準エラー出力 = %q, %q を含むはず", stderr, tt.wantStderr)
			}
		})
	}
}

func TestExampleConfigs(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "config")
	var g gwConfig
	if err := config.Load(filepath.Join(dir, "gw.example.json"), &g); err != nil {
		t.Error(err)
	}
	if g.Separation == nil || !*g.Separation || g.ControllerUser != defaultControllerUser || g.LANUser != defaultLANUser {
		t.Errorf("GW の権限の分離の例 = %v %q %q", g.Separation, g.ControllerUser, g.LANUser)
	}
	var c clientConfig
	if err := config.Load(filepath.Join(dir, "client.example.json"), &c); err != nil {
		t.Error(err)
	}
	if len(c.Honeytokens) != 4 {
		t.Errorf("おとりの例 = %v", c.Honeytokens)
	}
	if c.Separation == nil || !*c.Separation || c.User != defaultAnalyzerUser {
		t.Errorf("権限の分離の例 = %v %q", c.Separation, c.User)
	}
}

// setup は ctl init、client keygen、ctl issue で、CONTROLLER と端末の鍵と証明書を用意する。
func setup(t *testing.T, dir string) (ctrlDir, clientDir string) {
	t.Helper()
	ctrlDir = filepath.Join(dir, "controller")
	clientDir = filepath.Join(dir, "client")
	steps := [][]string{
		{"ctl", "init", "-dir", ctrlDir},
		{"client", "keygen", "-dir", clientDir},
		{"ctl", "issue", "-dir", ctrlDir, "-id", "pc-001", "-pub", filepath.Join(clientDir, fileClientPub), "-out", clientDir},
	}
	for _, args := range steps {
		if code, _, stderr := runCmd(t, args...); code != exitOK {
			t.Fatalf("%v: %s", args, stderr)
		}
	}
	return ctrlDir, clientDir
}

func TestSetup(t *testing.T) {
	dir := t.TempDir()
	ctrlDir, clientDir := setup(t, dir)

	cert, err := pki.ReadCertFile(filepath.Join(clientDir, fileClientCert))
	if err != nil {
		t.Fatal(err)
	}
	id, err := pki.IdentityFromCert(cert)
	if err != nil || id != (pki.Identity{Role: pki.RoleClient, ID: "pc-001"}) {
		t.Errorf("端末の証明書の持ち主 = %v, %v", id, err)
	}
	signPub, _ := os.ReadFile(filepath.Join(ctrlDir, fileSignPub))
	commandPub, _ := os.ReadFile(filepath.Join(clientDir, fileCommandPub))
	if len(signPub) == 0 || !bytes.Equal(signPub, commandPub) {
		t.Error("端末に配った指示の検証用の鍵が、CONTROLLER の署名の鍵と違う")
	}
	for _, f := range []string{
		filepath.Join(ctrlDir, fileCAKey), filepath.Join(ctrlDir, fileSignKey),
		filepath.Join(ctrlDir, fileControllerKey), filepath.Join(ctrlDir, fileAdminKey),
		filepath.Join(clientDir, fileClientKey),
	} {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s の権限 = %v", f, fi.Mode().Perm())
		}
	}

	// 既にある鍵は作り直さない。
	if code, _, _ := runCmd(t, "ctl", "init", "-dir", ctrlDir); code != exitError {
		t.Error("認証局を上書きできた")
	}
	if code, _, _ := runCmd(t, "client", "keygen", "-dir", clientDir); code != exitError {
		t.Error("端末の鍵を上書きできた")
	}
	if code, _, _ := runCmd(t, "ctl", "issue", "-dir", ctrlDir, "-id", "PC 001", "-pub", filepath.Join(clientDir, fileClientPub), "-out", dir); code != exitError {
		t.Error("不正な端末 ID に証明書を発行できた")
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// TestGWAndClient は GW と CLIENT を実際に起動し、おとりへの接触から隔離までを確かめる。
// root 権限を使わないため、GW の遮断（nft）と自己隔離は無効にし、おとりは inotify で監視する。
// 通信はループバック（127.0.0.1）だけで行う。
func TestGWAndClient(t *testing.T) {
	dir := t.TempDir()
	ctrlDir, _ := setup(t, dir)
	addr := freePort(t)

	data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "policy.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	pol.Response = policy.ResponseEnforce
	writeJSON(t, filepath.Join(dir, "policy.json"), pol)
	no := false
	writeJSON(t, filepath.Join(dir, "gw.json"), gwConfig{
		Listen: addr, PKIDir: "controller", StateDir: "gw-state", Policy: "policy.json", Enforce: &no,
	})
	token := filepath.Join(dir, "home", ".aws", "credentials")
	writeJSON(t, filepath.Join(dir, "client.json"), map[string]any{
		"controller":         addr,
		"pki_dir":            "client",
		"state_dir":          "client-state",
		"heartbeat_interval": "100ms",
		"honeytokens":        []map[string]string{{"path": token, "kind": "aws"}},
		"isolation":          false,
		// この試験はおとりから隔離までを確かめる。手元の PC のプロセスや接続の一覧、ホームのファイルは見ない。
		"process_monitor":    false,
		"connection_monitor": false,
		"files":              map[string]any{"watch": []string{}, "protect": []string{}},
	})

	ctx, cancel := context.WithCancel(context.Background())
	var gwErr, clientErr bytes.Buffer
	done := make(chan int, 2)
	go func() {
		done <- run(ctx, []string{"gw", "-config", filepath.Join(dir, "gw.json")}, &bytes.Buffer{}, &gwErr)
	}()
	defer func() {
		cancel()
		<-done
		<-done
		if t.Failed() {
			t.Logf("GW のログ:\n%s\nCLIENT のログ:\n%s", gwErr.String(), clientErr.String())
		}
	}()

	devices := func() map[string]api.Device {
		code, stdout, _ := runCmd(t, "ctl", "devices", "-dir", ctrlDir, "-server", addr, "-json")
		if code != exitOK {
			return nil
		}
		var list []api.Device
		json.Unmarshal([]byte(stdout), &list)
		out := map[string]api.Device{}
		for _, d := range list {
			out[d.ID] = d
		}
		return out
	}
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
	waitFor("GW の起動", func() bool { return devices() != nil })

	go func() {
		done <- run(ctx, []string{"client", "-config", filepath.Join(dir, "client.json")}, &bytes.Buffer{}, &clientErr)
	}()
	waitFor("端末の登録", func() bool { _, ok := devices()["pc-001"]; return ok })

	// 別のプロセスがおとりを読む。
	if out, err := exec.Command("cat", token).CombinedOutput(); err != nil {
		t.Fatalf("おとりを読めない: %v %s", err, out)
	}
	waitFor("隔離", func() bool { return devices()["pc-001"].Isolation != "" })
	d := devices()["pc-001"]
	if d.Isolation != policy.IsolateManagementAndUpdates || d.Reason != "おとりへの接触" {
		t.Errorf("台帳 = %+v", d)
	}

	code, stdout, stderr := runCmd(t, "ctl", "release", "pc-001", "-dir", ctrlDir, "-server", addr)
	if code != exitOK || !strings.Contains(stdout, "pc-001") {
		t.Fatalf("解除できない: %s %s", stdout, stderr)
	}
	if got := devices()["pc-001"].Isolation; got != "" {
		t.Errorf("解除後の隔離 = %q", got)
	}

	// 全体の状態と、イベントの検索（M8）。
	code, stdout, stderr = runCmd(t, "ctl", "status", "-dir", ctrlDir, "-server", addr)
	if code != exitOK || !strings.Contains(stdout, "端末") || !strings.Contains(stdout, "1 台") || !strings.Contains(stdout, "おとりへの接触") {
		t.Errorf("ctl status: %s %s", stdout, stderr)
	}
	code, stdout, stderr = runCmd(t, "ctl", "events", "-device", "pc-001", "-class", "finding", "-since", "1h", "-dir", ctrlDir, "-server", addr)
	if code != exitOK || !strings.Contains(stdout, "おとりへの接触") || !strings.Contains(stdout, "pc-001") {
		t.Errorf("ctl events: %s %s", stdout, stderr)
	}
	code, stdout, _ = runCmd(t, "ctl", "events", "-device", "pc-999", "-dir", ctrlDir, "-server", addr)
	if code != exitOK || !strings.Contains(stdout, "条件に合うイベントはありません") {
		t.Errorf("ほかの端末のイベント: %s", stdout)
	}
	if code, _, _ := runCmd(t, "ctl", "events", "-class", "login", "-dir", ctrlDir, "-server", addr); code != exitError {
		t.Error("知らない種類で検索できた")
	}
}

func TestWatchFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changed := make(chan string, 4)
	go watchFiles(ctx, []string{path}, 10*time.Millisecond, func(p string) { changed <- p })
	time.Sleep(50 * time.Millisecond)
	select {
	case p := <-changed:
		t.Fatalf("変更していないのに知らせた: %s", p)
	default:
	}
	if err := os.WriteFile(path, []byte("2"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-changed:
		if p != path {
			t.Errorf("知らせたファイル = %s", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("変更を知らせない")
	}
}

func TestGWConfigRequiresRouterForDHCP(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "gw.json"), map[string]any{
		"listen": "127.0.0.1:8443", "pki_dir": "controller", "state_dir": "state", "policy": "policy.json",
		"dhcp": map[string]any{"range": "10.0.0.100-10.0.0.199"},
	})
	code, _, stderr := runCmd(t, "gw", "-config", filepath.Join(dir, "gw.json"))
	if code != exitError || !strings.Contains(stderr, "router の設定が必要") {
		t.Errorf("終了コード = %d, %s", code, stderr)
	}
}
