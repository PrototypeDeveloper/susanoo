package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startConsole は、設定ファイル path の Web コンソールを試験用のサーバーで動かす。
func startConsole(t *testing.T, path, kind, service string) (*consoleServer, *httptest.Server, *http.Client) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := newConsoleServer(path, kind, service, ln.Addr().(*net.TCPAddr).Port, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: s.handler()}}
	srv.Start()
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return s, srv, &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func consolePost(t *testing.T, c *http.Client, srv *httptest.Server, path string, body any, origin string) (int, map[string]any) {
	t.Helper()
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// Web コンソールは、合言葉の入った URL で開いた後だけ、設定を読み、確かめ、控えを残して保存し、サービスを起動し直す。
func TestConsole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gw.json")
	orig := `{"listen": "192.168.10.1:8443", "pki_dir": "controller", "state_dir": "state", "policy": "policy.json",
	  "router": {"lan": "lan0", "wan": "wan0"}, "dhcp": {"range": "192.168.10.100-192.168.10.199"}}`
	os.WriteFile(path, []byte(orig), 0o600)
	os.Mkdir(filepath.Join(dir, "controller"), 0o700)
	os.WriteFile(filepath.Join(dir, "policy.json"), []byte("{}"), 0o600)
	s, srv, c := startConsole(t, path, "gw", "susanoo-gw")
	var restarted []string
	s.restart = func(_ context.Context, svc string) (string, error) {
		restarted = append(restarted, svc)
		return "", nil
	}
	s.active = func(context.Context, string) string { return "active" }
	origin := srv.URL

	// 合言葉のない要求は断る。
	for _, p := range []string{"/", "/api/config", "/?token=wrong"} {
		resp, err := c.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s の応答 = %d", p, resp.StatusCode)
		}
	}
	// 合言葉の入った URL で開くと、クッキーを付けて合言葉のない URL に移す。
	resp, err := c.Get(srv.URL + "/?token=" + s.token)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" || !strings.Contains(resp.Header.Get("Set-Cookie"), "SameSite=Strict") {
		t.Fatalf("合言葉の URL の応答 = %d %v", resp.StatusCode, resp.Header)
	}
	resp, _ = c.Get(srv.URL + "/")
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(page), "console.js") || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("画面 = %d %s", resp.StatusCode, page)
	}
	for _, asset := range []string{"/console.js", "/console.css"} {
		resp, _ := c.Get(srv.URL + asset)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s の応答 = %d", asset, resp.StatusCode)
		}
	}
	resp, _ = c.Get(srv.URL + "/api/config")
	var cfg consoleConfig
	json.NewDecoder(resp.Body).Decode(&cfg)
	resp.Body.Close()
	if cfg.Kind != "gw" || cfg.Text != orig || cfg.Active != "active" || len(cfg.Fields) == 0 || cfg.Fields[0].Path != "listen" {
		t.Fatalf("設定 = %+v", cfg)
	}

	// 書き換える要求は、同じ画面（Origin）からだけ受け付ける。
	if status, _ := consolePost(t, c, srv, "/api/check", consoleRequest{Text: orig}, ""); status != http.StatusForbidden {
		t.Errorf("Origin のない要求 = %d", status)
	}
	if status, _ := consolePost(t, c, srv, "/api/check", consoleRequest{Text: orig}, "http://evil.example"); status != http.StatusForbidden {
		t.Errorf("ほかのサイトからの要求 = %d", status)
	}
	// 検証は起動のときと同じ。
	for name, text := range map[string]string{
		"JSON の形":         `{"listen": `,
		"知らない項目":          `{"listen": "192.168.10.1:8443", "pki_dir": "c", "state_dir": "s", "policy": "p", "unknown": 1}`,
		"router と bridge": `{"listen": "192.168.10.1:8443", "pki_dir": "c", "state_dir": "s", "policy": "p", "router": {"lan": "a", "wan": "b"}, "bridge": {"name": "br0", "lan": "a", "wan": "b"}}`,
		"DHCP の範囲":        `{"listen": "192.168.10.1:8443", "pki_dir": "c", "state_dir": "s", "policy": "p", "router": {"lan": "a", "wan": "b"}, "dhcp": {"range": "x"}}`,
	} {
		_, out := consolePost(t, c, srv, "/api/check", consoleRequest{Text: text}, origin)
		if out["ok"] != false || len(out["errors"].([]any)) == 0 {
			t.Errorf("%s の誤りを見逃しました: %v", name, out)
		}
	}
	changed := strings.Replace(orig, `"lan0"`, `"lan1"`, 1)
	_, out := consolePost(t, c, srv, "/api/check", consoleRequest{Text: changed}, origin)
	if out["ok"] != true || out["changed"] != true || !strings.Contains(fmt.Sprint(out["diff"]), "lan1") {
		t.Fatalf("変更の確認 = %v", out)
	}

	// 読み込んだ後に変わっていたら保存しない。
	if status, _ := consolePost(t, c, srv, "/api/save", consoleRequest{Text: changed, Hash: "stale"}, origin); status != http.StatusConflict {
		t.Errorf("古い版からの保存 = %d", status)
	}
	if status, _ := consolePost(t, c, srv, "/api/save", consoleRequest{Text: `{"listen": "x"}`, Hash: cfg.Hash}, origin); status != http.StatusBadRequest {
		t.Errorf("検証に通らない保存 = %d", status)
	}
	status, out := consolePost(t, c, srv, "/api/save", consoleRequest{Text: changed, Hash: cfg.Hash}, origin)
	if status != http.StatusOK || out["ok"] != true {
		t.Fatalf("保存 = %d %v", status, out)
	}
	saved, _ := os.ReadFile(path)
	var m map[string]any
	if json.Unmarshal(saved, &m) != nil || !strings.Contains(string(saved), "\n  \"router\": {\n    \"lan\": \"lan1\"") {
		t.Errorf("保存した設定:\n%s", saved)
	}
	backup, _ := os.ReadFile(out["backup"].(string))
	if string(backup) != orig {
		t.Errorf("控え = %s", backup)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("保存した設定の権限 = %v", fi.Mode().Perm())
	}
	// 起動し直す。
	if _, out := consolePost(t, c, srv, "/api/restart", struct{}{}, origin); out["ok"] != true || len(restarted) != 1 || restarted[0] != "susanoo-gw" {
		t.Errorf("起動し直し = %v %v", out, restarted)
	}

	// DNS リバインディング：ほかの名前（Host）での要求は断る。
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/config", nil)
	req.Host = "attacker.example:" + strings.Split(srv.Listener.Addr().String(), ":")[1]
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("ほかの Host での要求 = %d", resp.StatusCode)
	}
}

// 控えは新しいものから決まった数だけ残す。
func TestConsoleBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")
	text := `{"controller": "192.168.10.1:8443", "pki_dir": "pki", "state_dir": "state"}`
	os.WriteFile(path, []byte(text), 0o600)
	s, srv, c := startConsole(t, path, "client", "")
	resp, _ := c.Get(srv.URL + "/?token=" + s.token)
	resp.Body.Close()
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.Local)
	s.now = func() time.Time { return now }
	for i := range consoleKeepBackups + 3 {
		cur, _ := os.ReadFile(path)
		next := fmt.Sprintf(`{"controller": "192.168.10.1:8443", "pki_dir": "pki", "state_dir": "state", "heartbeat_interval": "%ds"}`, i+1)
		if status, out := consolePost(t, c, srv, "/api/save", consoleRequest{Text: next, Hash: textHash(cur)}, srv.URL); status != http.StatusOK {
			t.Fatalf("%d 回目の保存 = %d %v", i, status, out)
		}
		now = now.Add(time.Second)
	}
	matches, _ := filepath.Glob(path + ".*.bak")
	if len(matches) != consoleKeepBackups {
		t.Errorf("控え = %d 個", len(matches))
	}
	// CLIENT の検証も起動のときと同じ。起動し直すサービスを決めていなければ、起動し直さない。
	_, out := consolePost(t, c, srv, "/api/check", consoleRequest{Text: `{"controller": "192.168.10.1:8443", "pki_dir": "p", "state_dir": "s", "resources": {"memory_mb": 1}}`}, srv.URL)
	if out["ok"] != false {
		t.Errorf("CLIENT の誤りを見逃しました: %v", out)
	}
	if status, _ := consolePost(t, c, srv, "/api/restart", struct{}{}, srv.URL); status != http.StatusNotFound {
		t.Errorf("サービスのない起動し直し = %d", status)
	}
}

func TestConsoleSetup(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:8484", "localhost:0", "[::1]:8484"} {
		if _, err := consoleListenAddr(ok); err != nil {
			t.Errorf("%s を断りました: %v", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:8484", "192.168.10.1:8484", ":8484", "example.com:80", "x"} {
		if _, err := consoleListenAddr(bad); err == nil {
			t.Errorf("%s を受け付けました", bad)
		}
	}
	for text, want := range map[string]string{`{"listen": "a"}`: "gw", `{"controller": "a"}`: "client"} {
		if got, err := detectConfigKind([]byte(text)); err != nil || got != want {
			t.Errorf("detectConfigKind(%s) = %q, %v", text, got, err)
		}
	}
	if _, err := detectConfigKind([]byte(`{"x": 1}`)); err == nil {
		t.Error("種類の分からない設定を見分けました")
	}
	// 設定の例は、どちらも入力欄の項目を持つ（入力欄の場所の書き間違いを見つける）。
	for kind, file := range map[string]string{"gw": "gw.example.json", "client": "client.example.json"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", file))
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := detectConfigKind(data); got != kind {
			t.Errorf("%s の種類 = %q", file, got)
		}
		s := &consoleServer{path: filepath.Join("..", "..", "..", "config", file), kind: kind}
		if _, errs, _ := s.validate(string(data)); len(errs) != 0 {
			t.Errorf("%s が検証に通りません: %v", file, errs)
		}
	}
	// ループバックでないアドレスでは起動しない。
	path := filepath.Join(t.TempDir(), "gw.json")
	os.WriteFile(path, []byte(`{"listen": "a"}`), 0o600)
	if code, _, errOut := runCmd(t, "console", "-config", path, "-listen", "0.0.0.0:8484"); code == exitOK || !strings.Contains(errOut, "ループバック") {
		t.Errorf("ループバックでないアドレス = %d %s", code, errOut)
	}
}

func TestLineDiff(t *testing.T) {
	got := lineDiff("a\nb\nc\n", "a\nx\nc\nd\n")
	var b strings.Builder
	for _, d := range got {
		b.WriteString(d.Op + d.Text + ";")
	}
	if b.String() != " a;-b;+x; c;+d;" {
		t.Errorf("lineDiff = %s", b.String())
	}
}
