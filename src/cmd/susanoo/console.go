package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"susanoo/internal/config"
	"susanoo/internal/fsutil"
)

// Web コンソール（2p）。GW と CLIENT の設定ファイル（gw.json、client.json）を、ブラウザーの日本語の画面で編集する。
// よく使う項目は入力欄で、残りは JSON の欄で編集し、保存の前に起動のときと同じ検証を通して変更点を示す。保存するときは
// 前の設定を控えとして残し、保存した後はボタンで systemd のサービスを起動し直せる。
//
// 設定を書き換えられると root の権限を取られるのと同じなので、次のように守る。
//   - 待ち受けはループバックのアドレスだけ（この機器の中からだけ使える）
//   - 起動のときに表示する一回限りの URL（合言葉の入ったもの）で開き、以降はクッキー（HttpOnly、SameSite=Strict）で確かめる
//     （同じ機器のほかの利用者からの接続を断る）
//   - Host の見出しを確かめ（DNS リバインディングの防止）、書き換える要求は Origin の見出しを確かめる（CSRF の防止）
//   - 操作がしばらくなければ止まる

//go:embed console
var consoleAssets embed.FS

const (
	consoleCookie      = "susanoo_console"
	consoleMaxBody     = 1 << 20
	consoleKeepBackups = 5
	consoleRestartWait = 90 * time.Second
)

const consoleUsage = `使い方: susanoo console -config <設定ファイル> [オプション]

GW か CLIENT の設定ファイルを、ブラウザーの日本語の画面で編集する（この機器の中からだけ使える）。設定ファイルを
書き換えて systemd のサービスを起動し直すので、root で動かす。起動すると、開く URL（一回限りの合言葉の入ったもの）を表示する。
`

// consoleServer は Web コンソールの状態。
type consoleServer struct {
	path    string
	kind    string // gw か client
	service string // 起動し直す systemd のサービス（空なら起動し直さない）
	token   string
	hosts   []string // 受け付ける Host の見出し
	log     *slog.Logger
	now     func() time.Time
	restart func(ctx context.Context, service string) (string, error)
	active  func(ctx context.Context, service string) string
	mu      sync.Mutex // 保存を 1 つずつ行う
	last    atomic.Int64
}

func runConsole(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("console", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { fmt.Fprint(stderr, consoleUsage); flags.PrintDefaults() }
	path := flags.String("config", "", "編集する設定ファイル（GW の gw.json か CLIENT の client.json）")
	listen := flags.String("listen", "127.0.0.1:8484", "待ち受けるアドレスとポート（ループバックのアドレスだけ）")
	kindFlag := flags.String("kind", "auto", "設定の種類（gw、client。auto なら中身から見分ける）")
	service := flags.String("service", "auto", "保存した後に起動し直す systemd のサービス（auto なら susanoo-gw か susanoo-client、none なら起動し直さない）")
	idle := flags.Duration("idle", 30*time.Minute, "この間操作がなければ止まる")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *path == "" {
		flags.Usage()
		return exitUsage
	}
	addr, err := consoleListenAddr(*listen)
	if err != nil {
		return fail(stderr, err)
	}
	data, err := os.ReadFile(*path)
	if err != nil {
		return fail(stderr, err)
	}
	kind := *kindFlag
	if kind == "auto" {
		if kind, err = detectConfigKind(data); err != nil {
			return fail(stderr, err)
		}
	}
	if kind != "gw" && kind != "client" {
		return fail(stderr, fmt.Errorf("-kind は gw か client にしてください: %q", kind))
	}
	svc := *service
	switch svc {
	case "auto":
		svc = "susanoo-" + kind
	case "none":
		svc = ""
	}
	ln, err := net.Listen("tcp", addr.String())
	if err != nil {
		return fail(stderr, err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	s := newConsoleServer(*path, kind, svc, port, newLogger(stderr))
	srv := &http.Server{Handler: s.handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if time.Since(time.Unix(s.last.Load(), 0)) > *idle {
					s.log.Info("操作がしばらくなかったので、Web コンソールを止めます")
					cancel()
					return
				}
			}
		}
	}()
	go func() {
		<-ctx.Done()
		sctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		srv.Shutdown(sctx)
	}()
	host := net.JoinHostPort(addr.Addr().String(), fmt.Sprint(port))
	fmt.Fprintf(stdout, "susanoo の Web コンソールを始めました（%s の設定 %s）。\nブラウザーで次の URL を開いてください（この機器の中からだけ使えます）:\n  http://%s/?token=%s\nCtrl+C で止めます。%s 操作がなければ止まります。\n",
		map[string]string{"gw": "GW", "client": "CLIENT"}[kind], *path, host, s.token, *idle)
	if os.Geteuid() != 0 {
		s.log.Warn("root でないため、設定ファイルを書き換えたり、サービスを起動し直したりできないことがあります")
	}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fail(stderr, err)
	}
	return exitOK
}

// consoleListenAddr は待ち受けるアドレスを確かめる。ループバックのアドレス（localhost は 127.0.0.1）だけを許す。
func consoleListenAddr(s string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("-listen %q はアドレスとポート（例: 127.0.0.1:8484）で書いてください", s)
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ap, err := netip.ParseAddrPort(net.JoinHostPort(host, port))
	if err != nil || !ap.Addr().IsLoopback() {
		return netip.AddrPort{}, fmt.Errorf("-listen %q はループバックのアドレス（127.0.0.1 か ::1）にしてください。Web コンソールはこの機器の中からだけ使えます", s)
	}
	return ap, nil
}

// detectConfigKind は設定ファイルの中身から種類（gw か client）を見分ける。
func detectConfigKind(data []byte) (string, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return "", fmt.Errorf("設定ファイルを JSON として読めません: %w", err)
	}
	_, gw := m["listen"]
	_, client := m["controller"]
	switch {
	case gw && !client:
		return "gw", nil
	case client && !gw:
		return "client", nil
	}
	return "", errors.New("設定ファイルの種類（GW か CLIENT か）を見分けられません。-kind で指定してください")
}

func newConsoleServer(path, kind, service string, port int, log *slog.Logger) *consoleServer {
	s := &consoleServer{path: path, kind: kind, service: service, token: rand.Text(), log: log, now: time.Now,
		restart: systemctlRestart, active: systemctlActive}
	for _, h := range []string{"127.0.0.1", "localhost", "[::1]"} {
		s.hosts = append(s.hosts, fmt.Sprintf("%s:%d", h, port))
	}
	s.last.Store(time.Now().Unix())
	return s
}

func systemctlRestart(ctx context.Context, service string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, consoleRestartWait)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "restart", service).CombinedOutput()
	return string(out), err
}

func systemctlActive(ctx context.Context, service string) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "is-active", service).Output()
	if s := strings.TrimSpace(string(out)); s != "" {
		return s
	}
	if err != nil {
		return "不明"
	}
	return ""
}

// handler は Web コンソールの要求を受け付ける。
func (s *consoleServer) handler() http.Handler {
	assets, _ := fs.Sub(consoleAssets, "console")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.Handle("GET /console.js", http.FileServerFS(assets))
	mux.Handle("GET /console.css", http.FileServerFS(assets))
	mux.HandleFunc("GET /api/config", s.authed(s.getConfig))
	mux.HandleFunc("POST /api/check", s.authed(s.writing(s.check)))
	mux.HandleFunc("POST /api/save", s.authed(s.writing(s.save)))
	mux.HandleFunc("POST /api/restart", s.authed(s.writing(s.restartService)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		// DNS リバインディングで、ほかのサイトの名前からこの機器のコンソールを呼ばれないよう、Host を確かめる。
		if !slices.Contains(s.hosts, r.Host) {
			http.Error(w, "この Host では受け付けません", http.StatusForbidden)
			return
		}
		s.last.Store(time.Now().Unix())
		mux.ServeHTTP(w, r)
	})
}

// validCookie は、要求が起動のときの合言葉のクッキーを持つかを返す。
func (s *consoleServer) validCookie(r *http.Request) bool {
	c, err := r.Cookie(consoleCookie)
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.token)) == 1
}

// index は画面を返す。合言葉の入った URL で開いたら、クッキーを付けて合言葉のない URL に移す。
func (s *consoleServer) index(w http.ResponseWriter, r *http.Request) {
	if t := r.URL.Query().Get("token"); t != "" {
		if subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) != 1 {
			http.Error(w, "合言葉が違います。起動したときに表示した URL を開いてください", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: consoleCookie, Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !s.validCookie(r) {
		http.Error(w, "起動したときに表示した URL（合言葉の入ったもの）から開いてください", http.StatusForbidden)
		return
	}
	data, err := consoleAssets.ReadFile("console/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// authed は合言葉のクッキーを確かめる。
func (s *consoleServer) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.validCookie(r) {
			consoleError(w, http.StatusForbidden, "起動したときに表示した URL から開き直してください")
			return
		}
		h(w, r)
	}
}

// writing は、書き換える要求の Origin（同じ画面からの要求か）と、本文の形を確かめる（CSRF の防止）。
func (s *consoleServer) writing(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "http://"+r.Host {
			consoleError(w, http.StatusForbidden, "この画面からの要求ではありません")
			return
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			consoleError(w, http.StatusUnsupportedMediaType, "本文は JSON にしてください")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, consoleMaxBody)
		h(w, r)
	}
}

func consoleError(w http.ResponseWriter, status int, msg string) {
	consoleJSON(w, status, map[string]any{"ok": false, "errors": []string{msg}})
}

func consoleJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func textHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// consoleConfig は画面に渡す設定。
type consoleConfig struct {
	Kind    string         `json:"kind"`
	Path    string         `json:"path"`
	Service string         `json:"service"`
	Active  string         `json:"active,omitempty"`
	Text    string         `json:"text"`
	Hash    string         `json:"hash"`
	Fields  []consoleField `json:"fields"`
}

func (s *consoleServer) getConfig(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		consoleError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cfg := consoleConfig{Kind: s.kind, Path: s.path, Service: s.service, Text: string(data), Hash: textHash(data), Fields: consoleFields(s.kind)}
	if s.service != "" {
		cfg.Active = s.active(r.Context(), s.service)
	}
	consoleJSON(w, http.StatusOK, cfg)
}

type consoleRequest struct {
	Text string `json:"text"`
	Hash string `json:"hash"`
}

// consoleCheck は検証の結果。
type consoleCheck struct {
	OK       bool       `json:"ok"`
	Errors   []string   `json:"errors"`
	Warnings []string   `json:"warnings"`
	Changed  bool       `json:"changed"`
	Diff     []diffLine `json:"diff"`
	Text     string     `json:"text,omitempty"` // 保存する形に整えたもの
}

// validate は設定の JSON を、起動のときと同じ検証に通す。返す text は保存する形（2 文字の字下げ、末尾に改行）。
func (s *consoleServer) validate(text string) (string, []string, []string) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(text), "", "  "); err != nil {
		return "", []string{"JSON の形が正しくありません: " + err.Error()}, nil
	}
	buf.WriteByte('\n')
	formatted := buf.String()
	var errs, warns []string
	switch s.kind {
	case "gw":
		var cfg gwConfig
		if err := config.Parse(buf.Bytes(), &cfg); err != nil {
			return formatted, []string{"設定を読めません: " + err.Error()}, nil
		}
		if err := cfg.check(); err != nil {
			errs = append(errs, err.Error())
		}
		for _, p := range []struct{ name, path string }{{"pki_dir", cfg.PKIDir}, {"policy", cfg.Policy}} {
			if p.path != "" {
				if _, err := os.Stat(config.Resolve(s.path, p.path)); err != nil {
					warns = append(warns, fmt.Sprintf("%s の %s がありません（起動できません）", p.name, p.path))
				}
			}
		}
		if cfg.Notify != nil && len(cfg.Notify.Destinations) > 0 {
			if fi, err := os.Stat(s.path); err == nil && fi.Mode().Perm()&0o044 != 0 {
				warns = append(warns, "通知の宛先（URL やパスワード）があるのに、設定ファイルをほかの利用者も読めます。chmod 600 で root だけが読めるようにしてください")
			}
		}
	case "client":
		var cfg clientConfig
		if err := config.Parse(buf.Bytes(), &cfg); err != nil {
			return formatted, []string{"設定を読めません: " + err.Error()}, nil
		}
		if err := cfg.check(); err != nil {
			errs = append(errs, err.Error())
		}
		if cfg.PKIDir != "" {
			if _, err := os.Stat(config.Resolve(s.path, cfg.PKIDir)); err != nil {
				warns = append(warns, fmt.Sprintf("pki_dir の %s がありません（起動できません）", cfg.PKIDir))
			}
		}
	}
	return formatted, errs, warns
}

func (s *consoleServer) check(w http.ResponseWriter, r *http.Request) {
	var req consoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		consoleError(w, http.StatusBadRequest, "要求を読めません")
		return
	}
	cur, err := os.ReadFile(s.path)
	if err != nil {
		consoleError(w, http.StatusInternalServerError, err.Error())
		return
	}
	formatted, errs, warns := s.validate(req.Text)
	res := consoleCheck{OK: len(errs) == 0, Errors: errs, Warnings: warns, Text: formatted}
	if formatted != "" {
		res.Diff = lineDiff(string(cur), formatted)
		res.Changed = formatted != string(cur)
	}
	consoleJSON(w, http.StatusOK, res)
}

// save は、検証に通った設定を、前の設定を控えに残してから保存する。読み込んだ後にほかの方法で変わっていたら断る。
func (s *consoleServer) save(w http.ResponseWriter, r *http.Request) {
	var req consoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		consoleError(w, http.StatusBadRequest, "要求を読めません")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := os.ReadFile(s.path)
	if err != nil {
		consoleError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if textHash(cur) != req.Hash {
		consoleError(w, http.StatusConflict, "読み込んだ後に、設定ファイルがほかの方法で変わりました。読み込み直してから編集してください")
		return
	}
	formatted, errs, warns := s.validate(req.Text)
	if len(errs) > 0 {
		consoleJSON(w, http.StatusBadRequest, consoleCheck{Errors: errs, Warnings: warns})
		return
	}
	if formatted == string(cur) {
		consoleJSON(w, http.StatusOK, map[string]any{"ok": true, "unchanged": true, "hash": textHash(cur)})
		return
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(s.path); err == nil {
		mode = fi.Mode().Perm()
	}
	backup := fmt.Sprintf("%s.%s.bak", s.path, s.now().Format("20060102-150405"))
	if err := fsutil.WriteFileAtomic(backup, cur, mode); err != nil {
		consoleError(w, http.StatusInternalServerError, "前の設定の控えを書けません: "+err.Error())
		return
	}
	if err := fsutil.WriteFileAtomic(s.path, []byte(formatted), mode); err != nil {
		consoleError(w, http.StatusInternalServerError, "設定ファイルを書けません: "+err.Error())
		return
	}
	s.pruneBackups()
	s.log.Info("Web コンソールで設定ファイルを保存しました", "ファイル", s.path, "控え", backup)
	consoleJSON(w, http.StatusOK, map[string]any{"ok": true, "hash": textHash([]byte(formatted)), "backup": backup, "warnings": warns})
}

// pruneBackups は、控えを新しいものから consoleKeepBackups 個だけ残す。
func (s *consoleServer) pruneBackups() {
	matches, _ := filepath.Glob(s.path + ".*.bak")
	slices.Sort(matches) // 名前に時刻が入っているので、名前の順が古い順
	for len(matches) > consoleKeepBackups {
		os.Remove(matches[0])
		matches = matches[1:]
	}
}

func (s *consoleServer) restartService(w http.ResponseWriter, r *http.Request) {
	if s.service == "" {
		consoleError(w, http.StatusNotFound, "起動し直すサービスを決めていません（-service none で起動しています）")
		return
	}
	out, err := s.restart(r.Context(), s.service)
	active := s.active(r.Context(), s.service)
	if err != nil {
		s.log.Warn("サービスを起動し直せません", "サービス", s.service, "エラー", err)
		consoleJSON(w, http.StatusOK, map[string]any{"ok": false, "errors": []string{"起動し直せません: " + err.Error()}, "output": out, "active": active})
		return
	}
	s.log.Info("Web コンソールからサービスを起動し直しました", "サービス", s.service, "状態", active)
	consoleJSON(w, http.StatusOK, map[string]any{"ok": true, "output": out, "active": active})
}

// diffLine は変更点の 1 行（Op は「 」「+」「-」）。
type diffLine struct {
	Op   string `json:"op"`
	Text string `json:"text"`
}

// lineDiff は a から b への行の変更点を返す（最長共通部分列による）。
func lineDiff(a, b string) []diffLine {
	x, y := strings.Split(strings.TrimSuffix(a, "\n"), "\n"), strings.Split(strings.TrimSuffix(b, "\n"), "\n")
	if len(x)*len(y) > 4_000_000 {
		return []diffLine{{"-", "（変更点が大きすぎるため表示しません）"}}
	}
	// lcs[i][j] は x[i:] と y[j:] の最長共通部分列の長さ。
	lcs := make([][]int32, len(x)+1)
	for i := range lcs {
		lcs[i] = make([]int32, len(y)+1)
	}
	for i := len(x) - 1; i >= 0; i-- {
		for j := len(y) - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out []diffLine
	i, j := 0, 0
	for i < len(x) && j < len(y) {
		switch {
		case x[i] == y[j]:
			out = append(out, diffLine{" ", x[i]})
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, diffLine{"-", x[i]})
			i++
		default:
			out = append(out, diffLine{"+", y[j]})
			j++
		}
	}
	for ; i < len(x); i++ {
		out = append(out, diffLine{"-", x[i]})
	}
	for ; j < len(y); j++ {
		out = append(out, diffLine{"+", y[j]})
	}
	return out
}
