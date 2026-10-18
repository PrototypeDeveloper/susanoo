package notify

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"susanoo/internal/event"
)

// 試験の通信はループバック（127.0.0.1）だけで行う。

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// hookServer は受け取った POST の本文を記録する偽の webhook の受け口。fail 回だけ 500 を返す。
type hookServer struct {
	*httptest.Server
	mu      sync.Mutex
	bodies  []string
	headers []http.Header
	fail    int
}

func newHookServer(t *testing.T) *hookServer {
	h := &hookServer{}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.fail > 0 {
			h.fail--
			http.Error(w, "busy", http.StatusInternalServerError)
			return
		}
		h.bodies = append(h.bodies, string(b))
		h.headers = append(h.headers, r.Header.Clone())
	}))
	t.Cleanup(h.Close)
	return h
}

func (h *hookServer) wait(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		if len(h.bodies) >= n {
			out := append([]string(nil), h.bodies...)
			h.mu.Unlock()
			return out
		}
		h.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("通知が %d 件届かない", n)
	return nil
}

func start(t *testing.T, cfg Config, opt Options) *Notifier {
	t.Helper()
	if opt.Logger == nil {
		opt.Logger = quiet
	}
	if opt.Retries == nil {
		opt.Retries = []time.Duration{10 * time.Millisecond}
	}
	n, err := New(cfg, opt)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { n.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return n
}

func isolateMsg(target string) Message {
	return Message{Kind: KindIsolate, Severity: event.SeverityHigh, Title: "端末 " + target + " を隔離しました", Target: target,
		Body: "自動対応で隔離しました。", Fields: map[string]string{"理由": "おとりへの接触", "段階": "management", "その他": "x"}}
}

func TestWebhookAndSlack(t *testing.T) {
	hook, slack := newHookServer(t), newHookServer(t)
	n := start(t, Config{Destinations: []Destination{
		{Name: "hook", Type: "webhook", URL: hook.URL, Headers: map[string]string{"Authorization": "Bearer t0ken"}},
		{Name: "chat", Type: "slack", URL: slack.URL + "/services/T/B/secret"},
	}}, Options{})
	n.Notify(isolateMsg("pc-001"))

	var got map[string]any
	if err := json.Unmarshal([]byte(hook.wait(t, 1)[0]), &got); err != nil {
		t.Fatal(err)
	}
	if got["kind"] != "isolate" || got["severity"] != "high" || got["target"] != "pc-001" || got["source"] != "susanoo" {
		t.Errorf("webhook の本文 = %v", got)
	}
	if f, _ := got["fields"].(map[string]any); f["理由"] != "おとりへの接触" {
		t.Errorf("webhook の項目 = %v", got["fields"])
	}
	if hook.headers[0].Get("Authorization") != "Bearer t0ken" || !strings.HasPrefix(hook.headers[0].Get("Content-Type"), "application/json") {
		t.Errorf("ヘッダー = %v", hook.headers[0])
	}
	var s map[string]string
	json.Unmarshal([]byte(slack.wait(t, 1)[0]), &s)
	text := s["text"]
	// 項目は決めた順（理由、段階）に並び、それ以外は後ろに付く。
	if !strings.HasPrefix(text, "*[susanoo] 端末 pc-001 を隔離しました*") || strings.Index(text, "理由:") > strings.Index(text, "段階:") ||
		strings.Index(text, "段階:") > strings.Index(text, "その他:") {
		t.Errorf("slack の本文 = %q", text)
	}
	st := n.Status()
	if len(st) != 2 || st[0].Sent != 1 || st[1].Sent != 1 || st[0].Failed != 0 {
		t.Errorf("状況 = %+v", st)
	}
}

// 検知の内容に含まれる記号で、Slack のリンクや呼び出しを作らせない。
func TestSlackEscapes(t *testing.T) {
	text := slackText(Message{Title: "<!channel> & <https://evil.test|click>", Time: time.Now()}, 0)
	if strings.Contains(text, "<!channel>") || strings.Contains(text, "<https://") || !strings.Contains(text, "&lt;!channel&gt; &amp;") {
		t.Errorf("本文 = %q", text)
	}
}

// 失敗したら試し直す。送れなかったら失敗を数え、URL のトークンをエラーに残さない。
func TestRetryAndFailure(t *testing.T) {
	hook := newHookServer(t)
	hook.fail = 1
	n := start(t, Config{Destinations: []Destination{{Name: "hook", Type: "webhook", URL: hook.URL}}}, Options{})
	n.Notify(isolateMsg("pc-001"))
	hook.wait(t, 1)

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // 誰も待ち受けていないポート
	bad := start(t, Config{Destinations: []Destination{{Name: "down", Type: "slack", URL: "http://" + addr + "/services/SECRET-TOKEN"}}}, Options{})
	bad.Notify(isolateMsg("pc-002"))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && bad.Status()[0].Failed == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	st := bad.Status()[0]
	if st.Failed != 1 || st.LastError == "" || strings.Contains(st.LastError, "SECRET-TOKEN") {
		t.Errorf("状況 = %+v", st)
	}
}

// 宛先ごとに、送る種類と検知結果の重大度の下限を選べる。同じ通知は 10 分に 1 回にまとめる。
func TestFilterAndDedupe(t *testing.T) {
	all, crit := newHookServer(t), newHookServer(t)
	n := start(t, Config{Destinations: []Destination{
		{Name: "all", Type: "webhook", URL: all.URL},
		{Name: "crit", Type: "webhook", URL: crit.URL, Events: []Kind{KindFinding}, MinSeverity: "critical"},
	}}, Options{})
	n.Notify(isolateMsg("pc-001"))
	n.Notify(isolateMsg("pc-001")) // まとめる
	n.Notify(Message{Kind: KindFinding, Severity: event.SeverityHigh, Title: "改ざん", Target: "pc-001"})
	n.Notify(Message{Kind: KindFinding, Severity: event.SeverityMedium, Title: "弱い検知", Target: "pc-001"}) // high 未満は送らない
	n.Notify(Message{Kind: KindFinding, Severity: event.SeverityCritical, Title: "重大", Target: "pc-001"})
	got := all.wait(t, 3)
	time.Sleep(100 * time.Millisecond)
	if len(all.bodies) != 3 || strings.Contains(strings.Join(got, ""), "弱い検知") {
		t.Errorf("all に届いた通知 = %v", all.bodies)
	}
	if c := crit.wait(t, 1); len(crit.bodies) != 1 || !strings.Contains(c[0], "重大") {
		t.Errorf("crit に届いた通知 = %v", crit.bodies)
	}
}

// 1 時間の上限を超えた分は送らず、次に送る通知に省略した数を添える。
func TestRateLimit(t *testing.T) {
	hook := newHookServer(t)
	var mu sync.Mutex
	now := time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	n := start(t, Config{RateLimit: 2, Destinations: []Destination{{Name: "hook", Type: "webhook", URL: hook.URL}}}, Options{Now: clock})
	for _, id := range []string{"pc-001", "pc-002", "pc-003", "pc-004"} {
		n.Notify(isolateMsg(id))
	}
	hook.wait(t, 2)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && n.Status()[0].Suppressed < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if st := n.Status()[0]; st.Sent != 2 || st.Suppressed != 2 {
		t.Fatalf("状況 = %+v", st)
	}
	mu.Lock()
	now = now.Add(time.Hour)
	mu.Unlock()
	n.Notify(isolateMsg("pc-005"))
	got := hook.wait(t, 3)
	var b map[string]any
	json.Unmarshal([]byte(got[2]), &b)
	if b["target"] != "pc-005" || b["suppressed"] != float64(2) {
		t.Errorf("上限の後の通知 = %v", b)
	}
}

// fakeSMTP は受け取ったメールを記録する偽の SMTP サーバー（STARTTLS と認証は扱わない）。
type fakeSMTP struct {
	addr string
	mu   sync.Mutex
	mail []string // DATA の中身
	rcpt []string
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeSMTP{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	reply := func(s string) { io.WriteString(c, s+"\r\n") }
	reply("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			reply("250-fake")
			reply("250 8BITMIME")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			f.mu.Lock()
			f.rcpt = append(f.rcpt, strings.TrimSpace(line[len("RCPT TO:"):]))
			f.mu.Unlock()
			reply("250 ok")
		case cmd == "DATA":
			reply("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.mail = append(f.mail, b.String())
			f.mu.Unlock()
			reply("250 queued")
		case cmd == "QUIT":
			reply("221 bye")
			return
		default:
			reply("250 ok")
		}
	}
}

func TestEmail(t *testing.T) {
	srv := newFakeSMTP(t)
	n := start(t, Config{Destinations: []Destination{{Name: "mail", Type: "email", Email: &Email{
		Server: srv.addr, TLS: "none", From: "susanoo@example.jp", To: []string{"admin@example.jp", "sec@example.jp"},
	}}}}, Options{})
	n.Notify(isolateMsg("pc-001"))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && n.Status()[0].Sent == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.mail) != 1 || len(srv.rcpt) != 2 {
		t.Fatalf("メール = %d 通、宛先 %v（状況 %+v）", len(srv.mail), srv.rcpt, n.Status())
	}
	head, body, _ := strings.Cut(srv.mail[0], "\r\n\r\n")
	var subject string
	for _, l := range strings.Split(head, "\r\n") {
		if s, ok := strings.CutPrefix(l, "Subject: "); ok {
			subject, _ = new(mime.WordDecoder).DecodeHeader(s)
		}
	}
	text, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(body, "\r\n", ""))
	if subject != "[susanoo] 端末 pc-001 を隔離しました" || err != nil || !strings.Contains(string(text), "理由: おとりへの接触") {
		t.Errorf("題名 = %q、本文 = %q（%v）", subject, text, err)
	}
}

// STARTTLS に対応していないサーバーには、既定（starttls）では送らない。
func TestEmailRequiresStartTLS(t *testing.T) {
	srv := newFakeSMTP(t)
	n, err := New(Config{Destinations: []Destination{{Name: "mail", Type: "email", Email: &Email{
		Server: srv.addr, From: "susanoo@example.jp", To: []string{"admin@example.jp"},
	}}}}, Options{Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	if r := n.Test(context.Background()); len(r) != 1 || !strings.Contains(r[0].Error, "STARTTLS") {
		t.Errorf("結果 = %+v", r)
	}
}

func TestTestNotification(t *testing.T) {
	hook := newHookServer(t)
	n, err := New(Config{Destinations: []Destination{
		{Name: "hook", Type: "webhook", URL: hook.URL, Events: []Kind{KindFinding}}, // 種類を絞っていても試験の通知は届く
		{Name: "down", Type: "webhook", URL: "http://127.0.0.1:1/x"},
	}}, Options{Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	r := n.Test(context.Background())
	if len(r) != 2 || r[0].Error != "" || r[1].Error == "" || len(hook.bodies) != 1 || !strings.Contains(hook.bodies[0], `"kind":"test"`) {
		t.Errorf("結果 = %+v、届いた通知 = %v", r, hook.bodies)
	}
}

func TestValidate(t *testing.T) {
	mail := func(e Email) Destination { return Destination{Name: "m", Type: "email", Email: &e} }
	ok := Email{Server: "smtp.example.jp:587", From: "a@example.jp", To: []string{"b@example.jp"}}
	for name, tc := range map[string]struct {
		cfg  Config
		want string
	}{
		"名前がない":       {Config{Destinations: []Destination{{Type: "webhook", URL: "https://example.jp/h"}}}, "name"},
		"名前の重複":       {Config{Destinations: []Destination{{Name: "a", Type: "webhook", URL: "https://example.jp/h"}, {Name: "a", Type: "slack", URL: "https://example.jp/s"}}}, "重複"},
		"種類が不正":       {Config{Destinations: []Destination{{Name: "a", Type: "sms"}}}, "type"},
		"URL が不正":     {Config{Destinations: []Destination{{Name: "a", Type: "webhook", URL: "ftp://example.jp"}}}, "url"},
		"知らない通知の種類":   {Config{Destinations: []Destination{{Name: "a", Type: "webhook", URL: "https://example.jp/h", Events: []Kind{"everything"}}}}, "events"},
		"重大度が不正":      {Config{Destinations: []Destination{{Name: "a", Type: "webhook", URL: "https://example.jp/h", MinSeverity: "huge"}}}, "min_severity"},
		"メールの設定がない":   {Config{Destinations: []Destination{{Name: "a", Type: "email"}}}, "email を書いて"},
		"サーバーにポートがない": {Config{Destinations: []Destination{mail(Email{Server: "smtp.example.jp", From: ok.From, To: ok.To})}}, "email.server"},
		"暗号化なしで認証":    {Config{Destinations: []Destination{mail(Email{Server: ok.Server, TLS: "none", Username: "u", From: ok.From, To: ok.To})}}, "認証できません"},
		"宛先のアドレスが不正":  {Config{Destinations: []Destination{mail(Email{Server: ok.Server, From: ok.From, To: []string{"bad"}})}}, "email.to"},
		"ヘッダーの名前が不正":  {Config{Destinations: []Destination{{Name: "a", Type: "webhook", URL: "https://example.jp/h", Headers: map[string]string{"X Bad": "1"}}}}, "headers"},
	} {
		err := tc.cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s = %v（%q を含むはず）", name, err, tc.want)
		}
	}
	good := Config{Destinations: []Destination{mail(ok), {Name: "h", Type: "slack", URL: "https://hooks.example.jp/x"}}}
	if err := good.Validate(); err != nil {
		t.Errorf("正しい設定 = %v", err)
	}
	var none *Notifier
	none.Notify(isolateMsg("pc-001")) // 宛先がなければ何もしない
	if none.Enabled() || none.Status() != nil {
		t.Error("nil の Notifier が有効とされた")
	}
}
