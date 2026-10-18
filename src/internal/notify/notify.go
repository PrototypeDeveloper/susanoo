// Package notify は管理者への通知（M7）を送る。
//
// 宛先は GW の設定ファイルに書く（宛先の URL やパスワードは秘密なので、署名して配るポリシーには入れない）。宛先の種類は次の 3 つ。
//
//   - webhook：JSON を POST する（独自の受け口や、自動化の仕組みにつなぐ）
//   - slack：Slack の Incoming Webhook の形（{"text": ...}）で POST する。同じ形を受け付ける Mattermost などにも使える
//   - email：SMTP でメールを送る（STARTTLS、TLS、暗号化なしのどれか。暗号化なしで認証はしない）
//
// 送る内容は、隔離、隔離の承認待ち、隔離が必要な検知（警告モードや監視モードで隔離しないとき）、隔離の解除と、
// 加点した検知結果のうち隔離に至らなかったもの。宛先ごとに、送る種類と、検知結果の重大度の下限を選べる。
//
// 送信は宛先ごとのゴルーチンで行い、CONTROLLER の処理を待たせない。失敗したら間を空けて 3 回まで試す。
// 宛先ごとに 1 時間に送る数の上限を設け、超えた分は数だけ数えて、次に送る通知に添える（攻撃で通知があふれないように）。
// 同じ種類、対象、題名の通知は 10 分に 1 回にまとめる。
package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"susanoo/internal/event"
)

// Kind は通知の種類。
type Kind string

const (
	KindIsolate  Kind = "isolate"  // 隔離した
	KindPending  Kind = "pending"  // 隔離の承認を待っている
	KindAlert    Kind = "alert"    // 隔離が必要な検知があった（警告モード、監視モードのため隔離しない）
	KindRelease  Kind = "release"  // 隔離を解除した
	KindFinding  Kind = "finding"  // 加点した検知結果（隔離に至らなかったもの）
	KindIncident Kind = "incident" // インシデントの報告の期限が近づいた、過ぎた（M9）
	KindTest     Kind = "test"     // 試験の通知（ctl notify test）
)

var kinds = []Kind{KindIsolate, KindPending, KindAlert, KindRelease, KindFinding, KindIncident}

// DefaultKinds は宛先が種類を書かないときに送る種類（すべて）。
var DefaultKinds = kinds

// Message は 1 件の通知。
type Message struct {
	Kind     Kind
	Severity event.Severity
	Title    string            // 題名（例: 端末 pc-001 を隔離しました）
	Body     string            // 内容
	Target   string            // 対象（端末 ID か MAC アドレス）
	Time     time.Time         // 起きた時刻
	Fields   map[string]string // 理由、段階など（表示の順は fieldOrder）
}

// fieldOrder は Fields を表示する順。ここにない項目は名前の順に後ろに並べる。
var fieldOrder = []string{"対象", "理由", "段階", "危険度", "グループ", "アドレス", "操作", "対処"}

// Config は通知の設定（GW の設定ファイルの notify）。
type Config struct {
	Destinations []Destination `json:"destinations"`
	RateLimit    int           `json:"rate_limit,omitempty"` // 宛先ごとに 1 時間に送る上限。既定 30
}

// Destination は通知の宛先。
type Destination struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`                   // webhook、slack、email
	URL         string            `json:"url,omitempty"`          // webhook、slack の送り先（https:// か http://）
	Headers     map[string]string `json:"headers,omitempty"`      // webhook、slack で付けるヘッダー（認証のトークンなど）
	Email       *Email            `json:"email,omitempty"`        // email の設定
	Events      []Kind            `json:"events,omitempty"`       // 送る種類。省略するとすべて
	MinSeverity string            `json:"min_severity,omitempty"` // 検知結果（finding）の重大度の下限（low、medium、high、critical）。既定 high
}

// Email はメールの送り方。
type Email struct {
	Server   string   `json:"server"`             // SMTP サーバー（ホスト:ポート）
	TLS      string   `json:"tls,omitempty"`      // starttls（既定）、tls（接続から TLS。465 番など）、none（暗号化しない）
	Username string   `json:"username,omitempty"` // 認証の利用者（なければ認証しない）
	Password string   `json:"password,omitempty"`
	From     string   `json:"from"`
	To       []string `json:"to"`
}

// 既定値と上限。
const (
	DefaultRateLimit = 30
	rateWindow       = time.Hour
	dedupeWindow     = 10 * time.Minute
	queueSize        = 256
	sendTimeout      = 20 * time.Second
	maxBodyLog       = 200
)

var severities = map[string]event.Severity{
	"low": event.SeverityLow, "medium": event.SeverityMedium, "high": event.SeverityHigh, "critical": event.SeverityCritical,
}

var severityNames = map[event.Severity]string{
	event.SeverityInformational: "info", event.SeverityLow: "low", event.SeverityMedium: "medium",
	event.SeverityHigh: "high", event.SeverityCritical: "critical", event.SeverityFatal: "fatal",
}

// Validate は設定を確かめる。問題をまとめて返す。
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf("notify: "+format, args...)) }
	if c.RateLimit < 0 {
		add("rate_limit は 0 以上にしてください")
	}
	seen := map[string]bool{}
	for i, d := range c.Destinations {
		where := fmt.Sprintf("destinations[%d]（%s）", i, d.Name)
		if d.Name == "" {
			add("%s: name がありません", where)
		} else if seen[d.Name] {
			add("%s: name が重複しています", where)
		}
		seen[d.Name] = true
		for _, k := range d.Events {
			if !slices.Contains(kinds, k) {
				add("%s: events の %q は isolate、pending、alert、release、finding、incident のどれかにしてください", where, k)
			}
		}
		if _, ok := severities[d.MinSeverity]; d.MinSeverity != "" && !ok {
			add("%s: min_severity %q は low、medium、high、critical のどれかにしてください", where, d.MinSeverity)
		}
		switch d.Type {
		case "webhook", "slack":
			u, err := url.Parse(d.URL)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				add("%s: url は https:// か http:// で始まる URL にしてください", where)
			}
			if d.Email != nil {
				add("%s: email は type が email のときだけ書けます", where)
			}
			for k := range d.Headers {
				if k == "" || strings.ContainsAny(k, " :\r\n") {
					add("%s: headers の名前 %q が不正です", where, k)
				}
			}
		case "email":
			e := d.Email
			if e == nil {
				add("%s: email を書いてください", where)
				continue
			}
			if _, _, err := net.SplitHostPort(e.Server); err != nil {
				add("%s: email.server はホストとポート（例: smtp.example.jp:587）で書いてください", where)
			}
			switch e.TLS {
			case "", "starttls", "tls":
			case "none":
				if e.Username != "" {
					add("%s: 暗号化しない（tls が none）ときは、パスワードを送らないよう認証できません", where)
				}
			default:
				add("%s: email.tls は starttls、tls、none のどれかにしてください", where)
			}
			if !validAddr(e.From) || len(e.To) == 0 || slices.ContainsFunc(e.To, func(a string) bool { return !validAddr(a) }) {
				add("%s: email.from と email.to にメールアドレスを書いてください", where)
			}
			if d.URL != "" || len(d.Headers) > 0 {
				add("%s: url と headers は type が webhook か slack のときだけ書けます", where)
			}
		default:
			add("%s: type は webhook、slack、email のどれかにしてください", where)
		}
	}
	return errors.Join(errs...)
}

func validAddr(a string) bool {
	at := strings.LastIndexByte(a, '@')
	return at > 0 && at < len(a)-1 && !strings.ContainsAny(a, " <>\r\n,")
}

// Status は宛先ごとの送信の状況（ctl status で表示する）。
type Status struct {
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Sent       int64     `json:"sent"`
	Failed     int64     `json:"failed"`
	Suppressed int64     `json:"suppressed"` // 上限を超えて送らなかった数
	LastSent   time.Time `json:"last_sent,omitzero"`
	LastError  string    `json:"last_error,omitempty"`
	LastFailed time.Time `json:"last_failed,omitzero"`
}

// Result は試験の通知の結果。
type Result struct {
	Name  string `json:"name"`
	Error string `json:"error,omitempty"` // 空なら送れた
}

// Notifier は通知を送る。
type Notifier struct {
	dests []*dest
	log   *slog.Logger
	now   func() time.Time
}

// dest は 1 つの宛先と、その送信の状況。
type dest struct {
	cfg     Destination
	kinds   []Kind
	minSev  event.Severity
	limit   int
	send    func(ctx context.Context, m Message, suppressed int) error
	queue   chan Message
	retries []time.Duration

	mu         sync.Mutex
	st         Status
	window     time.Time // 上限を数えている 1 時間の始まり
	count      int       // window の中で送った数
	suppressed int       // 上限を超えて送らず、まだ知らせていない数
	recent     map[string]time.Time
	failing    bool
}

// Options は試験のための設定。
type Options struct {
	Logger  *slog.Logger
	Now     func() time.Time
	Retries []time.Duration // 失敗したときに試し直すまでの間（既定 10 秒、60 秒）
	Client  *http.Client
}

// New は宛先ごとの送り手を作る。cfg は Validate で確かめたもの。Run を呼ぶまで送らない。
func New(cfg Config, opt Options) (*Notifier, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Retries == nil {
		opt.Retries = []time.Duration{10 * time.Second, time.Minute}
	}
	if opt.Client == nil {
		opt.Client = &http.Client{
			Timeout: sendTimeout,
			// 転送には従わない（通知の中身を、設定していない宛先に送らないように）。
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport:     &http.Transport{Proxy: nil, TLSHandshakeTimeout: 10 * time.Second, ForceAttemptHTTP2: true},
		}
	}
	limit := cfg.RateLimit
	if limit == 0 {
		limit = DefaultRateLimit
	}
	n := &Notifier{log: opt.Logger, now: opt.Now}
	for _, d := range cfg.Destinations {
		x := &dest{cfg: d, kinds: d.Events, minSev: event.SeverityHigh, limit: limit, queue: make(chan Message, queueSize),
			retries: opt.Retries, recent: map[string]time.Time{}, st: Status{Name: d.Name, Type: d.Type}}
		if len(x.kinds) == 0 {
			x.kinds = DefaultKinds
		}
		if s, ok := severities[d.MinSeverity]; ok {
			x.minSev = s
		}
		switch d.Type {
		case "webhook":
			x.send = func(ctx context.Context, m Message, sup int) error {
				return postJSON(ctx, opt.Client, d, webhookBody(m, sup))
			}
		case "slack":
			x.send = func(ctx context.Context, m Message, sup int) error {
				return postJSON(ctx, opt.Client, d, map[string]string{"text": slackText(m, sup)})
			}
		case "email":
			x.send = func(ctx context.Context, m Message, sup int) error {
				return sendMail(ctx, *d.Email, mailMessage(*d.Email, m, sup, opt.Now()))
			}
		}
		if u, err := url.Parse(d.URL); err == nil && u.Scheme == "http" {
			opt.Logger.Warn("通知の宛先は暗号化されていません（http://）。宛先と内容が途中で読まれる恐れがあります", "宛先", d.Name)
		}
		if d.Type == "email" && d.Email.TLS == "none" {
			opt.Logger.Warn("通知のメールは暗号化されません（tls が none）", "宛先", d.Name)
		}
		n.dests = append(n.dests, x)
	}
	return n, nil
}

// Enabled は宛先が 1 つでもあるかを返す。
func (n *Notifier) Enabled() bool { return n != nil && len(n.dests) > 0 }

// Run は宛先ごとに送信を続け、ctx が終わったら返る。
func (n *Notifier) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, d := range n.dests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n.worker(ctx, d)
		}()
	}
	wg.Wait()
}

// Notify は通知を宛先ごとの送り待ちに入れる。待たずに返る。送り待ちがいっぱいなら捨てて数える。
func (n *Notifier) Notify(m Message) {
	if n == nil {
		return
	}
	if m.Time.IsZero() {
		m.Time = n.now()
	}
	for _, d := range n.dests {
		if !d.wants(m) {
			continue
		}
		d.mu.Lock()
		key := string(m.Kind) + "\x00" + m.Target + "\x00" + m.Title
		if t, ok := d.recent[key]; ok && m.Time.Sub(t) < dedupeWindow && m.Time.Sub(t) >= 0 {
			d.mu.Unlock()
			continue
		}
		if len(d.recent) > 1024 {
			for k, t := range d.recent {
				if m.Time.Sub(t) >= dedupeWindow {
					delete(d.recent, k)
				}
			}
		}
		d.recent[key] = m.Time
		d.mu.Unlock()
		select {
		case d.queue <- m:
		default:
			d.mu.Lock()
			d.suppressed++
			d.st.Suppressed++
			d.mu.Unlock()
		}
	}
}

// wants は宛先がこの通知を送るかを返す。
func (d *dest) wants(m Message) bool {
	if m.Kind == KindTest {
		return true
	}
	if !slices.Contains(d.kinds, m.Kind) {
		return false
	}
	return m.Kind != KindFinding || m.Severity >= d.minSev
}

func (n *Notifier) worker(ctx context.Context, d *dest) {
	for {
		select {
		case <-ctx.Done():
			return
		case m := <-d.queue:
			sup, ok := d.admit(n.now())
			if !ok {
				continue
			}
			n.deliver(ctx, d, m, sup)
		}
	}
}

// admit は 1 時間の上限の中で送ってよいかを返す。送ってよければ、これまでに上限を超えて送らなかった数も返す。
func (d *dest) admit(now time.Time) (int, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if now.Sub(d.window) >= rateWindow || now.Before(d.window) {
		d.window, d.count = now, 0
	}
	if d.count >= d.limit {
		d.suppressed++
		d.st.Suppressed++
		return 0, false
	}
	d.count++
	sup := d.suppressed
	d.suppressed = 0
	return sup, true
}

// deliver は通知を送り、失敗したら間を空けて試し直す。
func (n *Notifier) deliver(ctx context.Context, d *dest, m Message, sup int) {
	var err error
	for attempt := 0; ; attempt++ {
		sctx, cancel := context.WithTimeout(ctx, sendTimeout)
		err = d.send(sctx, m, sup)
		cancel()
		if err == nil || attempt >= len(d.retries) || ctx.Err() != nil {
			break
		}
		select {
		case <-time.After(d.retries[attempt]):
		case <-ctx.Done():
			return
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := n.now()
	if err != nil {
		d.st.Failed++
		d.st.LastError, d.st.LastFailed = err.Error(), now
		if !d.failing {
			n.log.Warn("通知を送れません", "宛先", d.cfg.Name, "通知", m.Title, "エラー", err)
		}
		d.failing = true
		return
	}
	d.st.Sent++
	d.st.LastSent = now
	if d.failing {
		n.log.Info("通知を送れるようになりました", "宛先", d.cfg.Name)
	}
	d.failing = false
}

// Test は試験の通知をすべての宛先にすぐ送り、結果を返す（上限とまとめは使わない）。
func (n *Notifier) Test(ctx context.Context) []Result {
	if n == nil {
		return nil
	}
	m := Message{Kind: KindTest, Severity: event.SeverityInformational, Title: "susanoo の試験の通知",
		Body: "通知の設定を確かめるための試験の通知です。この通知が届いていれば、宛先の設定は正しく動いています。", Time: n.now()}
	results := make([]Result, len(n.dests))
	var wg sync.WaitGroup
	for i, d := range n.dests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sctx, cancel := context.WithTimeout(ctx, sendTimeout)
			defer cancel()
			results[i] = Result{Name: d.cfg.Name}
			if err := d.send(sctx, m, 0); err != nil {
				results[i].Error = err.Error()
			}
		}()
	}
	wg.Wait()
	return results
}

// Status は宛先ごとの送信の状況を返す。
func (n *Notifier) Status() []Status {
	if n == nil {
		return nil
	}
	out := make([]Status, 0, len(n.dests))
	for _, d := range n.dests {
		d.mu.Lock()
		out = append(out, d.st)
		d.mu.Unlock()
	}
	return out
}

// webhookBody は webhook の JSON。
func webhookBody(m Message, suppressed int) map[string]any {
	b := map[string]any{
		"source":   "susanoo",
		"kind":     m.Kind,
		"severity": severityNames[m.Severity],
		"title":    m.Title,
		"message":  m.Body,
		"time":     m.Time.UTC().Format(time.RFC3339),
	}
	if m.Target != "" {
		b["target"] = m.Target
	}
	if len(m.Fields) > 0 {
		b["fields"] = m.Fields
	}
	if suppressed > 0 {
		b["suppressed"] = suppressed
	}
	return b
}

// slackText は Slack の形の本文。
func slackText(m Message, suppressed int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*[susanoo] %s*\n", escapeSlack(m.Title))
	if m.Body != "" {
		b.WriteString(escapeSlack(m.Body))
		b.WriteString("\n")
	}
	for _, kv := range orderedFields(m.Fields) {
		fmt.Fprintf(&b, "%s: %s\n", escapeSlack(kv[0]), escapeSlack(kv[1]))
	}
	fmt.Fprintf(&b, "時刻: %s", m.Time.Local().Format("2006-01-02 15:04:05"))
	if suppressed > 0 {
		fmt.Fprintf(&b, "\n（通知の上限を超えたため、これまでに %d 件の通知を省略しました）", suppressed)
	}
	return b.String()
}

// escapeSlack は Slack で特別な意味を持つ文字（&、<、>）を置き換える（検知の内容に含まれる文字でリンクや呼び出しを作らせない）。
func escapeSlack(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func orderedFields(f map[string]string) [][2]string {
	var out [][2]string
	for _, k := range fieldOrder {
		if v, ok := f[k]; ok && v != "" {
			out = append(out, [2]string{k, v})
		}
	}
	var rest []string
	for k := range f {
		if !slices.Contains(fieldOrder, k) && f[k] != "" {
			rest = append(rest, k)
		}
	}
	slices.Sort(rest)
	for _, k := range rest {
		out = append(out, [2]string{k, f[k]})
	}
	return out
}

// postJSON は v を JSON で POST し、2xx でなければエラーを返す。
func postJSON(ctx context.Context, c *http.Client, d Destination, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "susanoo")
	for k, v := range d.Headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return redact(err, d.URL)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyLog))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

// redact は、エラーの文に含まれる URL を、ホストまでに縮める（Slack の URL などはトークンを含むため、ログに残さない）。
func redact(err error, raw string) error {
	u, perr := url.Parse(raw)
	if perr != nil {
		return errors.New("送れません")
	}
	short := u.Scheme + "://" + u.Host + "/…"
	return errors.New(strings.ReplaceAll(err.Error(), raw, short))
}

// mailMessage はメールの全体（ヘッダーと本文）を作る。題名は RFC 2047、本文は UTF-8 を base64 にする。
func mailMessage(e Email, m Message, suppressed int, now time.Time) []byte {
	var body strings.Builder
	if m.Body != "" {
		body.WriteString(m.Body + "\r\n\r\n")
	}
	for _, kv := range orderedFields(m.Fields) {
		fmt.Fprintf(&body, "%s: %s\r\n", kv[0], kv[1])
	}
	fmt.Fprintf(&body, "時刻: %s\r\n", m.Time.Local().Format("2006-01-02 15:04:05"))
	if suppressed > 0 {
		fmt.Fprintf(&body, "\r\n（通知の上限を超えたため、これまでに %d 件の通知を省略しました）\r\n", suppressed)
	}
	body.WriteString("\r\n-- \r\nsusanoo\r\n")

	var b bytes.Buffer
	host := e.From[strings.LastIndexByte(e.From, '@')+1:]
	fmt.Fprintf(&b, "From: %s\r\n", e.From)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(e.To, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.BEncoding.Encode("utf-8", "[susanoo] "+m.Title))
	fmt.Fprintf(&b, "Date: %s\r\n", now.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", rand.Text(), host)
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(body.String()))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return b.Bytes()
}

// sendMail は SMTP でメールを送る。
func sendMail(ctx context.Context, e Email, msg []byte) error {
	host, _, _ := net.SplitHostPort(e.Server)
	d := net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	if e.TLS == "tls" {
		conn, err = (&tls.Dialer{NetDialer: &d, Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}).DialContext(ctx, "tcp", e.Server)
	} else {
		conn, err = d.DialContext(ctx, "tcp", e.Server)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if e.TLS == "" || e.TLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("SMTP サーバーが STARTTLS に対応していません（暗号化しないなら tls を none にしてください）")
		}
		if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if e.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", e.Username, e.Password, host)); err != nil {
			return err
		}
	}
	if err := c.Mail(e.From); err != nil {
		return err
	}
	for _, to := range e.To {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
