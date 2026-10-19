//go:build linux

package linux

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"susanoo/internal/event"
)

// ログオンの記録（C4）。
//
// ログオンとログオフは、systemd-logind が /run/systemd/sessions に書くセッションのファイルを定期的に読んで捕らえる。
// pam_systemd を通るログオン（ssh、コンソール、画面）は、端末を割り当てない ssh の命令の実行も含めてセッションになる。
// 失敗したログオンは、認証のログ（auth.log、secure）の sshd と pam_unix の行から読む。認証のログのファイルがなければ、
// journalctl でジャーナルの auth と authpriv の記録を読む。どれも起動した後のものだけを記録する（それまでの分は読まない）。

const (
	DefaultSessionsDir = "/run/systemd/sessions"
	defaultLogonPoll   = 2 * time.Second
	maxSessions        = 4096
	maxSessionFile     = 16 << 10
	maxAuthReadPerPoll = 1 << 20
	maxAuthLine        = 8 << 10
	maxLogonField      = 256
	authFailureRate    = 2   // 失敗したログオンのイベントを 1 秒あたりこれだけ、
	authFailureBurst   = 120 // まとめてこれだけまで送る（総当たりの大量の行で送り先をあふれさせない）
	journalRetryMin    = 10 * time.Second
	journalRetryMax    = 5 * time.Minute
	emptyUser          = "（空）"
)

// DefaultAuthLogs は既定の認証のログ（Debian 系と Red Hat 系）。
func DefaultAuthLogs() []string { return []string{"/var/log/auth.log", "/var/log/secure"} }

var journalctlPaths = []string{"/usr/bin/journalctl", "/bin/journalctl"}

// LogonConfig はログオンの記録の設定。
type LogonConfig struct {
	Enabled     bool
	SessionsDir string        // systemd-logind のセッションのディレクトリ。空なら DefaultSessionsDir
	AuthLogs    []string      // 認証のログ。nil なら DefaultAuthLogs、空なら読まない
	Journal     bool          // 認証のログのファイルが 1 つもないとき、journalctl でジャーナルを読む
	Journalctl  string        // journalctl の場所。空なら既定の場所を探す
	Poll        time.Duration // セッションと認証のログを読む間隔。既定 2 秒
}

type logonMonitor struct {
	cfg      LogonConfig
	log      *slog.Logger
	sessions *sessionWatcher // セッションのディレクトリがなければ nil
	tails    []*authTail
	journal  string // journalctl を使うならその場所
	limit    *limiter
	over     overflowLog
}

func newLogonMonitor(cfg LogonConfig, log *slog.Logger) (*logonMonitor, error) {
	if cfg.SessionsDir == "" {
		cfg.SessionsDir = DefaultSessionsDir
	}
	if cfg.AuthLogs == nil {
		cfg.AuthLogs = DefaultAuthLogs()
	}
	if cfg.Poll <= 0 {
		cfg.Poll = defaultLogonPoll
	}
	m := &logonMonitor{cfg: cfg, log: log, limit: newLimiter(authFailureRate, authFailureBurst)}
	if st, err := os.Stat(cfg.SessionsDir); err == nil && st.IsDir() {
		if m.sessions, err = newSessionWatcher(cfg.SessionsDir); err != nil {
			return nil, err
		}
	}
	var missing []string
	for _, path := range cfg.AuthLogs {
		t, err := openTail(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) && log != nil {
				log.Warn("認証のログを読めません", "ファイル", path, "エラー", err)
			}
			missing = append(missing, path)
			continue
		}
		m.tails = append(m.tails, t)
	}
	if len(m.tails) == 0 && cfg.Journal {
		m.journal = findJournalctl(cfg.Journalctl)
	}
	if m.sessions == nil && len(m.tails) == 0 && m.journal == "" {
		m.close()
		return nil, fmt.Errorf("ログオンの情報源がありません（%s、認証のログ %s、journalctl）", cfg.SessionsDir, strings.Join(missing, "、"))
	}
	return m, nil
}

// findJournalctl は journalctl の場所を返す。なければ空。
func findJournalctl(path string) string {
	candidates := journalctlPaths
	if path != "" {
		candidates = []string{path}
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0 {
			return p
		}
	}
	return ""
}

func (m *logonMonitor) close() error {
	for _, t := range m.tails {
		t.close()
	}
	return nil
}

func (m *logonMonitor) run(ctx context.Context, emit func(*event.Event)) error {
	if m.journal != "" {
		go m.runJournal(ctx, emit)
	}
	t := time.NewTicker(m.cfg.Poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
		now := time.Now()
		if m.sessions != nil {
			for _, e := range m.sessions.poll(now) {
				emit(e)
			}
		}
		for _, tail := range m.tails {
			for _, line := range tail.poll() {
				ident, pid, msg, ok := parseSyslogLine(line)
				if !ok {
					continue
				}
				m.handle(parseAuthMessage(ident, pid, msg), tail.path, now, emit)
			}
		}
	}
}

// handle は認証のログの 1 件をイベントにする。成功したログオンは、セッションを読めないときだけ記録する（重ねないため）。
func (m *logonMonitor) handle(r *authRecord, source string, now time.Time, emit func(*event.Event)) {
	if r == nil || (r.success && m.sessions != nil) {
		return
	}
	if !r.success && !m.limit.allow(now) {
		m.over.note(m.log, "失敗したログオン", now)
		return
	}
	e := r.event(now)
	e.Unmapped = map[string]any{"auth_log": map[string]any{"source": source}}
	if n := m.limit.takeDropped(); n > 0 {
		e.Unmapped["suppressed"] = n // 上限を超えて記録しなかった失敗の数
	}
	emit(e)
}

// runJournal は journalctl でジャーナルを読み続ける。journalctl が止まったら、間をおいて起動し直す。
func (m *logonMonitor) runJournal(ctx context.Context, emit func(*event.Event)) {
	wait := journalRetryMin
	for {
		begin := time.Now()
		err := m.journalOnce(ctx, emit)
		if ctx.Err() != nil {
			return
		}
		if time.Since(begin) > journalRetryMax {
			wait = journalRetryMin
		}
		if m.log != nil {
			m.log.Warn("ジャーナルの読み取りが止まりました。間をおいて試し直します", "エラー", err, "待ち時間", wait)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, journalRetryMax)
	}
}

func (m *logonMonitor) journalOnce(ctx context.Context, emit func(*event.Event)) error {
	cmd := exec.CommandContext(ctx, m.journal, "--follow", "--lines=0", "--output=json", "--no-pager", "--quiet",
		"SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10")
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	var stderr bytes.Buffer
	cmd.Stderr = &limitedWriter{w: &stderr, n: 4 << 10}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		ident, pid, msg, ok := parseJournalLine(sc.Bytes())
		if !ok {
			continue
		}
		m.handle(parseAuthMessage(ident, pid, msg), "journal", time.Now(), emit)
	}
	err = cmd.Wait()
	if err == nil {
		err = errors.New("journalctl が終了しました")
	}
	if s := strings.TrimSpace(stderr.String()); s != "" {
		err = fmt.Errorf("%w: %s", err, s)
	}
	return err
}

// limitedWriter は n バイトまでだけ書き、残りは捨てる。
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := min(len(p), l.n)
		l.w.Write(p[:k])
		l.n -= k
	}
	return len(p), nil
}

// ---- systemd-logind のセッション ----

type sessionState struct {
	info   map[string]string
	logged bool // ログオンを記録した（起動する前からのセッションは記録しない）
	closed bool // ログオフを記録した
}

type sessionWatcher struct {
	dir   string
	known map[string]*sessionState
}

func newSessionWatcher(dir string) (*sessionWatcher, error) {
	cur, err := scanSessions(dir)
	if err != nil {
		return nil, err
	}
	w := &sessionWatcher{dir: dir, known: map[string]*sessionState{}}
	for id, info := range cur {
		w.known[id] = &sessionState{info: info}
	}
	return w, nil
}

// poll はセッションの一覧を読み、新しいセッションをログオン、なくなったか閉じ始めたセッションをログオフにする。
func (w *sessionWatcher) poll(now time.Time) []*event.Event {
	cur, err := scanSessions(w.dir)
	if err != nil {
		return nil
	}
	var out []*event.Event
	for id, info := range cur {
		s := w.known[id]
		if s == nil {
			s = &sessionState{info: info}
			w.known[id] = s
			if userSession(info) && info["STATE"] != "closing" {
				s.logged = true
				out = append(out, sessionEvent(id, info, event.AuthLogon, now))
			}
			continue
		}
		s.info = info
		if s.logged && !s.closed && info["STATE"] == "closing" {
			s.closed = true
			out = append(out, sessionEvent(id, info, event.AuthLogoff, now))
		}
	}
	for id, s := range w.known {
		if _, ok := cur[id]; ok {
			continue
		}
		if s.logged && !s.closed {
			out = append(out, sessionEvent(id, s.info, event.AuthLogoff, now))
		}
		delete(w.known, id)
	}
	return out
}

// userSession は利用者のログオンのセッションか（画面のログオンの待ち受けや、systemd の利用者のマネージャーではないか）を返す。
func userSession(info map[string]string) bool {
	c := info["CLASS"]
	return (c == "" || strings.HasPrefix(c, "user")) && (info["USER"] != "" || info["UID"] != "")
}

// scanSessions はセッションのディレクトリのファイルを読む。名前が「.」で始まるもの（書きかけ）は読まない。
func scanSessions(dir string) (map[string]map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]string{}
	for _, e := range entries {
		if len(out) >= maxSessions {
			break
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") || !e.Type().IsRegular() {
			continue
		}
		data, err := readLimited(filepath.Join(dir, name), maxSessionFile)
		if err != nil {
			continue
		}
		out[name] = parseEnvFile(data)
	}
	return out, nil
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

// parseEnvFile は「名前=値」の行を読む（systemd の環境変数のファイルの形。値は「"」で囲み、「\」で文字を逃がすことがある）。
func parseEnvFile(data []byte) map[string]string {
	out := map[string]string{}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || k == "" {
			continue
		}
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			var sb strings.Builder
			for i := 1; i < len(v)-1; i++ {
				if v[i] == '\\' && i+1 < len(v)-1 {
					i++
				}
				sb.WriteByte(v[i])
			}
			v = sb.String()
		}
		out[k] = clip(v)
	}
	return out
}

// clip は記録する値の長さを抑える。
func clip(s string) string {
	if len(s) > maxLogonField {
		return s[:maxLogonField]
	}
	return s
}

// sessionEvent はセッションのログオンかログオフのイベントを作る。
func sessionEvent(id string, info map[string]string, activity int, now time.Time) *event.Event {
	e := event.New(event.ClassAuthentication, activity, event.SeverityInformational, now)
	e.User = &event.User{Name: info["USER"], UID: info["UID"]}
	e.StatusID = event.StatusSuccess
	remote := info["REMOTE"] == "1"
	e.IsRemote = &remote
	tty := info["TTY"]
	switch {
	case remote && tty != "":
		e.LogonTypeID = event.LogonRemoteInteractive
	case remote:
		e.LogonTypeID = event.LogonNetwork
	default:
		e.LogonTypeID = event.LogonInteractive
	}
	if svc := info["SERVICE"]; svc != "" {
		e.Service = &event.Service{Name: svc}
	}
	e.Session = &event.Session{UID: id, Terminal: tty}
	if usec, err := strconv.ParseInt(info["REALTIME"], 10, 64); err == nil && usec > 0 {
		e.Session.CreatedTime = usec / 1000
	}
	e.SrcEndpoint = endpointOf(info["REMOTE_HOST"], 0)
	if pid, err := strconv.Atoi(info["LEADER"]); err == nil && pid > 0 {
		e.LogonProcess = &event.Process{PID: pid}
		if activity == event.AuthLogon {
			e.LogonProcess.Name = readAncestor(pid).name
		}
	}
	extra := map[string]any{}
	for _, k := range []string{"CLASS", "TYPE", "SEAT", "REMOTE_USER", "DESKTOP"} {
		if v := info[k]; v != "" {
			extra[strings.ToLower(k)] = v
		}
	}
	if len(extra) > 0 {
		e.Unmapped = map[string]any{"logind": extra}
	}
	user := orElse(info["USER"], "uid "+info["UID"])
	what := "ログオンしました"
	if activity == event.AuthLogoff {
		what = "ログオフしました"
	}
	e.Message = fmt.Sprintf("利用者 %s が %s で%s（%s）", user, orElse(info["SERVICE"], "不明なサービス"), what, logonPlace(remote, info["REMOTE_HOST"], tty))
	return e
}

func logonPlace(remote bool, host, tty string) string {
	var parts []string
	switch {
	case remote && host != "":
		parts = append(parts, host+" から")
	case remote:
		parts = append(parts, "遠隔")
	default:
		parts = append(parts, "端末の前")
	}
	if tty != "" {
		parts = append(parts, tty)
	}
	return strings.Join(parts, "、")
}

func orElse(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// endpointOf は相手のアドレス（名前のこともある）を端点にする。
func endpointOf(host string, port int) *event.Endpoint {
	if host == "" {
		return nil
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return &event.Endpoint{IP: a.Unmap().String(), Port: port}
	}
	return &event.Endpoint{Hostname: clip(host), Port: port}
}

// ---- 認証のログ ----

// authTail は認証のログを末尾から読み進める。ログの切り替え（名前を変えて新しいファイルを作る、切り詰める）にも追従する。
type authTail struct {
	path     string
	f        *os.File
	dev, ino uint64
	off      int64
	partial  []byte
	skipping bool // 長すぎる行の残りを読み捨てている
}

// openTail はファイルを開き、今の末尾から読み始める。
func openTail(path string) (*authTail, error) {
	t := &authTail{path: path}
	if err := t.reopen(); err != nil {
		return nil, err
	}
	off, err := t.f.Seek(0, io.SeekEnd)
	if err != nil {
		t.close()
		return nil, err
	}
	t.off = off
	return t, nil
}

func (t *authTail) reopen() error {
	f, err := os.Open(t.path)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return fmt.Errorf("%s は通常のファイルではありません", t.path)
	}
	if t.f != nil {
		t.f.Close()
	}
	t.f, t.off, t.partial, t.skipping = f, 0, nil, false
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		t.dev, t.ino = uint64(sys.Dev), sys.Ino
	}
	return nil
}

func (t *authTail) close() {
	if t.f != nil {
		t.f.Close()
		t.f = nil
	}
}

// poll は増えた分の行を返す。ファイルが切り替わっていたら、古いファイルの残りを読んでから新しいファイルの先頭から読む。
func (t *authTail) poll() []string {
	lines := t.read()
	st, err := os.Stat(t.path)
	if err != nil {
		return lines // 切り替えの途中（新しいファイルがまだない）
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	switch {
	case ok && (uint64(sys.Dev) != t.dev || sys.Ino != t.ino):
		if t.reopen() == nil {
			lines = append(lines, t.read()...)
		}
	case st.Size() < t.off: // 切り詰められた（切り詰めた直後に、前と同じ大きさまで書かれると気付かない）
		if _, err := t.f.Seek(0, io.SeekStart); err == nil {
			t.off, t.partial, t.skipping = 0, nil, false
			lines = append(lines, t.read()...)
		}
	}
	return lines
}

func (t *authTail) read() []string {
	if t.f == nil {
		return nil
	}
	data, _ := io.ReadAll(io.LimitReader(t.f, maxAuthReadPerPoll))
	t.off += int64(len(data))
	var lines []string
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			if !t.skipping {
				t.partial = append(t.partial, data...)
				if len(t.partial) > maxAuthLine {
					t.partial, t.skipping = nil, true
				}
			}
			break
		}
		if !t.skipping {
			line := append(t.partial, data[:i]...)
			if len(line) <= maxAuthLine {
				lines = append(lines, string(line))
			}
		}
		t.partial, t.skipping = nil, false
		data = data[i+1:]
	}
	return lines
}

// syslog の行（「Oct 19 10:00:00 host prog[pid]: 本文」か「2026-10-19T10:00:00.000000+09:00 host prog[pid]: 本文」）。
var syslogLine = regexp.MustCompile(`^(?:[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+) \S+ ([^\s\[:]+)(?:\[(\d+)\])?: (.*)$`)

// parseSyslogLine は syslog の行から、プログラムの名前、PID、本文を取り出す。
func parseSyslogLine(line string) (ident string, pid int, msg string, ok bool) {
	m := syslogLine.FindStringSubmatch(line)
	if m == nil {
		return "", 0, "", false
	}
	pid, _ = strconv.Atoi(m[2])
	return m[1], pid, m[3], true
}

// parseJournalLine は journalctl -o json の 1 行から、プログラムの名前、PID、本文を取り出す。
func parseJournalLine(line []byte) (ident string, pid int, msg string, ok bool) {
	var j map[string]json.RawMessage
	if json.Unmarshal(line, &j) != nil {
		return "", 0, "", false
	}
	str := func(k string) string {
		var s string
		if json.Unmarshal(j[k], &s) == nil {
			return s
		}
		var b []byte // 文字として表せない値は、バイトの配列になる
		var nums []int
		if json.Unmarshal(j[k], &nums) == nil {
			for _, n := range nums {
				b = append(b, byte(n))
			}
		}
		return string(b)
	}
	msg = str("MESSAGE")
	if msg == "" {
		return "", 0, "", false
	}
	ident = orElse(str("SYSLOG_IDENTIFIER"), str("_COMM"))
	pid, _ = strconv.Atoi(orElse(str("SYSLOG_PID"), str("_PID")))
	return ident, pid, msg, true
}

// authRecord は認証のログから読んだ 1 件。
type authRecord struct {
	success bool
	user    string
	invalid bool // 存在しない利用者
	host    string
	port    int
	method  string
	service string
	ident   string
	pid     int
}

var (
	sshFailed   = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(.*) from (\S+) port (\d+)`)
	sshInvalid  = regexp.MustCompile(`^Invalid user (.*) from (\S+?)(?: port (\d+))?$`)
	sshAccepted = regexp.MustCompile(`^Accepted (\S+) for (.*) from (\S+) port (\d+)`)
	pamFailure  = regexp.MustCompile(`^pam_unix\(([^:)]+):auth\): authentication failure;(.*)$`)
)

// parseAuthMessage は認証のログの本文を読む。ログオンに関係のない行は nil を返す。
//
// sshd の「Invalid user」（存在しない利用者への接続ごとに 1 回）と、存在する利用者の「Failed」（認証の試みごと）を失敗にする。
// 存在しない利用者の「Failed ... for invalid user」は、「Invalid user」と重なるので数えない。pam_unix の認証の失敗は、
// sshd のもの（sshd の行と重なる）を除いて、login、su、sudo などの失敗にする。
func parseAuthMessage(ident string, pid int, msg string) *authRecord {
	r := &authRecord{ident: ident, pid: pid}
	if m := sshFailed.FindStringSubmatch(msg); m != nil {
		if m[2] != "" {
			return nil
		}
		r.method, r.user, r.host = m[1], m[3], m[4]
		r.port, _ = strconv.Atoi(m[5])
		r.service = "sshd"
		return r.clean()
	}
	if m := sshInvalid.FindStringSubmatch(msg); m != nil {
		r.user, r.host, r.invalid, r.service = m[1], m[2], true, "sshd"
		r.port, _ = strconv.Atoi(m[3])
		return r.clean()
	}
	if m := sshAccepted.FindStringSubmatch(msg); m != nil {
		r.success, r.method, r.user, r.host, r.service = true, m[1], m[2], m[3], "sshd"
		r.port, _ = strconv.Atoi(m[4])
		return r.clean()
	}
	if m := pamFailure.FindStringSubmatch(msg); m != nil {
		r.service = m[1]
		if strings.HasPrefix(r.service, "sshd") {
			return nil
		}
		kv := map[string]string{}
		for _, f := range strings.Fields(m[2]) {
			if k, v, ok := strings.Cut(f, "="); ok {
				kv[k] = v
			}
		}
		r.user = orElse(kv["user"], kv["ruser"])
		r.host = kv["rhost"]
		r.method = "password"
		return r.clean()
	}
	return nil
}

func (r *authRecord) clean() *authRecord {
	r.user, r.host, r.method, r.service = clip(r.user), clip(r.host), clip(r.method), clip(r.service)
	if r.user == "" {
		r.user = emptyUser
	}
	return r
}

// event は認証のログの 1 件をログオンのイベントにする。
func (r *authRecord) event(now time.Time) *event.Event {
	sev := event.SeverityInformational
	status := event.StatusSuccess
	if !r.success {
		sev, status = event.SeverityLow, event.StatusFailure
	}
	e := event.New(event.ClassAuthentication, event.AuthLogon, sev, now)
	e.User = &event.User{Name: r.user}
	e.StatusID = status
	remote := r.host != "" || r.service == "sshd"
	e.IsRemote = &remote
	e.LogonTypeID = event.LogonInteractive
	if remote {
		e.LogonTypeID = event.LogonNetwork
	}
	e.AuthProtocol = r.method
	e.Service = &event.Service{Name: r.service}
	e.SrcEndpoint = endpointOf(r.host, r.port)
	if r.pid > 0 || r.ident != "" {
		e.LogonProcess = &event.Process{PID: r.pid, Name: clip(r.ident)}
	}
	from := ""
	if r.host != "" {
		from = r.host + " から、"
	}
	switch {
	case r.success:
		e.Message = fmt.Sprintf("利用者 %s が %s でログオンしました（%s%s）", r.user, r.service, from, r.method)
	case r.invalid:
		e.StatusDetail = "存在しない利用者"
		e.Message = fmt.Sprintf("%s で存在しない利用者 %s へのログオンを試みました（%s）", r.service, r.user, strings.TrimSuffix(from, "、"))
	default:
		e.StatusDetail = "認証の失敗"
		e.Message = fmt.Sprintf("利用者 %s の %s でのログオンに失敗しました（%s%s）", r.user, r.service, from, r.method)
	}
	return e
}
