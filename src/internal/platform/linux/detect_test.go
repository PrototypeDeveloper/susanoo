//go:build linux

package linux

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"susanoo/internal/event"
	"susanoo/internal/platform"
)

// privileged は root で動いているかを返す。root でない fanotify は、ほかのプロセスのイベントの PID を 0 で渡すため、
// プロセスの確認は root のときだけ行う（実運用の執行部は root で動く）。
func privileged() bool { return os.Geteuid() == 0 }

// 永続化の場所と権限の設定の場所の変更は、変更したプロセスと内容の抜粋とともに検知結果になる（C4）。
func TestPersistenceFinding(t *testing.T) {
	dir := t.TempDir()
	persist, priv := filepath.Join(dir, "cron.d"), filepath.Join(dir, "sudoers.d")
	for _, d := range []string{persist, priv} {
		os.Mkdir(d, 0o755)
	}
	m, err := newFileMonitor(FileConfig{Persistence: []string{persist}, Privilege: []string{priv}}, nil, nil, quiet)
	if err != nil {
		t.Skipf("FID 方式の fanotify を使えない: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var col collector
	go m.run(ctx, col.emit)
	go func() { <-ctx.Done(); m.close() }()

	job := filepath.Join(persist, "backup")
	sh(t, "printf '# 毎日\\n0 3 * * * root /usr/local/bin/backup --all\\n' > "+job)
	f := col.find(t, "永続化の場所の変更", func(e *event.Event) bool {
		return e.FindingInfo.HasType(event.FindingTypePersistence) && len(e.Evidences) > 0 && e.Evidences[0].File.Path == job
	})
	if !strings.Contains(f.Message, "0 3 * * * root /usr/local/bin/backup --all") || (privileged() && (f.Evidences[0].Process == nil || f.Evidences[0].Process.Name != "sh")) {
		t.Errorf("検知結果 = %s（%+v）", f.Message, f.Evidences[0].Process)
	}
	if d, _ := f.Unmapped["file_change"].(map[string]any); d["category"] != "persistence" || d["snippet"] == "" {
		t.Errorf("判断の材料 = %v", f.Unmapped)
	}
	// 記録のイベントも残る。
	col.find(t, "作成の記録", func(e *event.Event) bool {
		return e.ClassUID == event.ClassFileSystemActivity && e.ActivityID == event.FileCreate && e.File.Path == job
	})

	rule := filepath.Join(priv, "ops")
	sh(t, "echo 'ops ALL=(ALL) NOPASSWD: ALL' > "+rule)
	f = col.find(t, "権限の設定の変更", func(e *event.Event) bool {
		return e.FindingInfo.HasType(event.FindingTypePrivilegeChange) && len(e.Evidences) > 0 && e.Evidences[0].File.Path == rule
	})
	if strings.Contains(f.Message, "内容") {
		t.Errorf("権限の設定の場所では内容の抜粋を付けない: %s", f.Message)
	}

	// 同じプロセスの同じファイルの変更は、1 分の間は 1 件にまとめる。
	m.mu.Lock()
	n := len(m.findings)
	m.mu.Unlock()
	key, _ := dirKey(persist)
	if es := m.handle(fidEvent{mask: fanCloseWrite, pid: 1, dir: key, name: "backup"}, time.Now()); len(es) != 2 {
		t.Fatalf("別のプロセスの変更 = %d 件（記録と検知結果の 2 件のはず）", len(es))
	}
	if es := m.handle(fidEvent{mask: fanCloseWrite, pid: 1, dir: key, name: "backup"}, time.Now()); len(es) != 0 {
		t.Errorf("続けて届いた同じ変更を %d 件にした", len(es))
	}
	m.mu.Lock()
	if len(m.findings) != n+1 {
		t.Errorf("検知結果の記録 = %d", len(m.findings))
	}
	m.mu.Unlock()
}

// 認証情報のファイルは、ふだん読むプログラム以外が読んだら検知結果になる（C8、C9）。
func TestSensitiveRead(t *testing.T) {
	dir := t.TempDir()
	sshDir := filepath.Join(dir, ".ssh")
	os.Mkdir(sshDir, 0o700)
	key, pub, token := filepath.Join(sshDir, "id_ed25519"), filepath.Join(sshDir, "id_ed25519.pub"), filepath.Join(dir, "credentials")
	for _, p := range []string{key, pub, token} {
		os.WriteFile(p, []byte("secret\n"), 0o600)
	}
	m, err := newFileMonitor(FileConfig{Sensitive: []SensitiveSpec{
		{Path: filepath.Join(sshDir, "id_*"), Exclude: []string{"*.pub"}, Readers: []string{"ssh"}},
		{Path: token, Readers: []string{"sh"}},
	}}, nil, nil, quiet)
	if err != nil {
		t.Skipf("FID 方式の fanotify を使えない: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var col collector
	go m.run(ctx, col.emit)
	go func() { <-ctx.Done(); m.close() }()

	// シェルの組み込みのリダイレクトで読むと、読んだプロセスは sh（終わらずに残っているので名前が分かる）。
	sh(t, "read x < "+key+"; read y < "+pub+"; read z < "+token+"; sleep 0.3")
	f := col.find(t, "秘密鍵の読み取り", func(e *event.Event) bool {
		return e.FindingInfo.HasType(event.FindingTypeCredentialAccess) && e.Evidences[0].File.Path == key
	})
	if privileged() {
		if p := f.Evidences[0].Process; p == nil || p.Name != "sh" {
			t.Errorf("読んだプロセス = %+v", p)
		}
		// 公開鍵（対象外）と、読んでよいプログラム（sh）の読み取りは検知結果にしない。
		time.Sleep(200 * time.Millisecond)
		col.mu.Lock()
		for _, e := range col.evs {
			if e.FindingInfo != nil && e.FindingInfo.HasType(event.FindingTypeCredentialAccess) && e.Evidences[0].File.Path != key {
				t.Errorf("対象外か、読んでよいプログラムの読み取りを検知結果にした: %s", e.Message)
			}
		}
		col.mu.Unlock()
	}
	m.mu.Lock()
	clear(m.findings) // root でないときは PID が 0 で届き、同じファイルの読み取りがまとめられるので、数え直す
	m.mu.Unlock()

	// ふだん読むプログラム以外（cat）が読むと検知結果になる。ファイルの印で捕らえる。
	sh(t, "cat "+token+" > /dev/null")
	col.find(t, "認証情報の読み取り", func(e *event.Event) bool {
		return e.FindingInfo.HasType(event.FindingTypeCredentialAccess) && e.Evidences[0].File.Path == token
	})

	// 置き換えられたファイルには、印を付け直す。
	os.WriteFile(token+".new", []byte("secret2\n"), 0o600)
	os.Rename(token+".new", token)
	m.mu.Lock()
	old := m.fileKeys[token]
	m.markFile(sensitiveFile{path: token, readers: []string{"sh"}})
	fresh := m.fileKeys[token]
	m.mu.Unlock()
	if old == fresh {
		t.Error("置き換えられたファイルの印を付け直していない")
	}
	m.mu.Lock()
	clear(m.findings)
	m.mu.Unlock()
	before := time.Now()
	sh(t, "cat "+token+" > /dev/null")
	col.find(t, "置き換えた後の読み取り", func(e *event.Event) bool {
		return e.FindingInfo != nil && e.FindingInfo.HasType(event.FindingTypeCredentialAccess) && e.Evidences[0].File.Path == token && e.Time >= before.UnixMilli()
	})
}

func sh(t *testing.T, script string) {
	t.Helper()
	if out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v %s", script, err, out)
	}
}

func TestWatchRuleAndReaders(t *testing.T) {
	r := watchRule{kind: kindSensitive, name: "id_*", exclude: []string{"*.pub"}}
	for name, want := range map[string]bool{"id_rsa": true, "id_ed25519": true, "id_rsa.pub": false, "known_hosts": false} {
		if got := r.matches(name); got != want {
			t.Errorf("%s = %v", name, got)
		}
	}
	all := watchRule{kind: kindRecord}
	if !all.matches("anything") {
		t.Error("名前なしの条件がすべてに当てはまらない")
	}
	ssh := &event.Process{Name: "ssh", File: &event.File{Path: "/usr/bin/ssh"}}
	if !allowedReader(ssh, []string{"ssh"}) || !allowedReader(ssh, []string{"/usr/bin/ssh"}) || allowedReader(ssh, []string{"cat"}) {
		t.Error("読んでよいプログラムの見分けが違う")
	}
	if allowedReader(nil, []string{"ssh"}) || allowedReader(&event.Process{PID: 3}, []string{"ssh"}) {
		t.Error("分からないプロセスを読んでよいプログラムとした")
	}
}

func TestSnippet(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(content), 0o644)
		return p
	}
	for name, tc := range map[string]struct{ content, want string }{
		"ユニット":  {"[Unit]\nDescription=x\n\n[Service]\nExecStart=/usr/local/bin/agent  --daemon\n\n[Install]\nWantedBy=multi-user.target\n", "ExecStart=/usr/local/bin/agent --daemon"},
		"自動起動":  {"[Desktop Entry]\nType=Application\nExec=/opt/x/run\nName=x\n", "Exec=/opt/x/run"},
		"cron":  {"# comment\n*/5 * * * * root /tmp/.x\n", "*/5 * * * * root /tmp/.x"},
		"注釈だけ":  {"# nothing\n\n", ""},
		"バイナリ":  {"\x00\x01\x02", ""},
		"長い行":   {strings.Repeat("あ", 300), strings.Repeat("あ", snippetMax) + "…"},
		"UTF-8": {"echo 日本語\n\xff\xfe", "echo 日本語"},
	} {
		if got := snippet(write(name, tc.content)); got != tc.want {
			t.Errorf("%s = %q, 期待値 %q", name, got, tc.want)
		}
	}
	link := filepath.Join(dir, "unit.service")
	os.Symlink("/etc/systemd/system/agent.service", link)
	if got := snippet(link); got != "→ /etc/systemd/system/agent.service" {
		t.Errorf("シンボリックリンク = %q", got)
	}
	if snippet(filepath.Join(dir, "missing")) != "" {
		t.Error("ないファイルの抜粋が空でない")
	}
}

func TestModuleMonitor(t *testing.T) {
	data := []byte("ccm 20480 9 - Live 0x0000000000000000\nrfcomm 110592 4 - Live 0x0000000000000000\n")
	if got := parseModules(data); len(got) != 2 || got[0] != "ccm" || got[1] != "rfcomm" {
		t.Fatalf("parseModules = %v", got)
	}
	m := &moduleMonitor{known: map[string]bool{"ccm": true, "rfcomm": true}}
	now := time.Now()
	if es := m.check([]string{"ccm", "rfcomm"}, now); len(es) != 0 {
		t.Error("知っているモジュールを検知した")
	}
	es := m.check([]string{"ccm", "rfcomm", "evil_mod", "another"}, now)
	if len(es) != 1 || !es[0].FindingInfo.HasType(event.FindingTypeKernelModule) || !strings.Contains(es[0].Message, "evil_mod、another") {
		t.Fatalf("検知結果 = %+v", es)
	}
	if es := m.check([]string{"ccm", "rfcomm", "evil_mod", "another"}, now); len(es) != 0 {
		t.Error("同じモジュールを 2 回検知した")
	}
	real, err := newModuleMonitor(0)
	if err != nil {
		t.Skipf("/proc/modules を読めない: %v", err)
	}
	if real.interval != defaultModulePoll || len(real.known) == 0 {
		t.Errorf("既定 = %v、モジュール %d", real.interval, len(real.known))
	}
}

func TestAgentMatcher(t *testing.T) {
	m := newAgentMatcher(DefaultAgents())
	bash := ancestor{pid: 10, name: "bash", exe: "/usr/bin/bash", argv: "bash"}
	cases := []struct {
		name string
		anc  []ancestor
		want string
	}{
		{"なし", []ancestor{bash}, ""},
		{"comm", []ancestor{bash, {pid: 9, name: "claude", exe: "/usr/local/bin/claude", argv: "claude"}}, "claude"},
		{"node の中のパス", []ancestor{bash, {pid: 9, name: "node", exe: "/usr/bin/node", argv: "node /usr/lib/node_modules/@openai/codex/bin/codex.js"}}, "codex"},
		{"argv0", []ancestor{{pid: 9, name: "bash", exe: "/usr/bin/bash", argv: "gemini -c x"}}, "gemini"},
		{"深すぎる祖先は使わない（inspect が切る）", []ancestor{bash, bash, {pid: 9, name: "aider", argv: "aider"}}, "aider"},
	}
	for _, c := range cases {
		p := &event.Process{PID: 11, Name: "curl", CmdLine: "curl https://example.test"}
		tag, ok := m.of(p, c.anc)
		if ok != (c.want != "") || tag.Name != c.want {
			t.Errorf("%s = %+v, %v", c.name, tag, ok)
		}
	}
	// プロセス自身がエージェントなら、そのプロセスの PID を付ける。
	self := &event.Process{PID: 5, Name: "claude", File: &event.File{Path: "/usr/local/bin/claude"}}
	if tag, ok := m.of(self, nil); !ok || tag.PID != 5 || tag.Name != "claude" {
		t.Errorf("自身 = %+v, %v", tag, ok)
	}
	e := event.New(event.ClassProcessActivity, event.ProcessLaunch, event.SeverityInformational, time.Now())
	m.annotate(e, self, nil)
	if tag, _ := e.Unmapped["agent"].(agentTag); tag.Name != "claude" {
		t.Errorf("unmapped.agent = %v", e.Unmapped)
	}
	var none *agentMatcher
	if _, ok := none.of(self, nil); ok {
		t.Error("設定のないときに当てはまった")
	}
	if _, ok := newAgentMatcher([]AgentSpec{}).of(self, nil); ok {
		t.Error("空の設定で当てはまった")
	}
}

func TestEscalation(t *testing.T) {
	root := func(name string) *event.Process {
		return &event.Process{PID: 100, Name: name, User: &event.User{UID: "0"}}
	}
	user := ancestor{pid: 10, uid: "1000", name: "bash"}
	sudoRoot := ancestor{pid: 20, uid: "0", name: "sudo"}
	sudoUser := ancestor{pid: 20, uid: "1000", name: "sudo"}
	rootShell := ancestor{pid: 30, uid: "0", name: "bash"}
	for name, tc := range map[string]struct {
		p    *event.Process
		anc  []ancestor
		want string // 経路。空なら検知しない
	}{
		"sudo（実 UID が root）":     {root("ls"), []ancestor{sudoRoot, user}, "bash → sudo → ls"},
		"sudo（実 UID が利用者）":       {root("ls"), []ancestor{sudoUser, user}, "sudo → ls"},
		"root のシェルの中の 2 つ目のコマンド": {root("ls"), []ancestor{rootShell, sudoRoot, user}, ""},
		"root から root":           {root("sshd"), []ancestor{{pid: 1, uid: "0", name: "systemd"}}, ""},
		"利用者のプロセス":               {&event.Process{PID: 100, Name: "ls", User: &event.User{UID: "1000"}}, []ancestor{user}, ""},
		"利用者が分からない":              {root("ls"), []ancestor{{pid: 20, name: "x"}}, ""},
		"祖先がない":                  {root("init"), nil, ""},
	} {
		origin, via, ok := escalation(tc.p, tc.anc)
		got := strings.Join(via, " → ")
		if ok != (tc.want != "") || got != tc.want || (ok && origin.uid != "1000") {
			t.Errorf("%s = %q, %v（元 %+v）", name, got, ok, origin)
		}
	}
}

// 権限昇格の検知結果は、同じ元のプロセスからは 10 分に 1 件にまとめる。
func TestEscalationFindingDedupe(t *testing.T) {
	m := &execMonitor{escalations: map[int]time.Time{}}
	p := &event.Process{PID: 100, Name: "ls", User: &event.User{UID: "0"}}
	anc := []ancestor{{pid: 20, uid: "0", name: "sudo"}, {pid: 10, uid: "1000", name: "bash"}}
	now := time.Now()
	f := m.escalationFinding(p, anc, now)
	if f == nil || !f.FindingInfo.HasType(event.FindingTypePrivilegeEscalation) || !strings.Contains(f.Message, "利用者 1000 の bash（PID 10）") {
		t.Fatalf("検知結果 = %+v", f)
	}
	if m.escalationFinding(&event.Process{PID: 101, Name: "cat", User: &event.User{UID: "0"}}, anc, now.Add(time.Minute)) != nil {
		t.Error("同じ元からの昇格を続けて検知した")
	}
	if m.escalationFinding(p, []ancestor{{pid: 21, uid: "0", name: "sudo"}, {pid: 11, uid: "1000", name: "bash"}}, now) == nil {
		t.Error("別の元からの昇格を検知しない")
	}
	if m.escalationFinding(p, anc, now.Add(escalationDedupe+time.Second)) == nil {
		t.Error("時間が経っても検知しない")
	}
}

// inspect はプロセスの祖先から系譜を作る。
func TestInspectLineage(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "sleep 2")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	p, anc := inspect(cmd.Process.Pid)
	if p == nil || p.Name != "sh" || p.Parent == nil || p.Parent.PID != os.Getpid() || p.Parent.File == nil || p.Parent.User == nil {
		t.Fatalf("プロセス = %+v（親 %+v）", p, p.Parent)
	}
	if len(anc) == 0 || anc[0].pid != os.Getpid() || len(p.Lineage) == 0 || p.Lineage[len(p.Lineage)-1] != anc[0].exe {
		t.Errorf("祖先 = %+v、系譜 = %v", anc, p.Lineage)
	}
	c := newProcCache()
	c.put(cmd.Process.Pid, p, anc, time.Now())
	cmd.Process.Kill()
	cmd.Wait()
	if q, _ := c.inspect(cmd.Process.Pid); q == nil || q.Name != "sh" {
		t.Errorf("終わったプロセスの情報を引けない: %+v", q)
	}
	if q, _ := c.inspect(1 << 30); q == nil || q.Name != "" {
		t.Errorf("知らないプロセス = %+v", q)
	}
}

// 証拠として、プロセスの一覧、ソケットと持ち主、ログの末尾を集める（root でなくても自分のプロセスの分は集まる）。
func TestSnapshot(t *testing.T) {
	loopbackUp(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	logPath := filepath.Join(t.TempDir(), "auth.log")
	var b strings.Builder
	for i := range 300 {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	b.WriteString("bad \xff utf8\n")
	os.WriteFile(logPath, []byte(b.String()), 0o600)

	p := New(Config{EvidenceLogs: []string{logPath, "/nonexistent/log"}, Logger: quiet})
	if !p.Capabilities().Has(platform.CapEvidence) {
		t.Fatal("証拠の保全を申告していない")
	}
	s, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	self := slices.IndexFunc(s.Processes, func(x platform.SnapshotProcess) bool { return x.PID == os.Getpid() })
	if self < 0 || s.Processes[self].PPID != os.Getppid() || s.Processes[self].Exe == "" || s.Processes[self].Started == 0 {
		t.Fatalf("自分のプロセス = %+v（%d 件）", s.Processes, len(s.Processes))
	}
	if since := time.Since(time.UnixMilli(s.Processes[self].Started)); since < 0 || since > time.Hour {
		t.Errorf("起動した時刻 = %v", time.UnixMilli(s.Processes[self].Started))
	}
	for _, x := range s.Processes {
		if x.PID == 2 || x.PPID == 2 {
			t.Errorf("カーネルのスレッドを含む: %+v", x)
		}
	}
	listen := slices.IndexFunc(s.Connections, func(c platform.SnapshotConn) bool {
		return c.Proto == "tcp" && c.State == "listen" && c.Local == ln.Addr().String()
	})
	if listen < 0 || s.Connections[listen].PID != os.Getpid() || s.Connections[listen].Remote != "" {
		t.Errorf("待ち受け = %+v", s.Connections)
	}
	if len(s.Logs) != 1 || s.Logs[0].Path != logPath || len(s.Logs[0].Lines) != logTailLines || !s.Logs[0].Truncated {
		t.Fatalf("ログ = %+v", s.Logs)
	}
	if last := s.Logs[0].Lines[len(s.Logs[0].Lines)-1]; last != "bad ? utf8" {
		t.Errorf("最後の行 = %q", last)
	}
	if len(s.Errors) != 0 {
		t.Errorf("エラー = %v（ないログは飛ばす）", s.Errors)
	}
	if New(Config{EvidenceLogs: []string{"relative.log"}, Logger: quiet}).Capabilities().Has(platform.CapEvidence) {
		t.Error("相対パスのログを受け付けた")
	}
}

func TestTailLog(t *testing.T) {
	dir := t.TempDir()
	short := filepath.Join(dir, "short.log")
	os.WriteFile(short, []byte("a\nb\n"), 0o600)
	l, err := tailLog(short, 10, 1024)
	if err != nil || len(l.Lines) != 2 || l.Truncated {
		t.Errorf("短いログ = %+v, %v", l, err)
	}
	big := filepath.Join(dir, "big.log")
	os.WriteFile(big, []byte(strings.Repeat("0123456789\n", 1000)), 0o600)
	l, _ = tailLog(big, 1000, 100) // 100 バイトだけ読む。途中から始まる最初の行は捨てる
	if !l.Truncated || len(l.Lines) == 0 || slices.ContainsFunc(l.Lines, func(s string) bool { return s != "0123456789" }) {
		t.Errorf("大きいログ = %+v", l)
	}
	empty := filepath.Join(dir, "empty.log")
	os.WriteFile(empty, nil, 0o600)
	if l, err := tailLog(empty, 10, 100); err != nil || l.Lines == nil || len(l.Lines) != 0 {
		t.Errorf("空のログ = %+v, %v", l, err)
	}
	if _, err := tailLog(dir, 10, 100); err == nil {
		t.Error("ディレクトリを読んだ")
	}
}

// fanotify の待ち行列があふれたら、黙って捨てずに、1 分に 1 回まで警告する。
func TestOverflowLogged(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, nil))
	m := &fileMonitor{log: log, watched: map[fidKey]*watchDir{}, files: map[fidKey]sensitiveFile{}, protected: map[fidKey]string{}}
	now := time.Now()
	for i := range 3 {
		if es := m.handle(fidEvent{mask: fanQOverflow}, now.Add(time.Duration(i)*time.Second)); len(es) != 0 {
			t.Fatalf("あふれの印からイベントを作った: %+v", es)
		}
	}
	m.handle(fidEvent{mask: fanQOverflow}, now.Add(2*time.Minute))
	if n := strings.Count(buf.String(), "取りこぼしました"); n != 2 || !strings.Contains(buf.String(), "回数=3") {
		t.Errorf("ログ = %s", buf.String())
	}
}
