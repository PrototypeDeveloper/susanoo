//go:build linux

package privsep

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/client"
	"susanoo/internal/controller"
	"susanoo/internal/event"
	"susanoo/internal/honeytoken"
	"susanoo/internal/keys"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/platform"
	"susanoo/internal/platform/platformtest"
	"susanoo/internal/policy"
	"susanoo/internal/sign"
)

// 試験の通信はループバック（127.0.0.1）と socketpair だけで行う。

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

var caps = platform.Capabilities{OS: "linux", Features: []platform.Capability{platform.CapHoneytoken, platform.CapIsolation}}

func socketpair(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, b := os.NewFile(uintptr(fds[0]), "executor"), os.NewFile(uintptr(fds[1]), "analyzer")
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

type nopEnforcer struct{}

func (nopEnforcer) Sync(context.Context, map[netip.Addr]policy.IsolationLevel, map[string]policy.IsolationLevel) error {
	return nil
}

func startController(t *testing.T, env *pkitest.Env) netip.AddrPort {
	t.Helper()
	ctrl, err := controller.New(controller.Config{
		Dir:    t.TempDir(),
		CA:     env.CA.Pool(),
		Cert:   env.Leaf(t, pki.RoleController, "main"),
		Signer: env.Signer,
		Policy: &policy.Policy{
			Version: 1, Name: "試験", IssuedAt: time.Now(), Response: policy.ResponseEnforce, OnFailure: policy.FailOpen,
			Groups: []policy.Group{{Name: policy.DefaultGroup, Egress: policy.Egress{Default: policy.EgressAllow}, Isolation: policy.IsolateManagement}},
		},
		Enforcer: nopEnforcer{},
		Logger:   quiet,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { ctrl.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return netip.MustParseAddrPort(ln.Addr().String())
}

type executor struct {
	local *client.Local
	cert  [][]byte
	fake  *platformtest.Fake
	stop  context.CancelFunc
	done  chan error
}

// startExecutor は執行部を動かし、解析部の側の端を返す。
func startExecutor(t *testing.T, env *pkitest.Env, addr netip.AddrPort) (*executor, *os.File) {
	t.Helper()
	cert := env.Leaf(t, pki.RoleClient, "pc-001")
	fake := platformtest.New(caps)
	local, err := client.NewLocal(client.LocalConfig{
		Cert: cert, CommandKey: env.Signer.PublicKey(), StateDir: t.TempDir(), Controller: addr,
		CheckInterval: 50 * time.Millisecond, Platform: fake, Logger: quiet,
	})
	if err != nil {
		t.Fatal(err)
	}
	ours, theirs := socketpair(t)
	ctx, cancel := context.WithCancel(context.Background())
	ex := &executor{local: local, cert: cert.Certificate, fake: fake, stop: cancel, done: make(chan error, 1)}
	hello := Hello{Controller: addr.String(), CA: [][]byte{env.CA.Cert.Raw}, Chain: cert.Certificate, HeartbeatInterval: 50 * time.Millisecond}
	go func() { ex.done <- Serve(ctx, ours, local, hello, quiet) }()
	t.Cleanup(func() { cancel(); <-ex.done })
	return ex, theirs
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s を待ちきれない", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// 執行部と解析部を socketpair でつなぎ、おとりへの接触から隔離までを通す。
// 解析部は TLS の署名も、ハートビートも、指示の適用も執行部に頼む。
func TestSeparatedClient(t *testing.T) {
	env := pkitest.New(t)
	addr := startController(t, env)
	ex, theirs := startExecutor(t, env, addr)

	remote, hello, err := Dial(theirs, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if hello.Controller != addr.String() || len(hello.Chain) != 1 || hello.HeartbeatInterval != 50*time.Millisecond {
		t.Fatalf("設定 = %+v", hello)
	}
	pool, err := hello.CertPool()
	if err != nil {
		t.Fatal(err)
	}
	agent, err := client.New(client.Config{
		Controller: addr, CA: pool, Chain: hello.Chain, HeartbeatInterval: hello.HeartbeatInterval, Executor: remote, Logger: quiet,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	agentDone := make(chan struct{})
	go func() { agent.Run(ctx); close(agentDone) }()
	defer func() { cancel(); <-agentDone }()

	e := honeytoken.Finding(honeytoken.Token{Path: "/home/u/.aws/credentials", Kind: honeytoken.KindAWS}, honeytoken.OpOpen, nil, time.Now())
	if err := ex.fake.Emit(context.Background(), *e); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "自己隔離", func() bool { return ex.fake.Isolated() != nil })
	if iso := ex.fake.Isolated(); iso.Level != policy.IsolateManagement || iso.Management[0] != addr {
		t.Errorf("自己隔離の指示 = %+v", iso)
	}

	// 執行部が隔離のルールの改ざんを見つけたら、イベントは解析部を通って CONTROLLER に届く。
	ex.fake.Tamper()
	waitFor(t, "自己隔離の入れ直し", func() bool { return ex.fake.Isolated() != nil })
}

// 乗っ取られた解析部が頼んでも、執行部は検証に通らないことはしない。
func TestExecutorRefusesMisuse(t *testing.T) {
	env := pkitest.New(t)
	ex, theirs := startExecutor(t, env, netip.MustParseAddrPort("127.0.0.1:1"))
	remote, _, err := Dial(theirs, quiet)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := remote.SignTLS(ctx, []byte("susanoo-sign-v1\x00command\x00{}")); err == nil {
		t.Error("TLS のクライアント認証でないものに署名した")
	}
	other, _ := keys.Generate()
	forger, _ := sign.NewSigner(other)
	payload, _ := json.Marshal(api.Command{DeviceID: "pc-001", Version: 99, Isolation: ""})
	if err := remote.Apply(ctx, forger.Sign(sign.PurposeCommand, payload)); err == nil {
		t.Error("偽造された指示を適用した")
	}
	payload, _ = json.Marshal(api.Command{DeviceID: "pc-001", Version: 5, Isolation: policy.IsolateFull})
	if err := remote.Apply(ctx, env.Signer.Sign(sign.PurposeCommand, payload)); err != nil || ex.fake.Isolated() == nil {
		t.Fatalf("正しい指示を適用しない: %v", err)
	}
	// ハートビートの状態は執行部が埋める。
	hb, err := remote.Heartbeat(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got api.Heartbeat
	json.Unmarshal(hb.Payload, &got)
	if got.Applied != 5 || got.Isolation != policy.IsolateFull || got.DeviceID != "pc-001" {
		t.Errorf("ハートビート = %+v", got)
	}
	// 知らない要求には、つながりを切らずにエラーを返す。
	if err := remote.p.call(ctx, "shell", nil, nil); err == nil || !strings.Contains(err.Error(), "知らない要求") {
		t.Errorf("知らない要求の応答 = %v", err)
	}
}

// 解析部は執行部が保存した証拠を受け取り、送ったことを知らせる。執行部は不正な ID を受け付けない（C11）。
func TestEvidenceOverPrivsep(t *testing.T) {
	env := pkitest.New(t)
	cert := env.Leaf(t, pki.RoleClient, "pc-001")
	fake := platformtest.New(platform.Capabilities{OS: "linux", Features: []platform.Capability{platform.CapIsolation, platform.CapEvidence}})
	local, err := client.NewLocal(client.LocalConfig{
		Cert: cert, CommandKey: env.Signer.PublicKey(), StateDir: t.TempDir(), Controller: netip.MustParseAddrPort("127.0.0.1:1"),
		CheckInterval: time.Hour, Platform: fake, Logger: quiet,
	})
	if err != nil {
		t.Fatal(err)
	}
	ours, theirs := socketpair(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, ours, local, Hello{Controller: "127.0.0.1:1", Chain: cert.Certificate}, quiet)
	}()
	t.Cleanup(func() { cancel(); <-done })
	remote, _, err := Dial(theirs, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := remote.NextEvidence(ctx); ok || err != nil {
		t.Fatalf("集める前の証拠 = %v, %v", ok, err)
	}
	payload, _ := json.Marshal(api.Command{DeviceID: "pc-001", Version: 3, Isolation: policy.IsolateManagement})
	if err := remote.Apply(ctx, env.Signer.Sign(sign.PurposeCommand, payload)); err != nil {
		t.Fatal(err)
	}
	var id string
	var envlp sign.Envelope
	waitFor(t, "証拠", func() bool {
		var ok bool
		id, envlp, ok, err = remote.NextEvidence(ctx)
		return ok && err == nil
	})
	v, _ := sign.NewVerifier(cert.Leaf.PublicKey.(ed25519.PublicKey))
	if body, err := v.Verify(sign.PurposeEvidence, envlp); err != nil || !strings.Contains(string(body), id) {
		t.Errorf("証拠の署名 = %v", err)
	}
	if err := remote.AckEvidence(ctx, "../state"); err == nil {
		t.Error("不正な ID を受け付けた")
	}
	if err := remote.AckEvidence(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := remote.NextEvidence(ctx); ok {
		t.Error("送った証拠をもう一度渡した")
	}
}

func frame(data []byte) []byte {
	b := make([]byte, 4, 4+len(data))
	binary.BigEndian.PutUint32(b, uint32(len(data)))
	return append(b, data...)
}

// 解析部から不正なフレームが届いたら、執行部はつながりを切ってエラーで止まる。
func TestServeRejectsMalformedFrames(t *testing.T) {
	for name, data := range map[string][]byte{
		"上限を超える長さ":  binary.BigEndian.AppendUint32(nil, maxFrame+1),
		"JSON でない":  frame([]byte("not json")),
		"知らない項目":    frame([]byte(`{"type":"apply","id":1,"exec":"/bin/sh"}`)),
		"後ろに余分なデータ": frame([]byte(`{"type":"heartbeat","id":1} {}`)),
		"中身に知らない項目": frame([]byte(`{"type":"apply","id":1,"body":{"purpose":"command","evil":1}}`)),
		"知らない知らせ":   frame([]byte(`{"type":"event","body":{}}`)),
	} {
		t.Run(name, func(t *testing.T) {
			env := pkitest.New(t)
			ex, theirs := startExecutor(t, env, netip.MustParseAddrPort("127.0.0.1:1"))
			c := newConn(theirs)
			var hello message
			if err := c.recv(&hello); err != nil || hello.Type != noticeHello {
				t.Fatalf("hello = %+v, %v", hello, err)
			}
			theirs.Write(data)
			select {
			case err := <-ex.done:
				if err == nil || errors.Is(err, ErrAnalyzerStopped) {
					t.Errorf("Serve の結果 = %v", err)
				}
				ex.done <- err // 後片付けのために戻す
			case <-time.After(5 * time.Second):
				t.Fatal("不正なフレームでつながりを切らない")
			}
		})
	}
}

// 解析部が止まると ErrAnalyzerStopped を、執行部が止まると解析部の要求は ErrExecutorStopped を返す。
func TestEitherSideStopping(t *testing.T) {
	env := pkitest.New(t)
	ex, theirs := startExecutor(t, env, netip.MustParseAddrPort("127.0.0.1:1"))
	remote, _, err := Dial(theirs, quiet)
	if err != nil {
		t.Fatal(err)
	}
	remote.Close()
	select {
	case err := <-ex.done:
		if !errors.Is(err, ErrAnalyzerStopped) {
			t.Errorf("Serve の結果 = %v", err)
		}
		ex.done <- err
	case <-time.After(5 * time.Second):
		t.Fatal("解析部が止まったことに気づかない")
	}

	ours, theirs2 := socketpair(t)
	go func() {
		c := newConn(ours)
		sendHello(c, Hello{})
		ours.Close()
	}()
	remote2, _, err := Dial(theirs2, quiet)
	if err != nil {
		t.Fatal(err)
	}
	<-remote2.Done()
	if _, err := remote2.Heartbeat(context.Background()); !errors.Is(err, ErrExecutorStopped) {
		t.Errorf("執行部が止まった後の要求 = %v", err)
	}
	out := make(chan event.Event)
	if err := remote2.Watch(context.Background(), out); !errors.Is(err, ErrExecutorStopped) {
		t.Errorf("執行部が止まった後の Watch = %v", err)
	}
}

// 執行部が止まると、解析部（Agent）も止まる。
func TestAnalyzerStopsWithExecutor(t *testing.T) {
	env := pkitest.New(t)
	addr := netip.MustParseAddrPort("127.0.0.1:1")
	ex, theirs := startExecutor(t, env, addr)
	remote, hello, err := Dial(theirs, quiet)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := hello.CertPool()
	if err != nil {
		t.Fatal(err)
	}
	agent, err := client.New(client.Config{Controller: addr, CA: pool, Chain: hello.Chain, HeartbeatInterval: 50 * time.Millisecond, Executor: remote, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- agent.Run(context.Background()) }()
	time.Sleep(100 * time.Millisecond)
	ex.stop()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run の結果 = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("執行部が止まっても解析部が止まらない")
	}
}

func TestCapMask(t *testing.T) {
	// CAP_DAC_READ_SEARCH、CAP_NET_ADMIN、CAP_SYS_PTRACE、CAP_SYS_ADMIN。
	if got := CapMask(ExecutorCaps); got != 0x281004 {
		t.Errorf("CapMask = %#x", got)
	}
	if _, _, err := lookupUser("65534"); err != nil {
		t.Error(err)
	}
	if _, _, err := lookupUser("susanoo-no-such-user"); err == nil {
		t.Error("存在しない利用者を見つけた")
	}
}

func FuzzParseFrame(f *testing.F) {
	f.Add([]byte(`{"type":"apply","id":1,"body":{"purpose":"command","key_id":"x","payload":"e30=","signature":"AA=="}}`))
	f.Add([]byte(`{"type":"sign_tls","id":2,"body":"AAAA"}`))
	f.Add([]byte(`{"type":"event","body":{"class_uid":1007}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var m message
		if parseFrame(data, &m) == nil {
			if _, err := json.Marshal(m); err != nil {
				t.Fatal(err)
			}
			var env sign.Envelope
			decodeBody(m.Body, &env)
			var e event.Event
			decodeBody(m.Body, &e)
		}
	})
}

// 権限を変える試験は、試験のプロセス自身を変えないよう、別のプロセスで動かす。
const helperEnv = "SUSANOO_PRIVSEP_TEST"

// spawnedArg は Spawn で起動し直した試験のプロセスに渡す引数（Spawn は環境変数を渡さないため）。
const spawnedArg = "privsep-spawned"

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == spawnedArg {
		os.Exit(helperSpawned())
	}
	switch os.Getenv(helperEnv) {
	case "harden":
		os.Exit(report(func() error {
			if err := Harden(); err != nil {
				return err
			}
			return SetName("susanoo-test")
		}))
	case "drop":
		os.Exit(report(func() error { return DropCapabilities(ExecutorCaps) }))
	}
	os.Exit(m.Run())
}

// report は f を実行し、/proc/self/status と、子プロセスの capability を出力する。
func report(f func() error) int {
	if err := f(); err != nil {
		fmt.Println("error:", err)
		if errors.Is(err, syscall.ENOTSUP) || strings.Contains(err.Error(), "cgo") {
			return 3
		}
		return 1
	}
	status, _ := os.ReadFile("/proc/self/status")
	os.Stdout.Write(status)
	child, _ := exec.Command("/bin/sh", "-c", "grep CapEff /proc/self/status").Output()
	fmt.Print("Child", string(child))
	return 0
}

// helperSpawned は、起動し直されたプロセスの状態を fd 3 で返す。
func helperSpawned() int {
	f, err := OpenConnFD()
	if err != nil {
		return 1
	}
	status, _ := os.ReadFile("/proc/self/status")
	wd, _ := os.Getwd()
	extra := make([]byte, 16)
	if x, err := InheritedFile(ConnFD+1, "extra"); err == nil {
		n, _ := x.Read(extra)
		extra = extra[:n]
	}
	fmt.Fprintf(f, "%sCwd:\t%s\nEnv:\t%d\nExtra:\t%s\n", status, wd, len(os.Environ()), extra)
	f.Close()
	return 0
}

func runHelper(t *testing.T, mode string) map[string]string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), helperEnv+"="+mode)
	out, err := cmd.Output()
	if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 3 {
		t.Skipf("cgo を使った試験の実行ファイルでは試せない（CGO_ENABLED=0 で作ってください）: %s", out)
	}
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return parseStatus(string(out))
}

func parseStatus(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

func TestHarden(t *testing.T) {
	st := runHelper(t, "harden")
	if st["NoNewPrivs"] != "1" || st["Name"] != "susanoo-test" {
		t.Errorf("NoNewPrivs = %q、Name = %q", st["NoNewPrivs"], st["Name"])
	}
}

// 執行部は 4 つの capability だけを残し、上限の集合からも外すので、実行したプログラムも同じ範囲に留まる。
func TestDropCapabilitiesWhenPrivileged(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root 権限が必要")
	}
	st := runHelper(t, "drop")
	want := fmt.Sprintf("%016x", CapMask(ExecutorCaps))
	for _, k := range []string{"CapEff", "CapPrm", "CapBnd", "ChildCapEff"} {
		if st[k] != want {
			t.Errorf("%s = %s（%s のはず）", k, st[k], want)
		}
	}
	if st["CapAmb"] != "0000000000000000" || st["CapInh"] != "0000000000000000" {
		t.Errorf("CapAmb = %s、CapInh = %s", st["CapAmb"], st["CapInh"])
	}
}

// 解析部は、補助グループも capability も環境変数も持たずに、指定した利用者で動く。
// 実行ファイルを /proc/self/exe で指すので、途中のディレクトリを利用者が辿れなくても起動できる。
func TestSpawnWhenPrivileged(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root 権限が必要")
	}
	uid, gid, err := lookupUser("nobody")
	if err != nil {
		t.Skip(err)
	}
	if _, _, err := Spawn("root", nil); err == nil {
		t.Error("解析部を root で起動した")
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	pw.Write([]byte("extra-ok"))
	pw.Close()
	a, conn, err := Spawn("nobody", []*os.File{pr}, spawnedArg)
	pr.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	out, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-a.Exited; err != nil {
		t.Fatalf("起動し直したプロセスが失敗しました: %v", err)
	}
	st := parseStatus(string(out))
	ids := func(n uint32) string { return strings.Repeat(fmt.Sprintf("%d\t", n), 3) + fmt.Sprint(n) }
	if st["Uid"] != ids(uid) || st["Gid"] != ids(gid) || st["Groups"] != "" {
		t.Errorf("Uid = %q、Gid = %q、Groups = %q", st["Uid"], st["Gid"], st["Groups"])
	}
	for _, k := range []string{"CapEff", "CapPrm", "CapAmb"} {
		if st[k] != "0000000000000000" {
			t.Errorf("%s = %s", k, st[k])
		}
	}
	if st["Cwd"] != "/" || st["Env"] != "0" || st["Extra"] != "extra-ok" {
		t.Errorf("Cwd = %q、Env = %q、Extra = %q", st["Cwd"], st["Env"], st["Extra"])
	}
}
