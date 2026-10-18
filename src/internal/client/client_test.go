package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/controller"
	"susanoo/internal/honeytoken"
	"susanoo/internal/keys"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/platform"
	"susanoo/internal/platform/platformtest"
	"susanoo/internal/policy"
	"susanoo/internal/sign"
	"susanoo/internal/transport"
)

// 試験の通信はループバック（127.0.0.1）だけで行う。

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeEnforcer struct {
	mu   sync.Mutex
	last map[netip.Addr]policy.IsolationLevel
}

func (f *fakeEnforcer) Sync(_ context.Context, addrs map[netip.Addr]policy.IsolationLevel, _ map[string]policy.IsolationLevel) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last = maps.Clone(addrs)
	return nil
}

func (f *fakeEnforcer) members() map[netip.Addr]policy.IsolationLevel {
	f.mu.Lock()
	defer f.mu.Unlock()
	return maps.Clone(f.last)
}

func startController(t *testing.T, env *pkitest.Env, enf controller.Enforcer) netip.AddrPort {
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
		Enforcer: enf,
		Issuer:   caIssuer{env},
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

func newLocal(t *testing.T, env *pkitest.Env, addr netip.AddrPort, stateDir string, p platform.Platform) *Local {
	t.Helper()
	l, err := NewLocal(LocalConfig{
		Cert:          env.Leaf(t, pki.RoleClient, "pc-001"),
		CA:            env.CA.Pool(),
		CommandKey:    env.Signer.PublicKey(),
		StateDir:      stateDir,
		Controller:    addr,
		CheckInterval: 50 * time.Millisecond,
		Platform:      p,
		Logger:        quiet,
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// newAgent は、同じプロセスの執行部を使う CLIENT を作る。執行部は起動時と同じく前回の隔離をかけ直す。
func newAgent(t *testing.T, env *pkitest.Env, addr netip.AddrPort, stateDir string, p platform.Platform) *Agent {
	t.Helper()
	l := newLocal(t, env, addr, stateDir, p)
	l.Restore(context.Background())
	a, err := New(Config{
		Controller:        addr,
		CA:                env.CA.Pool(),
		Chain:             l.cfg.Cert.Certificate,
		HeartbeatInterval: 50 * time.Millisecond,
		Executor:          l,
		Logger:            quiet,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func run(t *testing.T, a *Agent) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return cancel
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

func adminPost(t *testing.T, env *pkitest.Env, addr netip.AddrPort, path string) {
	t.Helper()
	tr := &http.Transport{TLSClientConfig: transport.ClientConfig(env.CA.Pool(), env.Leaf(t, pki.RoleAdmin, "admin"), pki.RoleController)}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr}).Post("https://"+addr.String()+path, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s の応答 = %s", path, resp.Status)
	}
}

var caps = platform.Capabilities{OS: "linux", Features: []platform.Capability{platform.CapHoneytoken, platform.CapIsolation}}

func TestHoneytokenToIsolation(t *testing.T) {
	env := pkitest.New(t)
	enf := &fakeEnforcer{}
	addr := startController(t, env, enf)
	fake := platformtest.New(caps)
	run(t, newAgent(t, env, addr, t.TempDir(), fake))

	// おとりへの接触 → CONTROLLER の判定 → GW の遮断と自己隔離。
	e := honeytoken.Finding(honeytoken.Token{Path: "/home/u/.ssh/id_ed25519", Kind: honeytoken.KindSSH}, honeytoken.OpOpen, nil, time.Now())
	if err := fake.Emit(context.Background(), *e); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "自己隔離", func() bool { return fake.Isolated() != nil })
	iso := fake.Isolated()
	if iso.Level != policy.IsolateManagement || len(iso.Management) != 1 || iso.Management[0] != addr {
		t.Errorf("自己隔離の指示 = %+v", iso)
	}
	if got := enf.members(); got[netip.MustParseAddr("127.0.0.1")] != policy.IsolateManagement {
		t.Errorf("GW の遮断 = %v", got)
	}

	// 管理者が解除すると、次のハートビートの応答で自己隔離も解除する。
	adminPost(t, env, addr, api.PathDevices+"/pc-001/release")
	waitFor(t, "自己隔離の解除", func() bool { return fake.Isolated() == nil })
	if got := enf.members(); len(got) != 0 {
		t.Errorf("解除後の GW の遮断 = %v", got)
	}
}

func TestIsolationSurvivesRestart(t *testing.T) {
	env := pkitest.New(t)
	addr := startController(t, env, &fakeEnforcer{})
	stateDir := t.TempDir()
	fake := platformtest.New(caps)
	cancel := run(t, newAgent(t, env, addr, stateDir, fake))
	e := honeytoken.Finding(honeytoken.Token{Path: "/x", Kind: honeytoken.KindAWS}, honeytoken.OpOpen, nil, time.Now())
	fake.Emit(context.Background(), *e)
	waitFor(t, "自己隔離", func() bool { return fake.Isolated() != nil })
	cancel()

	// 再起動した CLIENT は、CONTROLLER に接続できなくても前回の隔離を続ける。
	unreachable := netip.MustParseAddrPort("127.0.0.1:1")
	fake2 := platformtest.New(caps)
	run(t, newAgent(t, env, unreachable, stateDir, fake2))
	waitFor(t, "再起動後の自己隔離", func() bool { return fake2.Isolated() != nil })
	if got := fake2.Isolated().Level; got != policy.IsolateManagement {
		t.Errorf("再起動後の段階 = %s", got)
	}
}

func TestApplyRejectsInvalidCommands(t *testing.T) {
	env := pkitest.New(t)
	fake := platformtest.New(caps)
	l := newLocal(t, env, netip.MustParseAddrPort("127.0.0.1:1"), t.TempDir(), fake)

	other, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	forger, err := sign.NewSigner(other)
	if err != nil {
		t.Fatal(err)
	}
	isolate := api.Command{DeviceID: "pc-001", Version: 10, Isolation: policy.IsolateFull}

	ctx := context.Background()
	for name, env := range map[string]sign.Envelope{
		"偽造された署名":   command(t, forger, sign.PurposeCommand, isolate),
		"用途が違う署名":   command(t, env.Signer, sign.PurposePolicy, isolate),
		"ほかの端末への指示": command(t, env.Signer, sign.PurposeCommand, api.Command{DeviceID: "pc-002", Version: 10, Isolation: policy.IsolateFull}),
	} {
		if err := l.Apply(ctx, env); err == nil || fake.Isolated() != nil {
			t.Fatalf("%s に従って隔離した（エラー %v）", name, err)
		}
	}

	if err := l.Apply(ctx, command(t, env.Signer, sign.PurposeCommand, isolate)); err != nil || fake.Isolated() == nil {
		t.Fatalf("正しい指示に従わない: %v", err)
	}
	// 古い版数の解除の指示（再送された古い指示など）には従わない。
	l.Apply(ctx, command(t, env.Signer, sign.PurposeCommand, api.Command{DeviceID: "pc-001", Version: 9}))
	if fake.Isolated() == nil {
		t.Error("古い指示に従って解除した")
	}
}

func command(t *testing.T, s *sign.Signer, purpose sign.Purpose, cmd api.Command) sign.Envelope {
	t.Helper()
	payload, err := json.Marshal(cmd)
	if err != nil {
		t.Fatal(err)
	}
	return s.Sign(purpose, payload)
}

// ハートビートの状態の項目は、執行部が自分の状態で埋めて署名する。
func TestHeartbeatCarriesExecutorState(t *testing.T) {
	env := pkitest.New(t)
	fake := platformtest.New(caps)
	l := newLocal(t, env, netip.MustParseAddrPort("127.0.0.1:1"), t.TempDir(), fake)
	ctx := context.Background()
	if err := l.Apply(ctx, command(t, env.Signer, sign.PurposeCommand, api.Command{DeviceID: "pc-001", Version: 10, Isolation: policy.IsolateFull})); err != nil {
		t.Fatal(err)
	}
	verifier, err := sign.NewVerifier(l.key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	var last uint64
	for range 2 {
		hb, err := l.Heartbeat(ctx)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := verifier.Verify(sign.PurposeHeartbeat, hb)
		if err != nil {
			t.Fatal(err)
		}
		var got api.Heartbeat
		json.Unmarshal(payload, &got)
		if got.DeviceID != "pc-001" || got.Applied != 10 || got.Isolation != policy.IsolateFull || got.Counter <= last || !got.Capabilities.Has(platform.CapIsolation) {
			t.Errorf("ハートビート = %+v", got)
		}
		last = got.Counter
	}
}

// 端末の鍵では、TLS 1.3 のクライアント認証の形のものにしか署名しない。
func TestSignTLSOnlyClientCertificateVerify(t *testing.T) {
	env := pkitest.New(t)
	l := newLocal(t, env, netip.MustParseAddrPort("127.0.0.1:1"), t.TempDir(), platformtest.New(caps))
	ctx := context.Background()
	valid := append([]byte(strings.Repeat(" ", 64)+tlsClientContext), make([]byte, 32)...)
	pub := l.key.Public().(ed25519.PublicKey)
	if sig, err := l.SignTLS(ctx, valid); err != nil || !ed25519.Verify(pub, valid, sig) {
		t.Fatalf("正しい形の署名に失敗: %v", err)
	}
	if _, err := l.SignTLS(ctx, append([]byte(strings.Repeat(" ", 64)+tlsClientContext), make([]byte, 48)...)); err != nil {
		t.Errorf("SHA-384 の形の署名に失敗: %v", err)
	}
	server := append([]byte(strings.Repeat(" ", 64)+"TLS 1.3, server CertificateVerify\x00"), make([]byte, 32)...)
	for name, msg := range map[string][]byte{
		"サーバーの文脈":   server,
		"ハッシュの長さ違い": append([]byte(strings.Repeat(" ", 64)+tlsClientContext), make([]byte, 31)...),
		"先頭が空白でない":  append([]byte{'x'}, valid[1:]...),
		"署名の封筒":     []byte("susanoo-sign-v1\x00heartbeat\x00{}"),
		"空":         nil,
	} {
		if _, err := l.SignTLS(ctx, msg); err == nil {
			t.Errorf("%s に署名した", name)
		}
	}
}

func TestNewRejectsNonClientCert(t *testing.T) {
	env := pkitest.New(t)
	admin := env.Leaf(t, pki.RoleAdmin, "admin")
	addr := netip.MustParseAddrPort("127.0.0.1:1")
	_, err := NewLocal(LocalConfig{Cert: admin, CommandKey: env.Signer.PublicKey(), StateDir: t.TempDir(), Controller: addr, Platform: platformtest.New(caps)})
	if err == nil {
		t.Error("管理者の証明書で執行部を作れた")
	}
	l := newLocal(t, env, addr, t.TempDir(), platformtest.New(caps))
	if _, err := New(Config{Controller: addr, CA: env.CA.Pool(), Chain: admin.Certificate, Executor: l}); err == nil {
		t.Error("管理者の証明書で解析部を作れた")
	}
}

// blackhole は CLIENT と CONTROLLER の間に入る中継。freeze を呼ぶと、それまでの接続を閉じずに
// 黙らせる（送信元のアドレスが消えた接続などを再現する）。その後の新しい接続はそのまま中継する。
type blackhole struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	frozen []*atomic.Bool
}

func newBlackhole(t *testing.T, target string) *blackhole {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &blackhole{ln: ln, target: target}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go b.relay(c)
		}
	}()
	return b
}

func (b *blackhole) relay(c net.Conn) {
	s, err := net.Dial("tcp", b.target)
	if err != nil {
		c.Close()
		return
	}
	frozen := &atomic.Bool{}
	b.mu.Lock()
	b.frozen = append(b.frozen, frozen)
	b.mu.Unlock()
	pipe := func(dst, src net.Conn) {
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if err != nil {
				return
			}
			if !frozen.Load() {
				dst.Write(buf[:n])
			}
		}
	}
	go pipe(s, c)
	go pipe(c, s)
}

func (b *blackhole) freeze() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, f := range b.frozen {
		f.Store(true)
	}
}

func (b *blackhole) addr() netip.AddrPort { return netip.MustParseAddrPort(b.ln.Addr().String()) }

func TestRecoversFromDeadConnection(t *testing.T) {
	env := pkitest.New(t)
	ctrlAddr := startController(t, env, &fakeEnforcer{})
	proxy := newBlackhole(t, ctrlAddr.String())
	run(t, newAgent(t, env, proxy.addr(), t.TempDir(), platformtest.New(caps)))

	lastSeen := func() time.Time {
		tr := &http.Transport{TLSClientConfig: transport.ClientConfig(env.CA.Pool(), env.Leaf(t, pki.RoleAdmin, "admin"), pki.RoleController)}
		defer tr.CloseIdleConnections()
		resp, err := (&http.Client{Transport: tr}).Get("https://" + ctrlAddr.String() + api.PathDevices)
		if err != nil {
			return time.Time{}
		}
		defer resp.Body.Close()
		var list []api.Device
		json.NewDecoder(resp.Body).Decode(&list)
		if len(list) == 0 {
			return time.Time{}
		}
		return list[0].LastSeen
	}
	waitFor(t, "最初のハートビート", func() bool { return !lastSeen().IsZero() })

	// 既存の接続が黙っても、接続し直してハートビートを再開する。
	proxy.freeze()
	frozenAt := time.Now()
	waitFor(t, "接続し直した後のハートビート", func() bool { return lastSeen().After(frozenAt.Add(500 * time.Millisecond)) })
}

func TestTamperedIsolationIsRestored(t *testing.T) {
	env := pkitest.New(t)
	enf := &fakeEnforcer{}
	addr := startController(t, env, enf)
	fake := platformtest.New(caps)
	run(t, newAgent(t, env, addr, t.TempDir(), fake))
	e := honeytoken.Finding(honeytoken.Token{Path: "/x", Kind: honeytoken.KindAWS}, honeytoken.OpOpen, nil, time.Now())
	fake.Emit(context.Background(), *e)
	waitFor(t, "自己隔離", func() bool { return fake.Isolated() != nil })

	// 攻撃者が自己隔離のルールを消しても、次の確認で入れ直す。
	fake.Tamper()
	waitFor(t, "自己隔離の入れ直し", func() bool { return fake.Isolated() != nil })
	h := fake.History()
	if !slices.Contains(h, "tamper") || h[len(h)-1] != "isolate:management" {
		t.Errorf("履歴 = %v", h)
	}
}

// caIssuer は GW の執行部の代わりに、試験用の認証局で端末の証明書を発行する。
type caIssuer struct{ env *pkitest.Env }

func (i caIssuer) IssueClient(_ context.Context, id string, pub ed25519.PublicKey) (*x509.Certificate, error) {
	return i.env.CA.Issue(pub, pki.Identity{Role: pki.RoleClient, ID: id}, time.Now())
}

// 執行部は、内部の認証局が発行し、持ち主と鍵が同じで、期限が今より先の証明書だけを受け入れて保存する。
func TestLocalRenewCert(t *testing.T) {
	env := pkitest.New(t)
	l := newLocal(t, env, netip.MustParseAddrPort("127.0.0.1:1"), t.TempDir(), platformtest.New(caps))
	certPath := filepath.Join(t.TempDir(), "client.crt")
	l.cfg.CertPath = certPath
	pub := l.key.Public().(ed25519.PublicKey)
	issue := func(ca *pki.CA, pub ed25519.PublicKey, id string, at time.Time) []byte {
		t.Helper()
		c, err := ca.Issue(pub, pki.Identity{Role: pki.RoleClient, ID: id}, at)
		if err != nil {
			t.Fatal(err)
		}
		return c.Raw
	}
	otherKey, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Minute)
	ctx := context.Background()
	for name, der := range map[string][]byte{
		"別の認証局":   issue(pkitest.New(t).CA, pub, "pc-001", later),
		"別の端末":    issue(env.CA, pub, "pc-002", later),
		"別の鍵":     issue(env.CA, otherKey.Public().(ed25519.PublicKey), "pc-001", later),
		"期限が先でない": l.leaf.Raw,
		"証明書でない":  []byte("not a certificate"),
	} {
		if err := l.RenewCert(ctx, der); err == nil {
			t.Errorf("%s の証明書を受け入れた", name)
		}
	}
	if _, err := os.Stat(certPath); err == nil {
		t.Fatal("不正な証明書を保存した")
	}
	good := issue(env.CA, pub, "pc-001", later)
	if err := l.RenewCert(ctx, good); err != nil {
		t.Fatal(err)
	}
	saved, err := pki.ReadCertFile(certPath)
	if err != nil || !bytes.Equal(saved.Raw, good) {
		t.Errorf("保存した証明書 = %v", err)
	}
}

// CLIENT は、有効期間の残りが 3 分の 1 を切った証明書を自分で更新し、元の証明書の期限が過ぎた後も通信を続ける。
func TestAgentRenewsCertificate(t *testing.T) {
	env := pkitest.New(t)
	addr := startController(t, env, &fakeEnforcer{})
	priv, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	short, err := env.CA.IssueFor(priv.Public().(ed25519.PublicKey), pki.Identity{Role: pki.RoleClient, ID: "pc-001"}, time.Now(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(t.TempDir(), "client.crt")
	l, err := NewLocal(LocalConfig{
		Cert: pki.TLSCertificate(short, priv), CA: env.CA.Pool(), CertPath: certPath, CommandKey: env.Signer.PublicKey(),
		StateDir: t.TempDir(), Controller: addr, CheckInterval: 50 * time.Millisecond, Platform: platformtest.New(caps), Logger: quiet,
	})
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{Controller: addr, CA: env.CA.Pool(), Chain: [][]byte{short.Raw}, HeartbeatInterval: 50 * time.Millisecond, Executor: l, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	run(t, a)
	waitFor(t, "証明書の更新", func() bool {
		c, err := pki.ReadCertFile(certPath)
		return err == nil && c.NotAfter.After(time.Now().Add(80*24*time.Hour))
	})

	lastSeen := func() time.Time {
		tr := &http.Transport{TLSClientConfig: transport.ClientConfig(env.CA.Pool(), env.Leaf(t, pki.RoleAdmin, "admin"), pki.RoleController)}
		defer tr.CloseIdleConnections()
		resp, err := (&http.Client{Transport: tr}).Get("https://" + addr.String() + api.PathDevices)
		if err != nil {
			return time.Time{}
		}
		defer resp.Body.Close()
		var list []api.Device
		json.NewDecoder(resp.Body).Decode(&list)
		if len(list) == 0 {
			return time.Time{}
		}
		return list[0].LastSeen
	}
	expired := short.NotAfter.Add(500 * time.Millisecond)
	time.Sleep(time.Until(expired))
	waitFor(t, "元の証明書の期限の後のハートビート", func() bool { return lastSeen().After(expired) })
}

// syncBuffer はログを集める。
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// CONTROLLER に送れない間は、警告を送るたびに出さず、イベントごとに接続し直さない。
func TestOfflineLogsOnce(t *testing.T) {
	env := pkitest.New(t)
	unreachable := netip.MustParseAddrPort("127.0.0.1:1")
	fake := platformtest.New(caps)
	l := newLocal(t, env, unreachable, t.TempDir(), fake)
	var logs syncBuffer
	a, err := New(Config{Controller: unreachable, CA: env.CA.Pool(), Chain: l.cfg.Cert.Certificate, HeartbeatInterval: 50 * time.Millisecond,
		Executor: l, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	run(t, a)
	for range 20 {
		e := honeytoken.Finding(honeytoken.Token{Path: "/x", Kind: honeytoken.KindAWS}, honeytoken.OpOpen, nil, time.Now())
		fake.Emit(context.Background(), *e)
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	if n := strings.Count(logs.String(), "CONTROLLER に送れません"); n != 1 {
		t.Errorf("送れない警告が %d 回出た\n%s", n, logs.String())
	}
}
