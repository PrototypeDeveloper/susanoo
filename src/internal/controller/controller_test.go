package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
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
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/audit"
	"susanoo/internal/event"
	"susanoo/internal/honeytoken"
	"susanoo/internal/notify"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/policy"
	"susanoo/internal/sign"
	"susanoo/internal/transport"
)

// 試験の通信はループバック（127.0.0.1）だけで行う。

var loopback = netip.MustParseAddr("127.0.0.1")

type syncCall struct {
	addrs map[netip.Addr]policy.IsolationLevel
	macs  map[string]policy.IsolationLevel
}

type fakeEnforcer struct {
	mu    sync.Mutex
	calls []syncCall
}

func (f *fakeEnforcer) Sync(_ context.Context, addrs map[netip.Addr]policy.IsolationLevel, macs map[string]policy.IsolationLevel) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, syncCall{maps.Clone(addrs), maps.Clone(macs)})
	return nil
}

func (f *fakeEnforcer) last() syncCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return syncCall{}
	}
	return f.calls[len(f.calls)-1]
}

// fakeLAN は試験用の GW の LAN。試験の通信はループバックなので、LAN のネットワークを 127.0.0.0/8 とする。
type fakeLAN struct {
	mu      sync.Mutex
	present map[netip.Addr]net.HardwareAddr
}

var gwMAC = net.HardwareAddr{2, 0, 0, 0, 0, 0xfe}

func (l *fakeLAN) Addr() netip.Addr      { return netip.MustParseAddr("127.0.0.254") }
func (l *fakeLAN) Prefix() netip.Prefix  { return netip.MustParsePrefix("127.0.0.0/8") }
func (l *fakeLAN) MAC() net.HardwareAddr { return gwMAC }

func (l *fakeLAN) Probe(_ context.Context, ip netip.Addr) (net.HardwareAddr, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	mac, ok := l.present[ip]
	return mac, ok
}

func (l *fakeLAN) set(ip netip.Addr, mac net.HardwareAddr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.present == nil {
		l.present = map[netip.Addr]net.HardwareAddr{}
	}
	if mac == nil {
		delete(l.present, ip)
	} else {
		l.present[ip] = mac
	}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func testPolicy(response policy.Response, approval bool) *policy.Policy {
	return &policy.Policy{
		Version: 1, Name: "試験", IssuedAt: time.Now(), Response: response, OnFailure: policy.FailOpen,
		Groups: []policy.Group{{
			Name:            policy.DefaultGroup,
			Egress:          policy.Egress{Default: policy.EgressAllow},
			Isolation:       policy.IsolateManagementAndUpdates,
			Updates:         []policy.Destination{{CIDR: "192.0.2.0/24"}, {Domain: "*.ubuntu.com"}},
			RequireApproval: approval,
		}},
	}
}

type fixture struct {
	t      *testing.T
	env    *pkitest.Env
	dir    string
	ctrl   *Controller
	enf    *fakeEnforcer
	lan    *fakeLAN
	clock  *clock
	addr   string
	cancel context.CancelFunc
	done   chan error
}

func start(t *testing.T, env *pkitest.Env, dir string, pol *policy.Policy) *fixture {
	t.Helper()
	return startWith(t, env, dir, pol, nil)
}

// startWith は GW の LAN（lan が nil でなければ）とともに CONTROLLER を起動する。
func startWith(t *testing.T, env *pkitest.Env, dir string, pol *policy.Policy, lan *fakeLAN) *fixture {
	t.Helper()
	return startFull(t, env, dir, pol, lan, nil)
}

// startFull は、GW の LAN と、端末の証明書の発行（issuer が nil でなければ）とともに CONTROLLER を起動する。
func startFull(t *testing.T, env *pkitest.Env, dir string, pol *policy.Policy, lan *fakeLAN, issuer Issuer) *fixture {
	t.Helper()
	return startNotify(t, env, dir, pol, lan, issuer, nil)
}

// startNotify は startFull と同じだが、通知の送り手 n（nil なら通知しない）を使う。
func startNotify(t *testing.T, env *pkitest.Env, dir string, pol *policy.Policy, lan *fakeLAN, issuer Issuer, n *notify.Notifier) *fixture {
	t.Helper()
	f := &fixture{t: t, env: env, dir: dir, enf: &fakeEnforcer{}, lan: lan, clock: &clock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}}
	var l LAN
	if lan != nil {
		l = lan
	}
	ctrl, err := New(Config{
		Notifier:         n,
		LAN:              l,
		Dir:              dir,
		CA:               env.CA.Pool(),
		Cert:             env.Leaf(t, pki.RoleController, "main"),
		Signer:           env.Signer,
		Policy:           pol,
		Enforcer:         f.enf,
		Issuer:           issuer,
		HeartbeatTimeout: 30 * time.Second,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:              f.clock.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.ctrl = ctrl
	f.serve()
	return f
}

// serve は CONTROLLER の受け付けを始める。試験の終わりに止める。
func (f *fixture) serve() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.t.Fatal(err)
	}
	f.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	f.done = make(chan error, 1)
	go func() { f.done <- f.ctrl.Serve(ctx, ln) }()
	f.t.Cleanup(f.stop)
}

func (f *fixture) stop() {
	if f.cancel == nil {
		return
	}
	f.cancel()
	if err := <-f.done; err != nil {
		f.t.Errorf("Serve の戻り値 = %v", err)
	}
	f.cancel = nil
}

// peer は試験用の端末（または ctl）。
type peer struct {
	f      *fixture
	cert   tls.Certificate
	http   *http.Client
	signer *sign.Signer
	id     string
	boot   string
	count  uint64
}

func (f *fixture) peer(role pki.Role, id string) *peer {
	return f.peerWith(f.env.Leaf(f.t, role, id), id)
}

// peerWith は証明書 cert で接続する試験用の端末を作る。
func (f *fixture) peerWith(cert tls.Certificate, id string) *peer {
	s, err := sign.NewSigner(cert.PrivateKey.(ed25519.PrivateKey))
	if err != nil {
		f.t.Fatal(err)
	}
	tr := &http.Transport{TLSClientConfig: transport.ClientConfig(f.env.CA.Pool(), cert, pki.RoleController), ForceAttemptHTTP2: true}
	f.t.Cleanup(tr.CloseIdleConnections)
	return &peer{f: f, cert: cert, http: &http.Client{Transport: tr, Timeout: 10 * time.Second}, signer: s, id: id, boot: "boot-1"}
}

func (d *peer) do(method, path string, body any) (int, []byte) {
	d.f.t.Helper()
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			d.f.t.Fatal(err)
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, "https://"+d.f.addr+path, r)
	if err != nil {
		d.f.t.Fatal(err)
	}
	resp, err := d.http.Do(req)
	if err != nil {
		d.f.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		d.f.t.Fatal(err)
	}
	return resp.StatusCode, data
}

func (d *peer) signedHeartbeat(hb api.Heartbeat) sign.Envelope {
	payload, err := json.Marshal(hb)
	if err != nil {
		d.f.t.Fatal(err)
	}
	return d.signer.Sign(sign.PurposeHeartbeat, payload)
}

func (d *peer) heartbeat() (int, api.Command) {
	d.f.t.Helper()
	d.count++
	status, body := d.do(http.MethodPost, api.PathHeartbeat, d.signedHeartbeat(api.Heartbeat{
		DeviceID: d.id, BootID: d.boot, Counter: d.count, Time: time.Now(), Hostname: d.id,
	}))
	return status, d.command(status, body)
}

func (d *peer) command(status int, body []byte) api.Command {
	d.f.t.Helper()
	if status != http.StatusOK {
		return api.Command{}
	}
	var desired api.Desired
	if err := json.Unmarshal(body, &desired); err != nil {
		d.f.t.Fatal(err)
	}
	v, err := sign.NewVerifier(d.f.env.Signer.PublicKey())
	if err != nil {
		d.f.t.Fatal(err)
	}
	payload, err := v.Verify(sign.PurposeCommand, desired.Command)
	if err != nil {
		d.f.t.Fatalf("指示の署名を検証できない: %v", err)
	}
	var cmd api.Command
	if err := json.Unmarshal(payload, &cmd); err != nil {
		d.f.t.Fatal(err)
	}
	return cmd
}

func (d *peer) touchHoneytoken() (int, api.Command) {
	d.f.t.Helper()
	e := honeytoken.Finding(honeytoken.Token{Path: "/home/u/.aws/credentials", Kind: honeytoken.KindAWS}, honeytoken.OpOpen, &event.Process{PID: 42, Name: "cat"}, time.Now())
	// CLIENT が別の端末 ID を名乗っても、証明書の ID で記録される。
	e.Device = &event.Device{UID: "spoofed"}
	status, body := d.do(http.MethodPost, api.PathEvents, api.EventBatch{Events: []event.Event{*e}})
	return status, d.command(status, body)
}

func (f *fixture) devices(admin *peer) map[string]api.Device {
	f.t.Helper()
	status, body := admin.do(http.MethodGet, api.PathDevices, nil)
	if status != http.StatusOK {
		f.t.Fatalf("端末の一覧を取得できない: %d %s", status, body)
	}
	var list []api.Device
	if err := json.Unmarshal(body, &list); err != nil {
		f.t.Fatal(err)
	}
	out := map[string]api.Device{}
	for _, d := range list {
		out[d.ID] = d
	}
	return out
}

func auditActions(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(bytes.NewReader(data)); err != nil {
		t.Fatalf("監査ログの連鎖が壊れている: %v", err)
	}
	var actions []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var r audit.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, r.Action+":"+r.Target)
	}
	return actions
}

func TestHeartbeatRegistersDevice(t *testing.T) {
	f := start(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	pc := f.peer(pki.RoleClient, "pc-001")

	status, cmd := pc.heartbeat()
	if status != http.StatusOK {
		t.Fatalf("ハートビートの応答 = %d", status)
	}
	if cmd.DeviceID != "pc-001" || cmd.Isolation != "" || cmd.Version != 0 {
		t.Errorf("指示 = %+v", cmd)
	}
	admin := f.peer(pki.RoleAdmin, "admin")
	d, ok := f.devices(admin)["pc-001"]
	if !ok || d.Addr != "127.0.0.1" || d.Group != policy.DefaultGroup || d.Hostname != "pc-001" {
		t.Errorf("台帳 = %+v", d)
	}
	if got := auditActions(t, f.dir); !slices.Equal(got, []string{"device.register:pc-001"}) {
		t.Errorf("監査ログ = %v", got)
	}
}

func TestHeartbeatRejects(t *testing.T) {
	f := start(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	pc := f.peer(pki.RoleClient, "pc-001")
	if status, _ := pc.heartbeat(); status != http.StatusOK {
		t.Fatal(status)
	}

	// 同じ起動で番号が増えていないハートビートは古いものとして拒否する。
	pc.count--
	if status, _ := pc.heartbeat(); status != http.StatusConflict {
		t.Errorf("古いハートビートの応答 = %d", status)
	}
	// 起動し直した CLIENT は番号が 1 に戻る。
	pc.boot, pc.count = "boot-2", 0
	if status, _ := pc.heartbeat(); status != http.StatusOK {
		t.Errorf("起動し直した後のハートビートの応答 = %d", status)
	}

	// 別の端末 ID を名乗るハートビート。
	other := pc.signedHeartbeat(api.Heartbeat{DeviceID: "pc-999", BootID: "x", Counter: 1})
	if status, _ := pc.do(http.MethodPost, api.PathHeartbeat, other); status != http.StatusForbidden {
		t.Errorf("別の端末 ID の応答 = %d", status)
	}
	// 証明書と違う鍵で署名したハートビート。
	pc2 := f.peer(pki.RoleClient, "pc-002")
	forged := pc2.signedHeartbeat(api.Heartbeat{DeviceID: "pc-001", BootID: "y", Counter: 1})
	if status, _ := pc.do(http.MethodPost, api.PathHeartbeat, forged); status != http.StatusForbidden {
		t.Errorf("違う鍵で署名したハートビートの応答 = %d", status)
	}
	// 知らない項目。
	if status, _ := pc.do(http.MethodPost, api.PathHeartbeat, map[string]any{"x": 1}); status != http.StatusBadRequest {
		t.Errorf("不正な本文の応答 = %d", status)
	}
}

func TestRoles(t *testing.T) {
	f := start(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	pc := f.peer(pki.RoleClient, "pc-001")
	admin := f.peer(pki.RoleAdmin, "admin")

	if status, _ := pc.do(http.MethodGet, api.PathDevices, nil); status != http.StatusForbidden {
		t.Errorf("端末が一覧を取得できた: %d", status)
	}
	if status, _ := pc.do(http.MethodPost, api.PathDevices+"/pc-001/release", nil); status != http.StatusForbidden {
		t.Errorf("端末が隔離を解除できた: %d", status)
	}
	hb := admin.signedHeartbeat(api.Heartbeat{DeviceID: "admin", BootID: "x", Counter: 1})
	if status, _ := admin.do(http.MethodPost, api.PathHeartbeat, hb); status != http.StatusForbidden {
		t.Errorf("管理者の証明書でハートビートを送れた: %d", status)
	}
}

func TestHoneytokenIsolatesAndAdminReleases(t *testing.T) {
	f := start(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	pc := f.peer(pki.RoleClient, "pc-001")
	admin := f.peer(pki.RoleAdmin, "admin")
	pc.heartbeat()

	status, cmd := pc.touchHoneytoken()
	if status != http.StatusOK {
		t.Fatalf("イベントの応答 = %d", status)
	}
	if cmd.Isolation != policy.IsolateManagementAndUpdates || cmd.Version == 0 {
		t.Errorf("隔離の指示 = %+v", cmd)
	}
	if len(cmd.Updates) != 1 || cmd.Updates[0] != netip.MustParsePrefix("192.0.2.0/24") {
		t.Errorf("更新サーバー = %v", cmd.Updates)
	}
	if got := f.enf.last().addrs; got[loopback] != policy.IsolateManagementAndUpdates {
		t.Errorf("GW の遮断 = %v", got)
	}
	d := f.devices(admin)["pc-001"]
	if d.Isolation != policy.IsolateManagementAndUpdates || d.Reason != ReasonHoneytoken || d.Since.IsZero() {
		t.Errorf("台帳 = %+v", d)
	}

	// 保存したイベントは、証明書の端末 ID で記録されている。
	events, err := os.ReadDir(filepath.Join(f.dir, "events"))
	if err != nil || len(events) != 1 {
		t.Fatalf("イベントのファイル = %v, %v", events, err)
	}
	data, err := os.ReadFile(filepath.Join(f.dir, "events", events[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"uid":"pc-001"`) || strings.Contains(string(data), "spoofed") {
		t.Errorf("イベントの端末 ID が証明書と違う: %s", data)
	}

	version := cmd.Version
	status, body := admin.do(http.MethodPost, api.PathDevices+"/pc-001/release", nil)
	if status != http.StatusOK {
		t.Fatalf("解除の応答 = %d %s", status, body)
	}
	if got := f.enf.last().addrs; len(got) != 0 {
		t.Errorf("解除後の GW の遮断 = %v", got)
	}
	_, cmd = pc.heartbeat()
	if cmd.Isolation != "" || cmd.Version <= version {
		t.Errorf("解除の指示 = %+v", cmd)
	}
	want := []string{"device.register:pc-001", "device.isolate:pc-001", "device.release:pc-001"}
	if got := auditActions(t, f.dir); !slices.Equal(got, want) {
		t.Errorf("監査ログ = %v, 期待値 %v", got, want)
	}
}

func TestHeartbeatLossIsolates(t *testing.T) {
	f := start(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	pc := f.peer(pki.RoleClient, "pc-001")
	pc.heartbeat()

	f.clock.advance(20 * time.Second)
	f.ctrl.checkHeartbeats()
	if got := f.enf.last().addrs; len(got) != 0 {
		t.Fatalf("途絶の前に遮断した: %v", got)
	}

	f.clock.advance(15 * time.Second)
	f.ctrl.checkHeartbeats()
	if got := f.enf.last().addrs; got[loopback] != policy.IsolateManagementAndUpdates {
		t.Errorf("途絶の後の GW の遮断 = %v", got)
	}
	d := f.devices(f.peer(pki.RoleAdmin, "admin"))["pc-001"]
	if d.Reason != ReasonHeartbeatLost {
		t.Errorf("隔離の理由 = %q", d.Reason)
	}
}

func TestRequireApproval(t *testing.T) {
	f := start(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, true))
	pc := f.peer(pki.RoleClient, "pc-001")
	admin := f.peer(pki.RoleAdmin, "admin")
	pc.heartbeat()

	_, cmd := pc.touchHoneytoken()
	if cmd.Isolation != "" {
		t.Errorf("承認の前に隔離した: %+v", cmd)
	}
	if d := f.devices(admin)["pc-001"]; d.Pending != ReasonHoneytoken {
		t.Errorf("承認待ち = %q", d.Pending)
	}

	status, body := admin.do(http.MethodPost, api.PathDevices+"/pc-001/isolate", api.IsolateRequest{Level: policy.IsolateFull})
	if status != http.StatusOK {
		t.Fatalf("隔離の応答 = %d %s", status, body)
	}
	d := f.devices(admin)["pc-001"]
	if d.Isolation != policy.IsolateFull || d.Pending != "" || d.Reason != ReasonHoneytoken {
		t.Errorf("承認後の台帳 = %+v", d)
	}
	if status, _ := admin.do(http.MethodPost, api.PathDevices+"/pc-999/isolate", nil); status != http.StatusNotFound {
		t.Errorf("台帳にない端末の応答 = %d", status)
	}
	if status, _ := admin.do(http.MethodPost, api.PathDevices+"/pc-001/isolate", api.IsolateRequest{Level: "all"}); status != http.StatusBadRequest {
		t.Errorf("不明な段階の応答 = %d", status)
	}
}

func TestMonitorModeDoesNotIsolate(t *testing.T) {
	for _, mode := range []policy.Response{policy.ResponseMonitor, policy.ResponseAlert} {
		t.Run(string(mode), func(t *testing.T) {
			f := start(t, pkitest.New(t), t.TempDir(), testPolicy(mode, false))
			pc := f.peer(pki.RoleClient, "pc-001")
			pc.heartbeat()
			if _, cmd := pc.touchHoneytoken(); cmd.Isolation != "" {
				t.Errorf("隔離した: %+v", cmd)
			}
			if got := f.enf.last().addrs; len(got) != 0 {
				t.Errorf("GW で遮断した: %v", got)
			}
		})
	}
}

func TestRestartKeepsIsolation(t *testing.T) {
	env := pkitest.New(t)
	dir := t.TempDir()
	f := start(t, env, dir, testPolicy(policy.ResponseEnforce, false))
	pc := f.peer(pki.RoleClient, "pc-001")
	pc.heartbeat()
	_, before := pc.touchHoneytoken()
	f.stop()

	// 起動し直すと、台帳から隔離を復元して GW で遮断し直す（受け付けを始める前に行う）。
	g := start(t, env, dir, testPolicy(policy.ResponseEnforce, false))
	pc.f = g
	pc.boot, pc.count = "boot-2", 0
	_, after := pc.heartbeat()
	if got := g.enf.last().addrs; got[loopback] != policy.IsolateManagementAndUpdates {
		t.Errorf("起動し直した後の GW の遮断 = %v", got)
	}
	if after.Isolation != before.Isolation || after.Version != before.Version {
		t.Errorf("起動し直した後の指示 = %+v, 前 %+v", after, before)
	}
}

func TestMassChangeIsolates(t *testing.T) {
	f := start(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	pc := f.peer(pki.RoleClient, "pc-001")
	pc.heartbeat()
	e := event.New(event.ClassDetectionFinding, event.FindingCreate, event.SeverityHigh, time.Now())
	e.FindingInfo = &event.FindingInfo{UID: "m-1", Title: "短時間の大量変更", Types: []string{event.FindingTypeMassChange}}
	status, body := pc.do(http.MethodPost, api.PathEvents, api.EventBatch{Events: []event.Event{*e}})
	cmd := pc.command(status, body)
	if cmd.Isolation == "" {
		t.Fatalf("大量の変更で隔離しない: %+v", cmd)
	}
	if d := f.devices(f.peer(pki.RoleAdmin, "admin"))["pc-001"]; d.Reason != ReasonMassChange {
		t.Errorf("隔離の理由 = %q", d.Reason)
	}

	// 改ざんの検知結果は記録するが、それだけでは隔離しない。
	f2 := start(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	pc2 := f2.peer(pki.RoleClient, "pc-002")
	pc2.heartbeat()
	tamper := event.New(event.ClassDetectionFinding, event.FindingCreate, event.SeverityHigh, time.Now())
	tamper.FindingInfo = &event.FindingInfo{UID: "t-1", Title: "防御の仕組みの改ざん", Types: []string{event.FindingTypeTamper}}
	status, body = pc2.do(http.MethodPost, api.PathEvents, api.EventBatch{Events: []event.Event{*tamper}})
	if cmd := pc2.command(status, body); cmd.Isolation != "" {
		t.Errorf("改ざんの検知結果だけで隔離した: %+v", cmd)
	}
}
