//go:build linux

package privsep

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"susanoo/internal/controller"
	"susanoo/internal/egress"
	"susanoo/internal/gw"
	"susanoo/internal/intel"
	"susanoo/internal/keys"
	"susanoo/internal/pki"
	"susanoo/internal/policy"
	"susanoo/internal/sign"
)

// nftRecorder は nft の代わりに、適用するスクリプトを記録する。
type nftRecorder struct {
	mu      sync.Mutex
	scripts []string
	delay   time.Duration
}

func (r *nftRecorder) Run(_ context.Context, script string) error {
	time.Sleep(r.delay)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scripts = append(r.scripts, script)
	return nil
}

func (r *nftRecorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.scripts...)
}

var gwPolicy = &policy.Policy{
	Version: 1, Name: "試験", IssuedAt: time.Now(), Response: policy.ResponseEnforce, OnFailure: policy.FailOpen,
	Groups: []policy.Group{
		{Name: policy.DefaultGroup, Isolation: policy.IsolateManagement, Egress: policy.Egress{Default: policy.EgressLearn}},
		{Name: "strict", Isolation: policy.IsolateManagement, Egress: policy.Egress{Default: policy.EgressDeny, Allow: []policy.Destination{
			{Domain: "allowed.test", Ports: []uint16{443}, Protocol: "tcp"},
		}}},
	},
}

type gwHello struct {
	Name string `json:"name"`
}

type gwPair struct {
	nft      *nftRecorder
	remote   *GWRemote
	changes  chan string
	certs    chan []byte
	policies chan controller.PolicyState
	intel    chan intel.Blocklist
	done     chan error
	cancel   context.CancelFunc
}

// fullAccess は、すべての要求を受け付けるつながり（試験のため）。
func fullAccess(q controller.Enforcer, e *egress.Engine) GWExecutor {
	return GWExecutor{Quarantine: q, Membership: e, Learner: e, Issuer: testIssuer{}, Policies: testPolicies{}, Intel: testIntel{}}
}

// testIntel は、用途が脅威情報のものだけを受け付ける。
type testIntel struct{}

func (testIntel) ApplyIntel(_ context.Context, env sign.Envelope) error {
	if env.Purpose != sign.PurposeIntel {
		return errors.New("用途が違います")
	}
	return nil
}

// testPolicies は、受け取った指示をそのまま状態として返す。
type testPolicies struct{}

func (testPolicies) ApplyPolicy(_ context.Context, env sign.Envelope, canary bool) (controller.PolicyState, error) {
	if canary {
		return controller.PolicyState{Current: []byte(`{"v":1}`), Canary: env.Payload}, nil
	}
	return controller.PolicyState{Current: env.Payload}, nil
}
func (testPolicies) PromotePolicy(context.Context) (controller.PolicyState, error) {
	return controller.PolicyState{Current: []byte(`{"v":2}`)}, nil
}
func (testPolicies) AbortPolicy(context.Context) (controller.PolicyState, error) {
	return controller.PolicyState{}, errors.New("先行適用している版がありません")
}

// testIssuer は、要求された端末の証明書を試験用の認証局で発行する。
type testIssuer struct{}

var testCA = func() *pki.CA {
	ca, err := pki.NewCA("試験用CA", time.Now())
	if err != nil {
		panic(err)
	}
	return ca
}()

func (testIssuer) IssueClient(_ context.Context, id string, pub ed25519.PublicKey) (*x509.Certificate, error) {
	return testCA.Issue(pub, pki.Identity{Role: pki.RoleClient, ID: id}, time.Now())
}

// startGW は GW の執行部（nft の代わりに記録係）を動かし、非特権の側からつなぐ。access でつながりが受け付ける要求を決める。
func startGW(t *testing.T, delay time.Duration, access func(controller.Enforcer, *egress.Engine) GWExecutor) *gwPair {
	t.Helper()
	rec := &nftRecorder{delay: delay}
	engine, err := egress.New(egress.Config{Policy: gwPolicy, LAN: "lan0", NFT: rec})
	if err != nil {
		t.Fatal(err)
	}
	ours, theirs := socketpair(t)
	ctx, cancel := context.WithCancel(context.Background())
	g := &gwPair{nft: rec, changes: make(chan string, 1), certs: make(chan []byte, 1), policies: make(chan controller.PolicyState, 1),
		intel: make(chan intel.Blocklist, 1), done: make(chan error, 1), cancel: cancel}
	ex := access(&gw.Enforcer{NFT: rec, ManagementPort: 8443}, engine)
	go func() {
		g.done <- ServeGW(ctx, ours, ex, gwHello{Name: "gw"}, GWNotices{Changes: g.changes, Certs: g.certs, Policies: g.policies, Intel: g.intel}, quiet)
	}()
	t.Cleanup(func() { cancel(); <-g.done })

	var hello gwHello
	if g.remote, err = DialGW(theirs, &hello, quiet); err != nil {
		t.Fatal(err)
	}
	if hello.Name != "gw" {
		t.Fatalf("設定 = %+v", hello)
	}
	return g
}

// 非特権のプロセスは、遮断、所属、DNS で得たアドレスを執行部に頼み、執行部は nft に反映する。
func TestGWSeparated(t *testing.T) {
	g := startGW(t, 0, fullAccess)
	ctx := context.Background()
	pc := netip.MustParseAddr("10.77.0.100")
	if err := g.remote.Sync(ctx, map[netip.Addr]policy.IsolationLevel{pc: policy.IsolateFull}, map[string]policy.IsolationLevel{"02:00:00:00:00:01": policy.IsolateFull}); err != nil {
		t.Fatal(err)
	}
	m := egress.Membership{MACs: map[string]string{"02:00:00:00:00:02": "strict"}, IPs: map[netip.Addr]string{netip.MustParseAddr("10.77.0.101"): "strict"}}
	if err := g.remote.SetMembership(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err := g.remote.Learn(ctx, egress.Target{Group: 1, Specs: []int{0}}, []netip.Addr{netip.MustParseAddr("192.0.2.10")}, time.Minute); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(g.nft.all(), "\n")
	for _, want := range []string{"10.77.0.100", "02:00:00:00:00:01", "02:00:00:00:00:02", "g1_a0_d4 { 192.0.2.10 timeout 90s }"} {
		if !strings.Contains(all, want) {
			t.Errorf("nft に %q が含まれない\n%s", want, all)
		}
	}

	// 執行部が見つけた設定ファイルの変更は、非特権のプロセスに届く。
	g.changes <- "/etc/susanoo/gw.json"
	select {
	case path := <-g.remote.Changes():
		if path != "/etc/susanoo/gw.json" {
			t.Errorf("変更の知らせ = %q", path)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("設定ファイルの変更が届かない")
	}
}

// 乗っ取られた非特権のプロセスが頼んでも、執行部は検証に通らない値を nft に渡さない。
func TestGWRefusesInvalidRequests(t *testing.T) {
	g := startGW(t, 0, fullAccess)
	ctx := context.Background()
	ip := []netip.Addr{netip.MustParseAddr("192.0.2.10")}
	for name, call := range map[string]func() error{
		"範囲の外のグループ":  func() error { return g.remote.Learn(ctx, egress.Target{Group: 7, Specs: []int{0}}, ip, time.Minute) },
		"学習モードのグループ": func() error { return g.remote.Learn(ctx, egress.Target{Group: 0, Specs: []int{0}}, ip, time.Minute) },
		"nft の構文を混ぜた MAC": func() error {
			return g.remote.Sync(ctx, nil, map[string]policy.IsolationLevel{"x }; flush ruleset; {": policy.IsolateFull})
		},
		"不明な隔離の段階": func() error { return g.remote.Sync(ctx, map[netip.Addr]policy.IsolationLevel{ip[0]: "open"}, nil) },
		"nft の構文を混ぜた所属": func() error {
			return g.remote.SetMembership(ctx, egress.Membership{MACs: map[string]string{"; flush ruleset": "strict"}})
		},
		"知らない要求": func() error { return g.remote.p.call(ctx, "flush", nil, nil) },
	} {
		if err := call(); err == nil {
			t.Errorf("%s を受け付けた", name)
		}
	}
	for _, s := range g.nft.all() {
		if strings.Contains(s, "flush ruleset") {
			t.Fatalf("nft に不正な値が渡った: %s", s)
		}
	}
	// 中身の形が違う要求は、乗っ取られた恐れがあるとみなして、つながりを切る。
	if err := g.remote.p.call(ctx, reqLearn, map[string]any{"target": map[string]any{"set": "g1_a0_d4"}}, nil); err == nil {
		t.Error("知らない項目を含む要求を受け付けた")
	}
	select {
	case err := <-g.done:
		if err == nil || errors.Is(err, ErrWorkerStopped) {
			t.Errorf("ServeGW の結果 = %v", err)
		}
		g.done <- err
	case <-time.After(5 * time.Second):
		t.Fatal("不正な要求でつながりを切らない")
	}
	<-g.remote.Done()
	if err := g.remote.Sync(ctx, nil, nil); !errors.Is(err, ErrExecutorStopped) {
		t.Errorf("切れた後の要求 = %v", err)
	}
}

// DNS の応答ごとの追加は並行して受け付け、執行部で nft の実行をまとめる。
func TestGWLearnIsBatched(t *testing.T) {
	g := startGW(t, 20*time.Millisecond, fullAccess)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make([]error, 20)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = g.remote.Learn(ctx, egress.Target{Group: 1, Specs: []int{0}}, []netip.Addr{netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})}, time.Minute)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := len(g.nft.all()); n >= len(errs) {
		t.Errorf("nft を %d 回実行した（まとめられていない）", n)
	}
}

// 非特権のプロセスが止まると、執行部は ErrWorkerStopped を返す。
func TestGWWorkerStopping(t *testing.T) {
	g := startGW(t, 0, fullAccess)
	g.remote.Close()
	select {
	case err := <-g.done:
		if !errors.Is(err, ErrWorkerStopped) {
			t.Errorf("ServeGW の結果 = %v", err)
		}
		g.done <- err
	case <-time.After(5 * time.Second):
		t.Fatal("非特権のプロセスが止まったことに気づかない")
	}
}

// LAN 側の処理のつながりは DNS で得たアドレスの追加だけを受け付け、遮断や所属の変更を頼まれたら
// 乗っ取られた恐れがあるとみなしてつながりを切る。
func TestGWLANConnectionIsRestricted(t *testing.T) {
	for name, call := range map[string]func(*GWRemote) error{
		"遮断の解除": func(r *GWRemote) error { return r.Sync(context.Background(), nil, nil) },
		"ポリシーの適用": func(r *GWRemote) error {
			_, err := r.ApplyPolicy(context.Background(), sign.Envelope{Purpose: sign.PurposePolicy}, false)
			return err
		},
		"脅威情報の適用": func(r *GWRemote) error {
			return r.ApplyIntel(context.Background(), sign.Envelope{Purpose: sign.PurposeIntel})
		},
		"証明書の発行": func(r *GWRemote) error {
			_, err := r.IssueClient(context.Background(), "pc-001", make(ed25519.PublicKey, ed25519.PublicKeySize))
			return err
		},
		"所属の変更": func(r *GWRemote) error {
			return r.SetMembership(context.Background(), egress.Membership{MACs: map[string]string{"02:00:00:00:00:09": "default"}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			g := startGW(t, 0, func(_ controller.Enforcer, e *egress.Engine) GWExecutor { return GWExecutor{Learner: e} })
			if err := g.remote.Learn(context.Background(), egress.Target{Group: 1, Specs: []int{0}}, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, time.Minute); err != nil {
				t.Fatal(err)
			}
			if err := call(g.remote); err == nil {
				t.Fatal("受け付けない要求が通った")
			}
			select {
			case err := <-g.done:
				if err == nil || errors.Is(err, ErrWorkerStopped) {
					t.Errorf("ServeGW の結果 = %v", err)
				}
				g.done <- err
			case <-time.After(5 * time.Second):
				t.Fatal("受け付けない要求でつながりを切らない")
			}
			for _, s := range g.nft.all() {
				if strings.Contains(s, "susanoo_gw") || strings.Contains(s, "02:00:00:00:00:09") {
					t.Errorf("受け付けない要求を nft に反映した: %s", s)
				}
			}
		})
	}
}

// CONTROLLER は端末の証明書の発行を執行部に頼み、執行部は更新した CONTROLLER の証明書を知らせる。
func TestGWCertificates(t *testing.T) {
	g := startGW(t, 0, fullAccess)
	priv, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := g.remote.IssueClient(context.Background(), "pc-001", priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := pki.IdentityFromCert(cert); id != (pki.Identity{Role: pki.RoleClient, ID: "pc-001"}) {
		t.Errorf("発行した証明書の持ち主 = %v", id)
	}
	if _, err := g.remote.IssueClient(context.Background(), "PC 001", priv.Public().(ed25519.PublicKey)); err == nil {
		t.Error("不正な ID で発行した")
	}
	g.certs <- []byte("new-cert")
	select {
	case der := <-g.remote.Certs():
		if string(der) != "new-cert" {
			t.Errorf("届いた証明書 = %q", der)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("更新した証明書の知らせが届かない")
	}
}

// CONTROLLER はポリシーの適用を執行部に頼み、執行部は切り替えたポリシーを LAN 側の処理に知らせる。
func TestGWPolicies(t *testing.T) {
	g := startGW(t, 0, fullAccess)
	ctx := context.Background()
	st, err := g.remote.ApplyPolicy(ctx, sign.Envelope{Purpose: sign.PurposePolicy, Payload: []byte(`{"v":3}`)}, true)
	if err != nil || string(st.Current) != `{"v":1}` || string(st.Canary) != `{"v":3}` {
		t.Errorf("先行適用の応答 = %+v、%v", st, err)
	}
	if st, err := g.remote.PromotePolicy(ctx); err != nil || string(st.Current) != `{"v":2}` {
		t.Errorf("全体に広げた応答 = %+v、%v", st, err)
	}
	if _, err := g.remote.AbortPolicy(ctx); err == nil || !strings.Contains(err.Error(), "先行適用") {
		t.Errorf("取り消しの応答 = %v", err)
	}
	g.policies <- controller.PolicyState{Current: []byte(`{"v":4}`)}
	select {
	case st := <-g.remote.Policies():
		if string(st.Current) != `{"v":4}` {
			t.Errorf("届いたポリシー = %+v", st)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("切り替えたポリシーの知らせが届かない")
	}
}

// CONTROLLER は脅威情報の適用を執行部に頼み、執行部は DNS で引かせないドメインを LAN 側の処理に知らせる。
// 大きな一覧（数 MB）も 1 回で渡せる。
func TestGWIntel(t *testing.T) {
	g := startGW(t, 0, fullAccess)
	big := make([]byte, 5<<20) // 脅威情報の上限（intel.MaxBytes）。base64 で 4/3 倍になる
	for i := range big {
		big[i] = 'a' + byte(i%26)
	}
	if err := g.remote.ApplyIntel(context.Background(), sign.Envelope{Purpose: sign.PurposeIntel, Payload: big}); err != nil {
		t.Fatal(err)
	}
	if err := g.remote.ApplyIntel(context.Background(), sign.Envelope{Purpose: sign.PurposePolicy}); err == nil || !strings.Contains(err.Error(), "用途") {
		t.Errorf("執行部が断った適用 = %v", err)
	}
	// 上限を超えるものは送らずにエラーを返し、つながりはそのまま使える。
	if err := g.remote.ApplyIntel(context.Background(), sign.Envelope{Purpose: sign.PurposeIntel, Payload: make([]byte, 7<<20)}); !errors.Is(err, errFrameTooLarge) {
		t.Errorf("大きすぎる適用 = %v", err)
	}
	if err := g.remote.ApplyIntel(context.Background(), sign.Envelope{Purpose: sign.PurposeIntel}); err != nil {
		t.Errorf("大きすぎる適用の後 = %v", err)
	}
	var domains []string
	for i := range 100000 {
		domains = append(domains, fmt.Sprintf("host-%06d.malware.example", i))
	}
	g.intel <- intel.Blocklist{Version: 3, Lists: []intel.BlocklistPart{{Name: "phishing", Domains: domains}}}
	select {
	case b := <-g.remote.Intel():
		if b.Version != 3 || len(b.Lists) != 1 || len(b.Lists[0].Domains) != 100000 {
			t.Errorf("届いた一覧 = 版 %d、%d 個", b.Version, len(b.Lists))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("脅威情報の知らせが届かない")
	}
}
