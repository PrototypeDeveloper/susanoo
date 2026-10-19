package egress

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"susanoo/internal/dns"
	"susanoo/internal/intel"
	"susanoo/internal/nft"
	"susanoo/internal/policy"
)

type recorder struct {
	mu      sync.Mutex
	scripts []string
	delay   time.Duration
}

func (r *recorder) Run(_ context.Context, script string) error {
	time.Sleep(r.delay)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scripts = append(r.scripts, script)
	if strings.Contains(script, "bad") {
		return errors.New("nft: syntax error")
	}
	return nil
}

func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.scripts...)
}

var testPolicy = &policy.Policy{
	Version: 1, Name: "試験", IssuedAt: time.Now(), Response: policy.ResponseEnforce, OnFailure: policy.FailOpen,
	Groups: []policy.Group{
		{
			Name: "strict", Isolation: policy.IsolateManagement,
			Egress: policy.Egress{Default: policy.EgressDeny, Allow: []policy.Destination{
				{Domain: "allowed.test", Ports: []uint16{8080}, Protocol: "tcp"},
				{Domain: "*.cdn.test"},
				{CIDR: "192.0.2.0/24", Ports: []uint16{443}, Protocol: "tcp"},
			}},
			Bypass: policy.Bypass{AllowQUIC: true},
		},
		{
			Name: policy.DefaultGroup, Isolation: policy.IsolateManagementAndUpdates,
			Egress:  policy.Egress{Default: policy.EgressLearn, Deny: []policy.Destination{{Domain: "*.blocked.test"}, {CIDR: "203.0.113.0/24"}}},
			Updates: []policy.Destination{{Domain: "updates.test"}, {CIDR: "198.51.100.0/24"}},
		},
	},
}

type learned struct {
	group, name string
	blocked     bool
}

func newEngine(t *testing.T) (*Engine, *recorder, *[]learned) {
	t.Helper()
	r := &recorder{}
	var mu sync.Mutex
	var got []learned
	e, err := New(Config{
		Policy: testPolicy, LAN: "lan0", DNS: netip.MustParseAddr("10.77.0.1"), NFT: r,
		OnLearn: func(g, n string, b bool) { mu.Lock(); got = append(got, learned{g, n, b}); mu.Unlock() },
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return e, r, &got
}

var (
	pcDefault  = netip.MustParseAddr("10.77.0.100")
	pcStrict   = netip.MustParseAddr("10.77.0.101")
	pcIsolated = netip.MustParseAddr("10.77.0.102")
)

func membership() Membership {
	return Membership{
		MACs:     map[string]string{"02:00:00:00:00:65": "strict"},
		IPs:      map[netip.Addr]string{pcStrict: "strict"},
		Isolated: map[netip.Addr]policy.IsolationLevel{pcIsolated: policy.IsolateManagementAndUpdates},
	}
}

func TestDecide(t *testing.T) {
	e, _, got := newEngine(t)
	if err := e.SetMembership(context.Background(), membership()); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		client  netip.Addr
		name    string
		qtype   uint16
		action  dns.Action
		group   string
		reason  string
		learner bool
	}{
		{pcDefault, "www.example.jp", dns.TypeA, dns.Forward, "default", "", false},
		{pcDefault, "x.blocked.test", dns.TypeA, dns.Block, "default", "拒否リスト", false},
		{pcDefault, "www.example.jp", dns.TypeHTTPS, dns.NoData, "default", "ECH の設定を含むレコード", false},
		{pcDefault, "use-application-dns.net", dns.TypeA, dns.Block, "default", "DoH の接続先", false},
		{pcDefault, "chrome.cloudflare-dns.com", dns.TypeA, dns.Block, "default", "DoH の接続先", false},
		{pcDefault, "mask.icloud.com", dns.TypeA, dns.Block, "default", "プライベートリレー", false},
		{pcStrict, "allowed.test", dns.TypeA, dns.Forward, "strict", "", true},
		{pcStrict, "img.cdn.test", dns.TypeAAAA, dns.Forward, "strict", "", true},
		{pcStrict, "www.example.jp", dns.TypeA, dns.Block, "strict", "許可リストにない", false},
		{pcIsolated, "updates.test", dns.TypeA, dns.Forward, "default", "", true},
		{pcIsolated, "www.example.jp", dns.TypeA, dns.Refuse, "default", "隔離中", false},
	}
	for _, tt := range tests {
		v := e.Decide(tt.client, dns.Question{Name: tt.name, Type: tt.qtype, Class: 1})
		if v.Action != tt.action || v.Group != tt.group || v.Reason != tt.reason || (v.Learn != nil) != tt.learner {
			t.Errorf("%s の %s: %+v（Learn %v）", tt.client, tt.name, v, v.Learn != nil)
		}
	}
	want := []learned{{"default", "www.example.jp", false}, {"default", "x.blocked.test", true}, {"strict", "www.example.jp", true}}
	if len(*got) != len(want) {
		t.Fatalf("記録 = %+v", *got)
	}
	for i := range want {
		if (*got)[i] != want[i] {
			t.Errorf("記録 %d = %+v, 期待値 %+v", i, (*got)[i], want[i])
		}
	}
}

// 脅威情報の遮断の一覧のドメインとその下の名前は引かせない。許可リストに当てはまる名前は許可を優先する。
func TestDecideIntel(t *testing.T) {
	e, _, got := newEngine(t)
	e.SetMembership(context.Background(), membership())
	set := &intel.Set{Version: 1, IssuedAt: time.Now(), Lists: []intel.List{
		{Name: "phishing", Action: intel.ActionBlock, Domains: []string{"evil.test", "allowed.test"}},
		{Name: "watch", Action: intel.ActionAlert, Domains: []string{"watch.test"}},
	}}
	e.SetIntel(intel.NewMatcher(set, intel.ActionBlock))
	for _, tt := range []struct {
		client netip.Addr
		name   string
		action dns.Action
		reason string
	}{
		{pcDefault, "evil.test", dns.Block, "脅威情報（phishing）"},
		{pcDefault, "login.evil.test", dns.Block, "脅威情報（phishing）"},
		{pcDefault, "notevil.test", dns.Forward, ""},
		{pcDefault, "watch.test", dns.Forward, ""},     // 検知だけの一覧
		{pcStrict, "allowed.test", dns.Forward, ""},    // 許可を優先する
		{pcStrict, "evil.test", dns.Block, "許可リストにない"}, // 原則拒否のグループ
	} {
		if v := e.Decide(tt.client, dns.Question{Name: tt.name, Type: dns.TypeA, Class: 1}); v.Action != tt.action || v.Reason != tt.reason {
			t.Errorf("%s の %s: %+v", tt.client, tt.name, v)
		}
	}
	if len(*got) == 0 || (*got)[0] != (learned{"default", "evil.test", true}) {
		t.Errorf("記録 = %+v", *got)
	}
	e.SetIntel(nil)
	if v := e.Decide(pcDefault, dns.Question{Name: "evil.test", Type: dns.TypeA, Class: 1}); v.Action != dns.Forward {
		t.Errorf("脅威情報を消した後 = %+v", v)
	}
}

func TestLearnAddsToSets(t *testing.T) {
	e, r, _ := newEngine(t)
	e.SetMembership(context.Background(), membership())

	v := e.Decide(pcStrict, dns.Question{Name: "allowed.test", Type: dns.TypeA})
	err := v.Learn(context.Background(), []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}, 300*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	last := r.all()[len(r.all())-1]
	// strict は 1 番目のグループ。allowed.test は 0 番目の許可（TCP 8080）。期限は TTL に余裕を足したもの。
	for _, want := range []string{
		"add element inet susanoo_egress g1_a0_d4 { 192.0.2.10 timeout 330s }",
		"add element inet susanoo_egress g1_a0_d6 { 2001:db8::10 timeout 330s }",
	} {
		if !strings.Contains(last, want) {
			t.Errorf("%q が含まれない\n%s", want, last)
		}
	}

	// TTL が短すぎても長すぎても、範囲に収める。
	v = e.Decide(pcIsolated, dns.Question{Name: "updates.test", Type: dns.TypeA})
	v.Learn(context.Background(), []netip.Addr{netip.MustParseAddr("198.51.100.7")}, 0)
	if last := r.all()[len(r.all())-1]; !strings.Contains(last, "add element inet susanoo_gw updates_dyn_4 { 198.51.100.7 timeout 90s }") {
		t.Errorf("更新サーバーの追加 = %s", last)
	}
	v = e.Decide(pcStrict, dns.Question{Name: "a.cdn.test", Type: dns.TypeA})
	v.Learn(context.Background(), []netip.Addr{netip.MustParseAddr("192.0.2.11")}, 10*time.Hour)
	if last := r.all()[len(r.all())-1]; !strings.Contains(last, "g1_a1_d4 { 192.0.2.11 timeout 3630s }") {
		t.Errorf("長い TTL の追加 = %s", last)
	}
}

func TestApplyAndMembership(t *testing.T) {
	e, r, _ := newEngine(t)
	if err := e.SetMembership(context.Background(), membership()); err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	script := r.all()[len(r.all())-1]
	for _, want := range []string{
		"\tset g1_m {\n\t\ttype ether_addr\n\t\telements = { 02:00:00:00:00:65 }\n\t}\n",
		"\tset g1_a2_s4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { 192.0.2.0/24 }\n\t}\n",
		"\tset g0_d_s4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { 203.0.113.0/24 }\n\t}\n",
		"dnat ip to 10.77.0.1:53",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("%q が含まれない\n%s", want, script)
		}
	}

	n := len(r.all())
	// 所属が変わらなければ nftables は変えない。
	e.SetMembership(context.Background(), membership())
	if len(r.all()) != n {
		t.Error("所属が変わらないのに nftables を変えた")
	}
	// 所属が変われば、所属の集合だけを入れ替える。ポリシーにないグループは既定のグループとして扱う。
	m := membership()
	m.MACs["02:00:00:00:00:66"] = "strict"
	m.MACs["02:00:00:00:00:67"] = "unknown"
	e.SetMembership(context.Background(), m)
	last := r.all()[len(r.all())-1]
	if !strings.Contains(last, "flush set inet susanoo_egress g1_m\nadd element inet susanoo_egress g1_m { 02:00:00:00:00:65, 02:00:00:00:00:66 }") || strings.Contains(last, "delete table") {
		t.Errorf("所属の入れ替え = %s", last)
	}
}

func TestBatcher(t *testing.T) {
	r := &recorder{delay: 20 * time.Millisecond}
	b := &batcher{runner: r}
	var wg sync.WaitGroup
	errs := make([]error, 10)
	for i := range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := "add element ok\n"
			if i == 3 {
				s = "bad\n"
			}
			errs[i] = b.run(context.Background(), s)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if (err != nil) != (i == 3) {
			t.Errorf("%d 番目のエラー = %v", i, err)
		}
	}
	// 同時に来た変更はまとめて適用する（失敗したまとまりは 1 件ずつ適用し直す）。
	if n := len(r.all()); n >= 20 {
		t.Errorf("nft を %d 回実行した（まとめていない）", n)
	}
}

func TestFailOpen(t *testing.T) {
	e, r, _ := newEngine(t)
	if err := e.FailOpen(context.Background(), netip.MustParseAddrPort("192.0.2.53:53")); err != nil {
		t.Fatal(err)
	}
	if last := r.all()[0]; !strings.Contains(last, "dnat ip to 192.0.2.53:53") || strings.Contains(last, "forward") {
		t.Errorf("障害時に通す設定 = %s", last)
	}
}

// remoteRecorder は執行部の代わりに、届いた要求を記録する。
type remoteRecorder struct {
	mu       sync.Mutex
	members  []Membership
	targets  []Target
	addrs    [][]netip.Addr
	ttls     []time.Duration
	executor *Engine // 指定されていれば、執行部の Engine で検証して反映する
}

func (r *remoteRecorder) SetMembership(ctx context.Context, m Membership) error {
	r.mu.Lock()
	r.members = append(r.members, m)
	r.mu.Unlock()
	if r.executor != nil {
		return r.executor.SetMembership(ctx, m)
	}
	return nil
}

func (r *remoteRecorder) Learn(ctx context.Context, t Target, ips []netip.Addr, ttl time.Duration) error {
	r.mu.Lock()
	r.targets, r.addrs, r.ttls = append(r.targets, t), append(r.addrs, ips), append(r.ttls, ttl)
	r.mu.Unlock()
	if r.executor != nil {
		return r.executor.Learn(ctx, t, ips, ttl)
	}
	return nil
}

// 判断だけを行う Engine（非特権の側）は、所属の変更と DNS で得たアドレスを、番号で執行部に渡す。
// 執行部の Engine は、同じポリシーから自分で集合の名前を決める。
func TestRemoteEngine(t *testing.T) {
	executor, r, _ := newEngine(t)
	remote := &remoteRecorder{executor: executor}
	e, err := New(Config{Policy: testPolicy, LAN: "lan0", DNS: netip.MustParseAddr("10.77.0.1"), Remote: remote})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := e.SetMembership(ctx, membership()); err != nil {
		t.Fatal(err)
	}
	if len(remote.members) != 1 || remote.members[0].MACs["02:00:00:00:00:65"] != "strict" {
		t.Errorf("執行部に渡した所属 = %+v", remote.members)
	}
	v := e.Decide(pcStrict, dns.Question{Name: "allowed.test", Type: dns.TypeA})
	if err := v.Learn(ctx, []netip.Addr{netip.MustParseAddr("192.0.2.10")}, 300*time.Second); err != nil {
		t.Fatal(err)
	}
	if len(remote.targets) != 1 || remote.targets[0].Group != 1 || !slices.Equal(remote.targets[0].Specs, []int{0}) {
		t.Errorf("執行部に渡した先 = %+v", remote.targets)
	}
	if last := r.all()[len(r.all())-1]; !strings.Contains(last, "g1_a0_d4 { 192.0.2.10 timeout 330s }") {
		t.Errorf("執行部の反映 = %s", last)
	}
	if err := e.Apply(ctx); err == nil {
		t.Error("判断だけの Engine でテーブルを作った")
	}
	if err := e.FailOpen(ctx, netip.AddrPort{}); err == nil {
		t.Error("判断だけの Engine で障害時の設定をした")
	}
	if _, err := New(Config{Policy: testPolicy, NFT: r, Remote: remote}); err == nil {
		t.Error("nft と Remote の両方を指定できた")
	}
}

// 執行部は、非特権の側から届いた番号を自分のポリシーで検証し、不正なものは反映しない。
// 加えるアドレスからは、ループバックやマルチキャストなどを除く。
func TestLearnValidatesTarget(t *testing.T) {
	e, r, _ := newEngine(t)
	ctx := context.Background()
	ip := []netip.Addr{netip.MustParseAddr("192.0.2.10")}
	for name, target := range map[string]Target{
		"範囲の外のグループ":      {Group: 5, Specs: []int{0}},
		"負のグループ":         {Group: -1, Specs: []int{0}},
		"学習モードのグループ":     {Group: 0, Specs: []int{0}},
		"範囲の外のポートの指定":    {Group: 1, Specs: []int{9}},
		"ポートの指定がない":      {Group: 1},
		"重なったポートの指定":     {Group: 1, Specs: []int{0, 0}},
		"更新サーバーとグループの両方": {Updates: true, Group: 1, Specs: []int{0}},
	} {
		if err := e.Learn(ctx, target, ip, time.Minute); err == nil {
			t.Errorf("%s を反映した", name)
		}
	}
	if n := len(r.all()); n != 0 {
		t.Fatalf("不正な要求で nft を %d 回実行した", n)
	}
	weird := []netip.Addr{
		netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("224.0.0.1"), netip.MustParseAddr("169.254.1.1"),
		netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("::1"), netip.MustParseAddr("fe80::1"),
	}
	if err := e.Learn(ctx, Target{Group: 1, Specs: []int{0}}, weird, time.Minute); err != nil || len(r.all()) != 0 {
		t.Errorf("加えるべきでないアドレスを反映した: %v %v", err, r.all())
	}
}

// listingRecorder は、集合の中身を読める nft の代わり。
type listingRecorder struct {
	recorder
	sets map[string][]nft.Element
}

func (r *listingRecorder) ListSetIn(_ context.Context, fam nft.Family, table, set string) ([]nft.Element, error) {
	if table != nft.EgressTable || fam.String() != "inet" {
		return nil, errors.New("知らないテーブル")
	}
	return r.sets[set], nil
}

// ポリシーを切り替えると、テーブルを作り直し、同じグループ・同じポートの指定の DNS で得たアドレスを、
// 新しい集合の名前（グループの順番が変わっても）に残りの期限のまま引き継ぐ。
func TestReconfigureKeepsLearned(t *testing.T) {
	r := &listingRecorder{sets: map[string][]nft.Element{
		"g1_a0_d4": {{Addr: netip.MustParseAddr("192.0.2.10"), Expires: 200 * time.Second}},
		"g1_a1_d4": {{Addr: netip.MustParseAddr("192.0.2.20"), Expires: 100 * time.Second}},
	}}
	e, err := New(Config{Policy: testPolicy, LAN: "lan0", NFT: r, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	e.SetMembership(ctx, membership())

	// 新しいポリシー：strict の前に別のグループを足し（strict は 2 番目になる）、*.cdn.test の許可（1 番目の指定）を外す。
	next := *testPolicy
	next.Version = 2
	next.Groups = append([]policy.Group{{Name: "lab", Isolation: policy.IsolateFull, Egress: policy.Egress{Default: policy.EgressDeny,
		Allow: []policy.Destination{{Domain: "lab.test"}}}}}, testPolicy.Groups...)
	strict := next.Groups[1]
	strict.Egress.Allow = []policy.Destination{strict.Egress.Allow[0], strict.Egress.Allow[2]}
	next.Groups[1] = strict
	if err := e.Reconfigure(ctx, &next); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(r.all(), "\n")
	if !strings.Contains(all, "delete table inet susanoo_egress") {
		t.Errorf("テーブルを作り直していない\n%s", all)
	}
	if !strings.Contains(all, "add element inet susanoo_egress g2_a0_d4 { 192.0.2.10 timeout 200s }") {
		t.Errorf("allowed.test のアドレスを新しい集合に引き継いでいない\n%s", all)
	}
	if strings.Contains(all, "192.0.2.20") {
		t.Errorf("外した許可のアドレスを引き継いだ\n%s", all)
	}
	// 判断も新しいポリシーに従う（strict の端末は、外した *.cdn.test を引けない）。
	if v := e.Decide(pcStrict, dns.Question{Name: "a.cdn.test", Type: dns.TypeA}); v.Action != dns.Block {
		t.Errorf("外した許可の名前の判断 = %+v", v)
	}
	if v := e.Decide(pcStrict, dns.Question{Name: "allowed.test", Type: dns.TypeA}); v.Action != dns.Forward || v.Learn == nil {
		t.Errorf("残した許可の名前の判断 = %+v", v)
	}
}

// ブリッジ方式では bridge のテーブルを作り、DNS で得たアドレスも bridge のテーブルに入れる。停止中は外部通信の制御のテーブルを消すだけ。
func TestBridgeFamily(t *testing.T) {
	r := &recorder{}
	e, err := New(Config{Policy: testPolicy, LAN: "lan0", Family: nft.Bridge, NFT: r, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := e.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.Learn(ctx, Target{Group: 1, Specs: []int{0}}, []netip.Addr{netip.MustParseAddr("192.0.2.10")}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := e.FailOpen(ctx, netip.MustParseAddrPort("192.0.2.53:53")); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(r.all(), "\n")
	if !strings.Contains(all, "table bridge susanoo_egress {\n") || !strings.Contains(all, "add element bridge susanoo_egress g1_a0_d4 { 192.0.2.10") ||
		strings.Contains(all, "inet") || strings.Contains(all, "dnat") {
		t.Errorf("スクリプト:\n%s", all)
	}
}
