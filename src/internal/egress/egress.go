// Package egress は GW の外部通信の制御（G2）、DNS の制御（G3）、抜け道の遮断（G4）をまとめる。
//
// ポリシーのグループごとに、DNS の問い合わせへの対応を決め（dns.Policy を満たす）、
// nftables の外部通信の制御のテーブル（nft.Egress）を管理する。許可リストで運用するグループ
// （既定の扱いが deny）では、許可に一致した名前を DNS で解決したときに、そのアドレスを有効期限付きで許可に加える。
// 隔離中で更新サーバーへの通信を許す端末には、ドメインで指定した更新サーバーの名前だけを引かせ、
// そのアドレスを GW の遮断のテーブルの許可に加える。
//
// GW の権限を分けるとき（G12）は、非特権の側の Engine は判断だけを行い、nftables への反映は
// Enforcer（執行部への要求）に任せる。執行部は集合の名前を受け取らず、ポリシーの中の番号（Target）を
// 自分の Engine で検証してから名前にする。
package egress

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"susanoo/internal/dns"
	"susanoo/internal/intel"
	"susanoo/internal/nft"
	"susanoo/internal/policy"
)

// DNS で得たアドレスを許可に加える期間。TTL をこの範囲に収め、余裕を足す。
const (
	minLearnTTL = time.Minute
	maxLearnTTL = time.Hour
	learnGrace  = 30 * time.Second
	nftTimeout  = 10 * time.Second
)

// Membership は端末のグループと隔離の状態。CONTROLLER が台帳から作る。
type Membership struct {
	MACs     map[string]string                    // MAC アドレス → グループ名（既定のグループの端末は含めない）
	IPs      map[netip.Addr]string                // アドレス → グループ名（既定のグループの端末は含めない）
	Isolated map[netip.Addr]policy.IsolationLevel // 隔離中のアドレス
}

// Target は DNS で得たアドレスを加える先。集合の名前ではなく、ポリシーの中の番号で表す。
type Target struct {
	Updates bool  `json:"updates,omitempty"` // 隔離中の端末に許す更新サーバー（GW の遮断のテーブル）
	Group   int   `json:"group"`             // グループの番号（0 が既定のグループ）
	Specs   []int `json:"specs,omitempty"`   // ポートの指定の番号
}

// Enforcer は外部通信の制御を nftables に反映する。nft を持つ Engine 自身が満たし、
// 権限を分けるときは執行部への要求で満たす。
type Enforcer interface {
	SetMembership(ctx context.Context, m Membership) error
	Learn(ctx context.Context, t Target, ips []netip.Addr, ttl time.Duration) error
}

// Config は外部通信の制御の設定。NFT と Remote のどちらか一方を指定する。
type Config struct {
	Policy *policy.Policy
	LAN    string     // LAN 側のインターフェース
	DNS    netip.Addr // GW の LAN 側のアドレス。有効なら LAN の DNS を GW のリゾルバに向け直す
	DNS6   netip.Addr // GW の LAN 側の IPv6 アドレス。有効なら LAN の IPv6 の DNS も向け直す
	Family nft.Family // nftables のテーブルの種類（空なら inet。ブリッジ方式は bridge で、LAN はブリッジの LAN 側のポート）
	NFT    nft.Runner // nftables に直接反映する（執行部、または権限を分けないとき）
	Remote Enforcer   // 判断だけを行い、反映は Remote に任せる（非特権の側）
	// OnLearn は、学習モードで通した名前（blocked が false）と、遮断した名前（true）を知らせる。
	OnLearn func(group, name string, blocked bool)
	// LANPrefixes は LAN のネットワーク。DNS で得たアドレスがこの中なら許可に加えない（2m-2）。
	LANPrefixes []netip.Prefix
	Logger      *slog.Logger
}

type allowRule struct {
	dest policy.Destination
	spec int // nft.EgressRule の番号
}

type group struct {
	name     string
	specKeys []string // ポートの指定ごとの識別（プロトコルとポート。ポリシーを切り替えるときの集合の対応に使う）
	def      policy.EgressDefault
	bypass   policy.Bypass
	allow    []allowRule      // ドメインで指定した許可
	specs    []nft.EgressRule // ポートの指定ごとの許可（CIDR の許可を含む）
	deny     []policy.Destination
	denyNet  []netip.Prefix
	updates  []policy.Destination // ドメインで指定した更新サーバー
}

// compiled はポリシーから組み立てたグループ。ポリシーを切り替えるときは丸ごと入れ替える。
type compiled struct {
	groups []*group // 0 番目が既定のグループ
	byName map[string]int
}

// Engine は外部通信の制御。
type Engine struct {
	cfg     Config
	log     *slog.Logger
	comp    atomic.Pointer[compiled]
	batch   *batcher
	members atomic.Pointer[Membership]
	intel   atomic.Pointer[intel.Matcher] // 遮断する脅威情報のドメイン（G7）

	mu      sync.Mutex // nftables の操作と lastMAC を守る
	lastMAC map[string]string

	guard     learnGuard                        // 許可への追加の数（2m-2）
	onLearned atomic.Pointer[func(LearnReport)] // 許可に加えた結果の知らせ先
}

// SetLister は集合の中身を読める nft.Runner（nft.Command が満たす）。ポリシーを切り替えるとき、
// DNS で得たアドレスを引き継ぐのに使う。
type SetLister interface {
	ListSetIn(ctx context.Context, fam nft.Family, table, set string) ([]nft.Element, error)
}

var _ Enforcer = (*Engine)(nil)

// New はポリシーを読み込んで Engine を作る。
func New(cfg Config) (*Engine, error) {
	if cfg.Policy == nil || (cfg.NFT == nil) == (cfg.Remote == nil) {
		return nil, errors.New("egress: ポリシーと、nft か Remote のどちらか一方が必要です")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	e := &Engine{cfg: cfg, log: cfg.Logger}
	if cfg.NFT != nil {
		e.batch = &batcher{runner: cfg.NFT}
	}
	c, err := compilePolicy(cfg.Policy)
	if err != nil {
		return nil, err
	}
	e.comp.Store(c)
	e.members.Store(&Membership{})
	e.intel.Store(intel.NewMatcher(nil))
	return e, nil
}

// SetIntel は、DNS で引かせない脅威情報のドメイン（遮断する一覧）を切り替える（G7）。
// グループの許可リストに当てはまる名前は、許可を優先する（誤検知のときに管理者が許可できるように）。
func (e *Engine) SetIntel(m *intel.Matcher) {
	if m == nil {
		m = intel.NewMatcher(nil)
	}
	e.intel.Store(m)
}

// compilePolicy はポリシーのグループを組み立てる。既定のグループを 0 番目にする。
func compilePolicy(p *policy.Policy) (*compiled, error) {
	c := &compiled{byName: map[string]int{}}
	order := []policy.Group{*p.Group(policy.DefaultGroup)}
	for _, g := range p.Groups {
		if g.Name != policy.DefaultGroup {
			order = append(order, g)
		}
	}
	for i, pg := range order {
		g, err := compile(pg)
		if err != nil {
			return nil, err
		}
		c.groups = append(c.groups, g)
		c.byName[pg.Name] = i
	}
	return c, nil
}

func compile(pg policy.Group) (*group, error) {
	g := &group{name: pg.Name, def: pg.Egress.Default, bypass: pg.Bypass}
	specIndex := map[string]int{}
	for _, d := range pg.Egress.Allow {
		key := fmt.Sprintf("%s:%v", d.Protocol, slices.Sorted(slices.Values(d.Ports)))
		i, ok := specIndex[key]
		if !ok {
			i = len(g.specs)
			specIndex[key] = i
			g.specs = append(g.specs, nft.EgressRule{Protocol: d.Protocol, Ports: slices.Clone(d.Ports)})
			g.specKeys = append(g.specKeys, key)
		}
		if d.CIDR != "" {
			p, err := netip.ParsePrefix(d.CIDR)
			if err != nil {
				return nil, err
			}
			g.specs[i].CIDRs = append(g.specs[i].CIDRs, p)
		} else {
			g.allow = append(g.allow, allowRule{dest: d, spec: i})
		}
	}
	for _, d := range pg.Egress.Deny {
		if d.CIDR != "" {
			p, err := netip.ParsePrefix(d.CIDR)
			if err != nil {
				return nil, err
			}
			g.denyNet = append(g.denyNet, p)
		} else {
			g.deny = append(g.deny, d)
		}
	}
	for _, d := range pg.Updates {
		if d.Domain != "" {
			g.updates = append(g.updates, d)
		}
	}
	return g, nil
}

// rules は現在の所属で nftables のルールを作る。
func (e *Engine) rules() nft.Egress {
	m := e.members.Load()
	r := nft.Egress{Family: e.cfg.Family, LAN: e.cfg.LAN, DNS: e.cfg.DNS, DNS6: e.cfg.DNS6, DoH: DoHServers}
	for i, g := range e.comp.Load().groups {
		ng := nft.EgressGroup{Name: g.name, Default: g.def, Bypass: g.bypass, Allow: g.specs, Deny: g.denyNet}
		if i > 0 {
			for mac, name := range m.MACs {
				if name == g.name {
					ng.Members = append(ng.Members, mac)
				}
			}
		}
		r.Groups = append(r.Groups, ng)
	}
	return r
}

// errRemote は、判断だけを行う Engine で nftables の操作を呼んだことを表す。
var errRemote = errors.New("egress: この Engine は nftables を操作しません")

// Apply は外部通信の制御のテーブルを作り直す。DNS で得たアドレスは消える（起動時に使う）。
func (e *Engine) Apply(ctx context.Context) error {
	if e.batch == nil {
		return errRemote
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	script, err := e.rules().Script()
	if err != nil {
		return err
	}
	if err := e.batch.run(ctx, script); err != nil {
		return err
	}
	e.lastMAC = maps.Clone(e.members.Load().MACs)
	return nil
}

// SetMembership は端末のグループと隔離の状態を更新する。MAC アドレスの所属が変わったときだけ、
// nftables の所属の集合を入れ替える（DNS で得たアドレスは保つ）。
func (e *Engine) SetMembership(ctx context.Context, m Membership) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	m.MACs = maps.Clone(m.MACs)
	byName := e.comp.Load().byName
	for mac, name := range m.MACs {
		if _, ok := byName[name]; !ok {
			delete(m.MACs, mac) // ポリシーにないグループは既定のグループとして扱う
		}
	}
	e.members.Store(&m)
	if e.cfg.Remote != nil {
		return e.cfg.Remote.SetMembership(ctx, m)
	}
	if maps.Equal(e.lastMAC, m.MACs) {
		return nil
	}
	script, err := e.rules().MembersScript()
	if err != nil {
		return err
	}
	if script != "" {
		if err := e.batch.run(ctx, script); err != nil {
			return err
		}
	}
	e.lastMAC = maps.Clone(m.MACs)
	return nil
}

// Reconfigure はポリシーを切り替える（M2）。nftables に反映する Engine では、外部通信の制御のテーブルを作り直し、
// DNS で得たアドレスのうち、新しいポリシーにも同じグループ・同じポートの指定があるものは、残りの期限のまま引き継ぐ。
// 端末のグループは今のものを使う（新しいポリシーにないグループの端末は既定のグループになる）。
func (e *Engine) Reconfigure(ctx context.Context, p *policy.Policy) error {
	next, err := compilePolicy(p)
	if err != nil {
		return err
	}
	if e.batch == nil {
		e.comp.Store(next)
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	learned := e.learnedLocked(ctx)
	prev := e.comp.Load()
	e.comp.Store(next)
	script, err := e.rules().Script()
	if err == nil {
		err = e.batch.run(ctx, script)
	}
	if err != nil {
		e.comp.Store(prev) // テーブルは nft -f で一度に置き換えるので、失敗したら元のまま
		return err
	}
	e.lastMAC = maps.Clone(e.members.Load().MACs)
	var b strings.Builder
	for gi, g := range next.groups {
		if g.def != policy.EgressDeny {
			continue
		}
		for si, key := range g.specKeys {
			for v6, elems := range learned[g.name+"\x00"+key] {
				for _, el := range elems {
					b.WriteString(nft.AddWithTimeoutIn(e.cfg.Family, nft.EgressTable, nft.AllowSet(gi, si, v6), []netip.Addr{el.Addr}, el.Expires))
				}
			}
		}
	}
	if b.Len() > 0 {
		if err := e.batch.run(ctx, b.String()); err != nil {
			e.log.Warn("DNS で得たアドレスを引き継げません。端末が名前を引き直すと戻ります", "エラー", err)
		}
	}
	return nil
}

// learnedLocked は、許可リストのグループの DNS で得たアドレスを、グループの名前とポートの指定ごとに読み出す。
// 読めなければ空を返す（引き継がない）。
func (e *Engine) learnedLocked(ctx context.Context) map[string]map[bool][]nft.Element {
	out := map[string]map[bool][]nft.Element{}
	lister, ok := e.cfg.NFT.(SetLister)
	if !ok {
		return out
	}
	for gi, g := range e.comp.Load().groups {
		if g.def != policy.EgressDeny {
			continue
		}
		for si, key := range g.specKeys {
			for _, v6 := range []bool{false, true} {
				elems, err := lister.ListSetIn(ctx, e.cfg.Family, nft.EgressTable, nft.AllowSet(gi, si, v6))
				if err != nil {
					continue
				}
				k := g.name + "\x00" + key
				if out[k] == nil {
					out[k] = map[bool][]nft.Element{}
				}
				for _, el := range elems {
					if el.Expires > 0 {
						out[k][v6] = append(out[k][v6], el)
					}
				}
			}
		}
	}
	return out
}

// FailOpen は障害時に通信を通す（fail_open）設定にする。外部通信の制御をやめ、
// upstream が有効なら LAN の DNS を上流の DNS サーバーに向け直す。
func (e *Engine) FailOpen(ctx context.Context, upstream netip.AddrPort) error {
	if e.batch == nil {
		return errRemote
	}
	script, err := nft.FailOpenScript(e.cfg.LAN, e.cfg.DNS, upstream)
	if e.cfg.Family == nft.Bridge {
		// ブリッジ方式の DNS の向け直しは BridgeRules が行うので、ここでは外部通信の制御をやめるだけ。
		script, err = nft.DeleteTableIn(nft.Bridge, nft.EgressTable), nil
	}
	if err != nil {
		return err
	}
	return e.batch.run(ctx, script)
}

// Decide は DNS の問い合わせへの対応を決める（dns.Policy）。
func (e *Engine) Decide(client netip.Addr, q dns.Question) dns.Verdict {
	m := e.members.Load()
	c := e.comp.Load()
	gi := 0
	if name, ok := m.IPs[client]; ok {
		if i, ok := c.byName[name]; ok {
			gi = i
		}
	}
	g := c.groups[gi]
	v := dns.Verdict{Group: g.name}
	name := q.Name

	if level, ok := m.Isolated[client]; ok {
		if level == policy.IsolateManagementAndUpdates && matchAny(g.updates, name) {
			v.Action = dns.Forward
			v.Learn = e.learner(Target{Updates: true})
			return v
		}
		v.Action, v.Reason = dns.Refuse, "隔離中"
		return v
	}
	switch {
	case !g.bypass.AllowECH && (q.Type == dns.TypeHTTPS || q.Type == dns.TypeSVCB):
		v.Action, v.Reason = dns.NoData, "ECH の設定を含むレコード"
		return v
	case !g.bypass.AllowDoH && matchAny(dohNames, name):
		v.Action, v.Reason = dns.Block, "DoH の接続先"
		return v
	case !g.bypass.AllowVPN && matchAny(relayNames, name):
		v.Action, v.Reason = dns.Block, "プライベートリレー"
		return v
	case matchAny(g.deny, name):
		v.Action, v.Reason = dns.Block, "拒否リスト"
		e.notify(g.name, name, true)
		return v
	}

	var specs []int
	for _, a := range g.allow {
		if a.dest.MatchDomain(name) && !slices.Contains(specs, a.spec) {
			specs = append(specs, a.spec)
		}
	}
	if len(specs) == 0 && g.def != policy.EgressDeny {
		if ms := e.intel.Load().Domain(name); len(ms) > 0 {
			v.Action, v.Reason = dns.Block, "脅威情報（"+ms[0].List+"）"
			e.notify(g.name, name, true)
			return v
		}
	}
	switch g.def {
	case policy.EgressDeny:
		if len(specs) == 0 {
			v.Action, v.Reason = dns.Block, "許可リストにない"
			e.notify(g.name, name, true)
			return v
		}
		v.Learn = e.learner(Target{Group: gi, Specs: specs})
	case policy.EgressLearn:
		if len(specs) == 0 {
			e.notify(g.name, name, false)
		}
	}
	v.Action = dns.Forward
	return v
}

func (e *Engine) notify(group, name string, blocked bool) {
	if e.cfg.OnLearn != nil && name != "" {
		e.cfg.OnLearn(group, name, blocked)
	}
}

func (e *Engine) learner(t Target) func(context.Context, []netip.Addr, time.Duration) error {
	return func(ctx context.Context, ips []netip.Addr, ttl time.Duration) error { return e.Learn(ctx, t, ips, ttl) }
}

// sets は Target を検証し、加える先のテーブルと集合の名前を返す。権限を分けるとき、執行部は
// 非特権の側から届いた Target をここで検証する。
func (e *Engine) sets(t Target) (table string, sets4, sets6 []string, err error) {
	if t.Updates {
		if t.Group != 0 || len(t.Specs) != 0 {
			return "", nil, nil, errors.New("egress: 更新サーバーの指定にグループは要りません")
		}
		return nft.GWTable, []string{nft.UpdatesDynamicSet(false)}, []string{nft.UpdatesDynamicSet(true)}, nil
	}
	groups := e.comp.Load().groups
	if t.Group < 0 || t.Group >= len(groups) {
		return "", nil, nil, fmt.Errorf("egress: グループの番号 %d は範囲の外です", t.Group)
	}
	g := groups[t.Group]
	if g.def != policy.EgressDeny || len(t.Specs) == 0 {
		return "", nil, nil, fmt.Errorf("egress: グループ %q は許可リストで運用していません", g.name)
	}
	seen := map[int]bool{}
	for _, s := range t.Specs {
		if s < 0 || s >= len(g.specs) || seen[s] {
			return "", nil, nil, fmt.Errorf("egress: ポートの指定の番号 %d が不正です", s)
		}
		seen[s] = true
		sets4 = append(sets4, nft.AllowSet(t.Group, s, false))
		sets6 = append(sets6, nft.AllowSet(t.Group, s, true))
	}
	return nft.EgressTable, sets4, sets6, nil
}

// Learn は、DNS で得たアドレスを有効期限付きで t の集合に加える。未指定のアドレス（遮断の代わりに返す DNS もある）は
// 黙って加えず、特別な用途、LAN、私的なアドレスと、1 分間に maxNewPerMinute を超える新しいアドレスは加えずに知らせる（2m-2）。
func (e *Engine) Learn(ctx context.Context, t Target, ips []netip.Addr, ttl time.Duration) error {
	if e.cfg.Remote != nil {
		return e.cfg.Remote.Learn(ctx, t, ips, ttl)
	}
	table, sets4, sets6, err := e.sets(t)
	if err != nil {
		return err
	}
	report := LearnReport{Time: time.Now(), Updates: t.Updates}
	allowPrivate := false
	if groups := e.comp.Load().groups; !t.Updates && t.Group < len(groups) { // sets で確かめた後にポリシーが変わることもある
		g := groups[t.Group]
		report.Group, allowPrivate = g.name, g.bypass.AllowPrivateDNS
	}
	key := targetKey(t)
	timeout := min(max(ttl, minLearnTTL), maxLearnTTL) + learnGrace
	var v4, v6 []netip.Addr
	for _, ip := range ips {
		ip = ip.Unmap()
		if !ip.IsValid() || ip.IsUnspecified() {
			continue
		}
		reason := e.refuseReason(ip, allowPrivate)
		if reason == "" && !e.guard.allow(key, ip, report.Time) {
			reason = RefuseRate
		}
		if reason != "" {
			report.Refused = append(report.Refused, RefusedAddr{Addr: ip, Reason: reason})
			continue
		}
		report.Added = append(report.Added, ip)
		if ip.Is4() {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	defer e.reportLearned(report)
	var b strings.Builder
	for _, s := range sets4 {
		b.WriteString(nft.AddWithTimeoutIn(e.cfg.Family, table, s, v4, timeout))
	}
	for _, s := range sets6 {
		b.WriteString(nft.AddWithTimeoutIn(e.cfg.Family, table, s, v6, timeout))
	}
	if b.Len() == 0 {
		return nil
	}
	return e.batch.run(ctx, b.String())
}

// batcher は nftables への変更を順に適用する。同時に来た変更は 1 回の nft の実行にまとめる。
// まとめた変更が失敗したら、1 件ずつ適用し直して、失敗したものだけにエラーを返す。
type batcher struct {
	runner nft.Runner

	mu      sync.Mutex
	pending []string
	waiters []chan error
	running bool
}

func (b *batcher) run(ctx context.Context, script string) error {
	ch := make(chan error, 1)
	b.mu.Lock()
	b.pending = append(b.pending, script)
	b.waiters = append(b.waiters, ch)
	if !b.running {
		b.running = true
		go b.loop()
	}
	b.mu.Unlock()
	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *batcher) loop() {
	for {
		b.mu.Lock()
		if len(b.pending) == 0 {
			b.running = false
			b.mu.Unlock()
			return
		}
		scripts, waiters := b.pending, b.waiters
		b.pending, b.waiters = nil, nil
		b.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), nftTimeout)
		err := b.runner.Run(ctx, strings.Join(scripts, ""))
		if err != nil && len(scripts) > 1 {
			for i, s := range scripts {
				waiters[i] <- b.runner.Run(ctx, s)
			}
		} else {
			for _, w := range waiters {
				w <- err
			}
		}
		cancel()
	}
}
