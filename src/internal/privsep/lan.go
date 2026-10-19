package privsep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"susanoo/internal/controller"
	"susanoo/internal/egress"
)

// GW の CONTROLLER と LAN 側の処理（DNS、DHCP、ARP の監視、通信の記録）のつながり（G12）。
//
// LAN 側の処理は、LAN から届くデータ（乗っ取られた端末が送るかもしれない）を解析するので、CONTROLLER と別の利用者で
// 動かし、署名の鍵や台帳には触れさせない。LAN 側の処理から CONTROLLER へは「見つけたこと」を知らせるだけで、
// CONTROLLER はそれを検証してから、信用しない観測として扱う。CONTROLLER から LAN 側の処理へは、在席の確認（ARP）と、
// 端末のグループと隔離の状態（DNS の判断と、DHCP で割り当てないアドレスに使う）を頼む。

// LAN 側の処理から CONTROLLER への知らせと、CONTROLLER から LAN 側の処理への要求。
const (
	noticeNeighbor = "neighbor"    // ARP で見えた機器
	noticeARPReq   = "arp_req"     // ARP で LAN のアドレスを探した（LAN 内のスキャンの検知に使う）
	noticeLease    = "lease"       // DHCP の貸し出しと返却
	noticeDNS      = "dns"         // DNS の問い合わせの記録
	noticeFlow     = "flow"        // 通信の記録
	noticeLearned  = "learned"     // 学習モードで通した名前と、遮断した名前
	noticeND       = "nd"          // IPv6 の近隣探索
	noticeDHCPv6   = "dhcp6"       // GW の問い合わせに答えた DHCPv6 のサーバー
	reqProbe       = "probe"       // 機器が LAN にいるかの確認
	reqWithdrawRA  = "withdraw_ra" // 不正なルーターの広告を取り消す RA を送る
	// 端末のグループと隔離の状態は reqMembership（gw.go）で頼む。
)

const (
	maxHostname   = 255  // DHCP のホスト名の上限（オプション 12 の長さ）
	maxNDItems    = 16   // 近隣探索と DHCPv6 の知らせの、ネットワークとアドレスの数の上限
	maxLANQueue   = 4096 // CONTROLLER がまだ処理していない知らせの上限
	dropReportGap = time.Minute
)

// ErrLANStopped は、CONTROLLER と LAN 側の処理のつながりが切れたことを表す。
var ErrLANStopped = errors.New("privsep: CONTROLLER と LAN 側の処理のつながりが切れました")

// LANObserver は LAN 側の処理からの知らせを受け取る（*controller.Controller が満たす）。
type LANObserver interface {
	ObserveNeighbor(frame net.HardwareAddr, senderIP netip.Addr)
	ObserveARPRequest(frame net.HardwareAddr, target netip.Addr)
	ObserveLease(mac string, ip netip.Addr, hostname string, expiry time.Time, released bool)
	RecordDNS(r controller.DNSRecord)
	RecordFlow(r controller.FlowRecord)
	RecordLearned(group, domain string, blocked bool)
	ObserveND(o controller.NDObservation)
	ObserveDHCPv6(o controller.DHCPv6Observation)
}

// LANServices は、LAN 側の処理が CONTROLLER の要求に応える働き。
type LANServices interface {
	Probe(ctx context.Context, ip netip.Addr) (net.HardwareAddr, bool)
	SetMembership(ctx context.Context, m egress.Membership) error
	WithdrawRA(ctx context.Context, src netip.Addr, mac net.HardwareAddr, prefixes []netip.Prefix, rdnss []netip.Addr) error
}

type ndBody struct {
	MAC            string         `json:"mac"`
	Type           int            `json:"type"`
	Src            netip.Addr     `json:"src"`
	Target         netip.Addr     `json:"target,omitzero"`
	Override       bool           `json:"override,omitempty"`
	RouterLifetime int            `json:"router_lifetime,omitempty"`
	Prefixes       []netip.Prefix `json:"prefixes,omitempty"`
	RDNSS          []netip.Addr   `json:"rdnss,omitempty"`
}

type dhcp6Body struct {
	MAC     string       `json:"mac"`
	Src     netip.Addr   `json:"src"`
	DNS     []netip.Addr `json:"dns,omitempty"`
	Address []netip.Addr `json:"address,omitempty"`
}

type withdrawBody struct {
	Src      netip.Addr     `json:"src"`
	MAC      string         `json:"mac"`
	Prefixes []netip.Prefix `json:"prefixes,omitempty"`
	RDNSS    []netip.Addr   `json:"rdnss,omitempty"`
}

// ipv6Only は、アドレスがすべて IPv6（IPv4 を埋め込んだものを除く）で、数が上限の内かを確かめる。
func ipv6Only(addrs ...netip.Addr) bool {
	if len(addrs) > maxNDItems {
		return false
	}
	for _, a := range addrs {
		if !a.Is6() || a.Is4In6() || a.Zone() != "" {
			return false
		}
	}
	return true
}

func prefixesOK(ps []netip.Prefix) bool {
	if len(ps) > maxNDItems {
		return false
	}
	for _, p := range ps {
		if !p.IsValid() || !ipv6Only(p.Addr()) {
			return false
		}
	}
	return true
}

type neighborBody struct {
	MAC string     `json:"mac"`
	IP  netip.Addr `json:"ip"`
}

type arpReqBody struct {
	MAC    string     `json:"mac"`
	Target netip.Addr `json:"target"`
}

type leaseBody struct {
	MAC      string     `json:"mac"`
	IP       netip.Addr `json:"ip"`
	Hostname string     `json:"hostname,omitempty"`
	Expiry   time.Time  `json:"expiry"`
	Released bool       `json:"released,omitempty"`
}

type learnedBody struct {
	Group   string `json:"group"`
	Domain  string `json:"domain"`
	Blocked bool   `json:"blocked,omitempty"`
}

type probeBody struct {
	IP netip.Addr `json:"ip"`
}

type probeReply struct {
	MAC string `json:"mac,omitempty"` // いなければ空
}

// parseMAC は Ethernet の MAC アドレスを検証し、決まった書き方にする。
func parseMAC(s string) (net.HardwareAddr, error) {
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return nil, fmt.Errorf("privsep: MAC アドレス %q が不正です", s)
	}
	return hw, nil
}

// LANLink は CONTROLLER の側の、LAN 側の処理とのつながり。controller.LAN の在席の確認と、
// 端末のグループの受け渡し（controller.Egress の一部）を、LAN 側の処理への要求で満たす。
//
// 知らせは検証してから内部の列に入れ、別のゴルーチンで LANObserver に渡す。読み込みのゴルーチンで処理すると、
// 処理の中で LAN 側の処理に頼む要求の応答を読めず、止まってしまうため。列があふれたら知らせを捨てる。
type LANLink struct {
	p   *peer
	rwc io.Closer
	log *slog.Logger

	queue   chan func(LANObserver)
	dropped atomic.Int64
	obs     atomic.Pointer[LANObserver]
	ready   chan struct{}
	once    sync.Once
}

// ConnectLAN は LAN 側の処理とのつながりを始める。知らせは SetObserver を呼ぶまで渡さない。
func ConnectLAN(rwc io.ReadWriteCloser, log *slog.Logger) *LANLink {
	l := &LANLink{rwc: rwc, log: log, queue: make(chan func(LANObserver), maxLANQueue), ready: make(chan struct{})}
	l.p = newPeer(newConn(rwc), rwc, handlers{notice: l.notice}, log, ErrLANStopped)
	go func() {
		if err := l.p.run(context.Background()); err != nil && !errors.Is(err, io.EOF) {
			log.Error("LAN 側の処理から不正なデータが届きました。つながりを切りました", "エラー", err)
		}
	}()
	go l.process()
	return l
}

// SetObserver は知らせの渡し先を決め、たまっていた知らせを渡し始める。
func (l *LANLink) SetObserver(obs LANObserver) {
	l.obs.Store(&obs)
	l.once.Do(func() { close(l.ready) })
}

// Done はつながりが切れたら閉じるチャネルを返す。
func (l *LANLink) Done() <-chan struct{} { return l.p.done }

// Close はつながりを切る。
func (l *LANLink) Close() error { return l.rwc.Close() }

func (l *LANLink) process() {
	select {
	case <-l.ready:
	case <-l.p.done:
		return
	}
	obs := *l.obs.Load()
	last := time.Now()
	for {
		select {
		case f := <-l.queue:
			f(obs)
		case <-l.p.done:
			return
		}
		if n := l.dropped.Load(); n > 0 && time.Since(last) > dropReportGap {
			l.dropped.Add(-n)
			last = time.Now()
			l.log.Warn("LAN 側の処理からの知らせが多すぎるため、一部を捨てました", "件数", n)
		}
	}
}

func (l *LANLink) enqueue(f func(LANObserver)) {
	select {
	case l.queue <- f:
	default:
		l.dropped.Add(1)
	}
}

// notice は LAN 側の処理からの知らせを検証して列に入れる。形が不正なら、つながりを切る。
func (l *LANLink) notice(typ string, body json.RawMessage) error {
	switch typ {
	case noticeNeighbor:
		var b neighborBody
		if err := decodeBody(body, &b); err != nil {
			return err
		}
		hw, err := parseMAC(b.MAC)
		if err != nil {
			return err
		}
		l.enqueue(func(o LANObserver) { o.ObserveNeighbor(hw, b.IP) })
	case noticeARPReq:
		var b arpReqBody
		if err := decodeBody(body, &b); err != nil {
			return err
		}
		hw, err := parseMAC(b.MAC)
		if err != nil {
			return err
		}
		if !b.Target.Is4() {
			return fmt.Errorf("privsep: ARP で探したアドレス %s が IPv4 ではありません", b.Target)
		}
		l.enqueue(func(o LANObserver) { o.ObserveARPRequest(hw, b.Target) })
	case noticeLease:
		var b leaseBody
		if err := decodeBody(body, &b); err != nil {
			return err
		}
		hw, err := parseMAC(b.MAC)
		if err != nil {
			return err
		}
		if len(b.Hostname) > maxHostname {
			return fmt.Errorf("privsep: ホスト名が長すぎます（%d バイト）", len(b.Hostname))
		}
		l.enqueue(func(o LANObserver) { o.ObserveLease(hw.String(), b.IP, b.Hostname, b.Expiry, b.Released) })
	case noticeDNS:
		var r controller.DNSRecord
		if err := decodeBody(body, &r); err != nil {
			return err
		}
		l.enqueue(func(o LANObserver) { o.RecordDNS(r) })
	case noticeFlow:
		var r controller.FlowRecord
		if err := decodeBody(body, &r); err != nil {
			return err
		}
		l.enqueue(func(o LANObserver) { o.RecordFlow(r) })
	case noticeLearned:
		var b learnedBody
		if err := decodeBody(body, &b); err != nil {
			return err
		}
		l.enqueue(func(o LANObserver) { o.RecordLearned(b.Group, b.Domain, b.Blocked) })
	case noticeND:
		var b ndBody
		if err := decodeBody(body, &b); err != nil {
			return err
		}
		hw, err := parseMAC(b.MAC)
		if err != nil {
			return err
		}
		targets := []netip.Addr{b.Src}
		if b.Target.IsValid() {
			targets = append(targets, b.Target)
		}
		if b.Type < 133 || b.Type > 136 || !ipv6Only(targets...) || !ipv6Only(b.RDNSS...) || !prefixesOK(b.Prefixes) ||
			b.RouterLifetime < 0 || b.RouterLifetime > 65535 {
			return fmt.Errorf("privsep: 近隣探索の知らせが不正です")
		}
		obs := controller.NDObservation{Frame: hw, Type: b.Type, Src: b.Src, Target: b.Target, Override: b.Override,
			RouterLifetime: b.RouterLifetime, Prefixes: b.Prefixes, RDNSS: b.RDNSS}
		l.enqueue(func(o LANObserver) { o.ObserveND(obs) })
	case noticeDHCPv6:
		var b dhcp6Body
		if err := decodeBody(body, &b); err != nil {
			return err
		}
		hw, err := parseMAC(b.MAC)
		if err != nil {
			return err
		}
		if !ipv6Only(b.Src) || !ipv6Only(b.DNS...) || !ipv6Only(b.Address...) {
			return fmt.Errorf("privsep: DHCPv6 の知らせが不正です")
		}
		obs := controller.DHCPv6Observation{Frame: hw, Src: b.Src, DNS: b.DNS, Address: b.Address}
		l.enqueue(func(o LANObserver) { o.ObserveDHCPv6(obs) })
	default:
		return fmt.Errorf("privsep: 知らない知らせ %q です", typ)
	}
	return nil
}

// Probe は ip のアドレスを持つ機器が LAN にいるかを、LAN 側の処理に確かめさせる。
func (l *LANLink) Probe(ctx context.Context, ip netip.Addr) (net.HardwareAddr, bool) {
	var r probeReply
	if err := l.p.call(ctx, reqProbe, probeBody{IP: ip}, &r); err != nil || r.MAC == "" {
		return nil, false
	}
	hw, err := parseMAC(r.MAC)
	if err != nil {
		return nil, false
	}
	return hw, true
}

// WithdrawRA は、不正なルーターの広告を取り消す RA を送るよう、LAN 側の処理に頼む。
func (l *LANLink) WithdrawRA(ctx context.Context, src netip.Addr, mac net.HardwareAddr, prefixes []netip.Prefix, rdnss []netip.Addr) error {
	return l.p.call(ctx, reqWithdrawRA, withdrawBody{Src: src, MAC: mac.String(), Prefixes: prefixes, RDNSS: rdnss}, nil)
}

// SetMembership は端末のグループと隔離の状態を LAN 側の処理に渡す。
func (l *LANLink) SetMembership(ctx context.Context, m egress.Membership) error {
	return l.p.call(ctx, reqMembership, m, nil)
}

// ControllerLink は LAN 側の処理の側の、CONTROLLER とのつながり。知らせを送って LANObserver を満たし、
// CONTROLLER の要求には Serve で渡した LANServices で応える。
type ControllerLink struct {
	p     *peer
	rwc   io.Closer
	log   *slog.Logger
	svc   atomic.Pointer[LANServices]
	ready chan struct{}
	once  sync.Once
}

var _ LANObserver = (*ControllerLink)(nil)

// ConnectController は CONTROLLER とのつながりを始める。要求には Serve を呼ぶまで応えない（待たせる）。
func ConnectController(rwc io.ReadWriteCloser, log *slog.Logger) *ControllerLink {
	l := &ControllerLink{rwc: rwc, log: log, ready: make(chan struct{})}
	l.p = newPeer(newConn(rwc), rwc, handlers{
		request:    l.request,
		concurrent: func(typ string) bool { return typ == reqProbe }, // 確かめるのに時間がかかるので並行して応える
	}, log, ErrLANStopped)
	go func() {
		if err := l.p.run(context.Background()); err != nil && !errors.Is(err, io.EOF) {
			log.Error("CONTROLLER から不正なデータが届きました。つながりを切りました", "エラー", err)
		}
	}()
	return l
}

// Serve は CONTROLLER の要求に svc で応え始める。
func (l *ControllerLink) Serve(svc LANServices) {
	l.svc.Store(&svc)
	l.once.Do(func() { close(l.ready) })
}

// Done はつながりが切れたら閉じるチャネルを返す。
func (l *ControllerLink) Done() <-chan struct{} { return l.p.done }

// Close はつながりを切る。
func (l *ControllerLink) Close() error { return l.rwc.Close() }

func (l *ControllerLink) request(ctx context.Context, typ string, body json.RawMessage) (any, error) {
	select {
	case <-l.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	svc := *l.svc.Load()
	switch typ {
	case reqProbe:
		var b probeBody
		if err := decodeBody(body, &b); err != nil {
			return nil, err
		}
		hw, ok := svc.Probe(ctx, b.IP)
		if !ok {
			return probeReply{}, nil
		}
		return probeReply{MAC: hw.String()}, nil
	case reqMembership:
		var m egress.Membership
		if err := decodeBody(body, &m); err != nil {
			return nil, err
		}
		return nil, svc.SetMembership(ctx, m)
	case reqWithdrawRA:
		var b withdrawBody
		if err := decodeBody(body, &b); err != nil {
			return nil, err
		}
		hw, err := parseMAC(b.MAC)
		if err != nil {
			return nil, err
		}
		if !b.Src.IsLinkLocalUnicast() || !ipv6Only(b.Src) || !ipv6Only(b.RDNSS...) || !prefixesOK(b.Prefixes) {
			return nil, errors.New("privsep: 取り消す広告の内容が不正です")
		}
		return nil, svc.WithdrawRA(ctx, b.Src, hw, b.Prefixes, b.RDNSS)
	}
	return nil, fmt.Errorf("知らない要求 %q です", typ)
}

func (l *ControllerLink) send(typ string, body any) {
	if err := l.p.notify(typ, body); err != nil {
		select {
		case <-l.p.done: // つながりが切れた後は捨てる（プロセスは止まる）
		default:
			l.log.Warn("CONTROLLER に知らせを送れません", "種類", typ, "エラー", err)
		}
	}
}

func (l *ControllerLink) ObserveNeighbor(frame net.HardwareAddr, senderIP netip.Addr) {
	l.send(noticeNeighbor, neighborBody{MAC: frame.String(), IP: senderIP})
}

func (l *ControllerLink) ObserveARPRequest(frame net.HardwareAddr, target netip.Addr) {
	l.send(noticeARPReq, arpReqBody{MAC: frame.String(), Target: target})
}

func (l *ControllerLink) ObserveLease(mac string, ip netip.Addr, hostname string, expiry time.Time, released bool) {
	l.send(noticeLease, leaseBody{MAC: mac, IP: ip, Hostname: hostname, Expiry: expiry, Released: released})
}

func (l *ControllerLink) RecordDNS(r controller.DNSRecord)   { l.send(noticeDNS, r) }
func (l *ControllerLink) RecordFlow(r controller.FlowRecord) { l.send(noticeFlow, r) }

func (l *ControllerLink) RecordLearned(group, domain string, blocked bool) {
	l.send(noticeLearned, learnedBody{Group: group, Domain: domain, Blocked: blocked})
}

func (l *ControllerLink) ObserveND(o controller.NDObservation) {
	l.send(noticeND, ndBody{MAC: o.Frame.String(), Type: o.Type, Src: o.Src, Target: o.Target, Override: o.Override,
		RouterLifetime: o.RouterLifetime, Prefixes: o.Prefixes, RDNSS: o.RDNSS})
}

func (l *ControllerLink) ObserveDHCPv6(o controller.DHCPv6Observation) {
	l.send(noticeDHCPv6, dhcp6Body{MAC: o.Frame.String(), Src: o.Src, DNS: o.DNS, Address: o.Address})
}
