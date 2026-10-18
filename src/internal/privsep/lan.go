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
	noticeNeighbor = "neighbor" // ARP で見えた機器
	noticeARPReq   = "arp_req"  // ARP で LAN のアドレスを探した（LAN 内のスキャンの検知に使う）
	noticeLease    = "lease"    // DHCP の貸し出しと返却
	noticeDNS      = "dns"      // DNS の問い合わせの記録
	noticeFlow     = "flow"     // 通信の記録
	noticeLearned  = "learned"  // 学習モードで通した名前と、遮断した名前
	reqProbe       = "probe"    // 機器が LAN にいるかの確認
	// 端末のグループと隔離の状態は reqMembership（gw.go）で頼む。
)

const (
	maxHostname   = 255  // DHCP のホスト名の上限（オプション 12 の長さ）
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
}

// LANServices は、LAN 側の処理が CONTROLLER の要求に応える働き。
type LANServices interface {
	Probe(ctx context.Context, ip netip.Addr) (net.HardwareAddr, bool)
	SetMembership(ctx context.Context, m egress.Membership) error
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
