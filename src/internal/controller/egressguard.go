package controller

import (
	"cmp"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/egress"
	"susanoo/internal/event"
	"susanoo/internal/policy"
)

// GW の検知の強化（2m-2）。
//
//   - 許可していない名前への接続：許可リストのグループの機器が、許可した名前のアドレス経由で、許可していない名前（TLS の SNI か
//     HTTP の Host）に接続したら検知結果にする（CDN などで複数のサイトがアドレスを共有していると、DNS による制御を抜けられる）
//   - 直接指定したアドレスの学習：学習モードのグループで、DNS で引いていないアドレスへの通信を、学習の記録に載せる
//   - 許可への異常な追加：執行部が断ったアドレス（特別な用途、LAN、私的なアドレス、短い間の大量の追加）を検知結果にする
//   - LAN 側の処理の知らせの食い違い：執行部が許可に加えたアドレスが DNS の応答の記録にないとき、LAN の外のアドレスからの
//     DHCP の貸し出し、通信、DNS の問い合わせが届いたときに検知結果にする（LAN 側の処理の乗っ取りの疑い）

const (
	dnsAnswerWindow  = 6 * time.Hour // DNS で引いたアドレスを、引いたものとみなす期間
	maxDNSAnswers    = 100000
	learnCheckDelay  = 10 * time.Second // 許可に加えたアドレスを、DNS の応答の記録と突き合わせるまでの待ち（届く順が前後するため）
	maxPendingLearns = 10000
	sniRealert       = time.Hour        // 同じ機器、同じ名前の、許可していない名前への接続を続けて検知結果にしない時間
	guardRealert     = 10 * time.Minute // 許可への異常な追加と、知らせの食い違いを、同じ種類で続けて検知結果にしない時間
	maxSNIAlerts     = 10000
)

// answerKey はグループの中で DNS で引いたアドレス。
type answerKey struct {
	group string
	ip    netip.Addr
}

// egressGuard は GW の検知の強化の状態（台帳とは別のロックで守る）。
type egressGuard struct {
	mu      sync.Mutex
	answers map[answerKey]time.Time // DNS で引いたアドレスと、引いた時刻
	pending []egress.LearnReport    // DNS の応答の記録と突き合わせを待つ、許可に加えたアドレス
	sni     map[string]time.Time    // 許可していない名前への接続を検知結果にした時刻
	alerted map[string]time.Time    // 許可への異常な追加と知らせの食い違いを検知結果にした時刻
}

// rememberAnswers は、グループ group の DNS の応答のアドレスを覚える。
func (c *Controller) rememberAnswers(group string, answers []string, now time.Time) {
	g := &c.egw
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.answers == nil {
		g.answers = map[answerKey]time.Time{}
	}
	for _, a := range answers {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			continue // CNAME など
		}
		if len(g.answers) >= maxDNSAnswers {
			for k, t := range g.answers {
				if now.Sub(t) > dnsAnswerWindow {
					delete(g.answers, k)
				}
			}
			if len(g.answers) >= maxDNSAnswers {
				return
			}
		}
		g.answers[answerKey{group, ip.Unmap()}] = now
	}
}

// answered は、グループ group で ip を DNS で引いていたかを返す。
func (c *Controller) answered(group string, ip netip.Addr, now time.Time) bool {
	c.egw.mu.Lock()
	defer c.egw.mu.Unlock()
	t, ok := c.egw.answers[answerKey{group, ip.Unmap()}]
	return ok && now.Sub(t) <= dnsAnswerWindow
}

// guardAlert は、key の検知結果を guardRealert の間にもう出していれば false を返す。
func (c *Controller) guardAlert(key string, now time.Time) bool {
	g := &c.egw
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.alerted == nil {
		g.alerted = map[string]time.Time{}
	}
	if t, ok := g.alerted[key]; ok && now.Sub(t) < guardRealert {
		return false
	}
	g.alerted[key] = now
	return true
}

// ObserveLearn は、執行部が DNS で得たアドレスを許可に加えた結果を受け取る。断ったアドレスは検知結果にし、加えたアドレスは
// 後で DNS の応答の記録と突き合わせる。
func (c *Controller) ObserveLearn(r egress.LearnReport) {
	now := c.now()
	if len(r.Refused) > 0 {
		c.reportRefused(r, now)
	}
	if !c.cfg.VerifyLearned || r.Updates || len(r.Added) == 0 {
		return
	}
	r.Time = now // 突き合わせの待ちは CONTROLLER の時計で数える
	c.egw.mu.Lock()
	if len(c.egw.pending) < maxPendingLearns {
		c.egw.pending = append(c.egw.pending, r)
	}
	c.egw.mu.Unlock()
}

// reportRefused は、執行部が許可に加えなかったアドレスを検知結果にする。
func (c *Controller) reportRefused(r egress.LearnReport, now time.Time) {
	byReason := map[string][]string{}
	for _, a := range r.Refused {
		byReason[a.Reason] = append(byReason[a.Reason], a.Addr.String())
	}
	group := cmp.Or(r.Group, "（隔離中の更新サーバー）")
	for _, reason := range slices.Sorted(func(yield func(string) bool) {
		for k := range byReason {
			if !yield(k) {
				return
			}
		}
	}) {
		addrs := byReason[reason]
		if !c.guardAlert("refused\x00"+r.Group+"\x00"+reason, now) {
			continue
		}
		shown := addrs[:min(len(addrs), 10)]
		msg := fmt.Sprintf("グループ %s の DNS の応答のアドレス %s を、許可に加えませんでした（%s）。許可した名前の DNS の応答が改ざんされているか"+
			"（DNS リバインディング）、GW の LAN 側の処理が乗っ取られている恐れがあります", group, strings.Join(shown, "、"), reason)
		c.log.Warn("DNS で得たアドレスを許可に加えませんでした", "グループ", group, "理由", reason, "アドレス", shown)
		e := c.finding(event.FindingTypeLearnAnomaly, "許可への異常な追加", msg, event.SeverityMedium, nil)
		e.Unmapped = map[string]any{"learn": map[string]any{"group": r.Group, "reason": reason, "addresses": shown}}
		c.observe(e, subject{})
	}
}

// checkLearnReports は、許可に加えてから learnCheckDelay たったアドレスを、DNS の応答の記録と突き合わせる。
func (c *Controller) checkLearnReports() {
	now := c.now()
	c.egw.mu.Lock()
	var due []egress.LearnReport
	keep := c.egw.pending[:0]
	for _, r := range c.egw.pending {
		if now.Sub(r.Time) >= learnCheckDelay {
			due = append(due, r)
		} else {
			keep = append(keep, r)
		}
	}
	c.egw.pending = keep
	c.egw.mu.Unlock()
	for _, r := range due {
		var missing []string
		for _, ip := range r.Added {
			if !c.answered(r.Group, ip, now) {
				missing = append(missing, ip.String())
			}
		}
		if len(missing) == 0 {
			continue
		}
		shown := missing[:min(len(missing), 10)]
		c.reportMismatch("learn\x00"+r.Group, fmt.Sprintf("グループ %s の許可に、DNS の応答の記録にないアドレス %s が加えられました", r.Group, strings.Join(shown, "、")),
			map[string]any{"kind": "learn", "group": r.Group, "addresses": shown}, now)
	}
}

// reportMismatch は LAN 側の処理の知らせの食い違いを検知結果にする。
func (c *Controller) reportMismatch(key, what string, detail map[string]any, now time.Time) {
	if !c.guardAlert("mismatch\x00"+key, now) {
		return
	}
	msg := what + "。GW の LAN 側の処理が乗っ取られ、偽の知らせを送っている恐れがあります"
	c.log.Warn("LAN 側の処理の知らせが食い違っています", "内容", what)
	e := c.finding(event.FindingTypeObservationMismatch, "LAN 側の処理の知らせの食い違い", msg, event.SeverityMedium, nil)
	e.Unmapped = map[string]any{"mismatch": detail}
	c.observe(e, subject{})
}

// outsideLAN は、LAN 側の処理が知らせた LAN の機器のアドレス ip が、LAN のネットワークの外かを返す（IPv4 だけを確かめる）。
func (c *Controller) outsideLAN(ip netip.Addr) bool {
	lan := c.cfg.LAN
	ip = ip.Unmap()
	return lan != nil && ip.Is4() && lan.Prefix().IsValid() && !lan.Prefix().Contains(ip)
}

// outsideMessages は、LAN の外のアドレスを LAN の機器として知らせたときの説明（%s はアドレス）。
var outsideMessages = map[string]string{
	"lease": "LAN の外のアドレス %s を DHCP で貸し出したという知らせが届きました",
	"flow":  "LAN の外のアドレス %s からの通信の記録が届きました",
	"dns":   "LAN の外のアドレス %s からの DNS の問い合わせの記録が届きました",
}

// checkOutsideLAN は、LAN 側の処理が LAN の外のアドレスを LAN の機器として知らせたら、食い違いとして検知結果にし、true を返す。
func (c *Controller) checkOutsideLAN(kind string, ip netip.Addr) bool {
	if !ip.IsValid() || !c.outsideLAN(ip) {
		return false
	}
	c.reportMismatch("outside\x00"+kind, fmt.Sprintf(outsideMessages[kind]+"（LAN は %s）", ip, c.cfg.LAN.Prefix()),
		map[string]any{"kind": kind, "address": ip.String()}, c.now())
	return true
}

// egressStateLocked は、検知の対象 t の外部通信の制御のグループ（ポリシーの設定と、制御での名前）と、隔離中かを返す。
func (c *Controller) egressStateLocked(t target) (*policy.Group, string, bool) {
	isolated := false
	if d := c.devices[t.device]; d != nil {
		isolated = d.Isolation != ""
	} else if h := c.hosts[t.mac]; h != nil {
		isolated = h.Isolation != ""
	}
	return c.groupLocked(t.group, t.canary), c.effectiveGroupLocked(t.group, t.canary), isolated
}

// allowsName は、グループの許可リストが名前 name を許可しているかを返す。
func allowsName(g *policy.Group, name string) bool {
	for _, d := range g.Egress.Allow {
		if d.MatchDomain(name) {
			return true
		}
	}
	return false
}

// allowsAddr は、グループの許可リストがアドレス ip を CIDR で許可しているかを返す。
func allowsAddr(g *policy.Group, ip netip.Addr) bool {
	for _, d := range g.Egress.Allow {
		if p, err := netip.ParsePrefix(d.CIDR); err == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}

// flowHostname は、通信の始まりの SNI か HTTP の Host を、許可リストと比べる形（小文字、ポートと末尾の「.」なし）にする。
// アドレスを直接書いた Host は空にする。
func flowHostname(r FlowRecord) string {
	h := cmp.Or(r.SNI, r.HTTPHost)
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if _, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return ""
	}
	return h
}

// checkEgressFlow は、通信の記録で、許可していない名前への接続を検知し、学習モードのグループの直接指定したアドレスを記録する。
func (c *Controller) checkEgressFlow(r FlowRecord, t target, s subject) {
	if r.Blocked {
		return
	}
	c.mu.Lock()
	g, name, isolated := c.egressStateLocked(t)
	c.mu.Unlock()
	if g == nil || isolated {
		return
	}
	now := c.now()
	dst := r.Dst.Addr().Unmap()
	switch g.Egress.Default {
	case policy.EgressDeny:
		host := flowHostname(r)
		if !r.Open || host == "" || allowsName(g, host) || allowsAddr(g, dst) {
			return
		}
		c.reportUnlistedName(r, host, name, t, s, now)
	case policy.EgressLearn:
		if r.Open || (r.Proto != 6 && r.Proto != 17) || r.Dst.Port() == 0 || allowsAddr(g, dst) || c.answered(name, dst, now) {
			return
		}
		c.recordDirect(name, dst, protoNames[r.Proto], int(r.Dst.Port()), now)
	}
}

// reportUnlistedName は、許可していない名前への接続を検知結果にする。
func (c *Controller) reportUnlistedName(r FlowRecord, host, group string, t target, s subject, now time.Time) {
	key := cmp.Or(t.key, s.ip.String()) + "\x00" + host
	c.egw.mu.Lock()
	if c.egw.sni == nil {
		c.egw.sni = map[string]time.Time{}
	}
	if at, ok := c.egw.sni[key]; ok && now.Sub(at) < sniRealert {
		c.egw.mu.Unlock()
		return
	}
	if len(c.egw.sni) >= maxSNIAlerts {
		for k, at := range c.egw.sni {
			if now.Sub(at) >= sniRealert {
				delete(c.egw.sni, k)
			}
		}
	}
	c.egw.sni[key] = now
	c.egw.mu.Unlock()
	kind := "TLS の SNI"
	if r.SNI == "" {
		kind = "HTTP の Host"
	}
	msg := fmt.Sprintf("許可リストのグループ %s の %s が、許可していない名前 %s（%s）に、アドレス %s 経由で接続しました。"+
		"CDN などでアドレスを共有するサイトを使った、許可リストの抜け道の疑いがあります", group, t.name(), host, kind, r.Dst)
	dev := &event.Device{UID: t.device, MAC: cmp.Or(t.mac, s.mac), IP: s.ip.String()}
	e := c.finding(event.FindingTypeUnlistedSNI, "許可していない名前への接続", msg, event.SeverityMedium, dev)
	e.DstEndpoint = &event.Endpoint{IP: r.Dst.Addr().String(), Port: int(r.Dst.Port()), Hostname: host}
	e.Unmapped = map[string]any{"egress": map[string]any{"group": group, "hostname": host, "source": kind}}
	c.observe(e, s)
}

// recordDirect は、学習モードのグループ group で、名前を引かずに直接指定したアドレスへの通信を学習の記録に載せる。
func (c *Controller) recordDirect(group string, ip netip.Addr, proto string, port int, now time.Time) {
	l := &c.learned
	l.mu.Lock()
	defer l.mu.Unlock()
	key := learnedKey{group: group, addr: ip.String(), proto: proto, port: port}
	e := l.entries[key]
	if e == nil {
		if len(l.entries) >= maxLearned {
			if !l.full {
				l.full = true
				c.log.Warn("学習の記録が上限に達しました。新しい名前とアドレスは記録しません", "上限", maxLearned)
			}
			return
		}
		e = &api.Learned{Group: group, Address: ip.String(), Port: port, Protocol: proto, First: now}
		l.entries[key] = e
	}
	e.Count++
	e.Last = now
	l.dirty = true
}

// learnedLabel は学習の記録の名前の欄（名前か、アドレスとポートとプロトコル）。
func learnedLabel(l api.Learned) string {
	if l.Address == "" {
		return l.Domain
	}
	return net.JoinHostPort(l.Address, strconv.Itoa(l.Port)) + "/" + l.Protocol
}
