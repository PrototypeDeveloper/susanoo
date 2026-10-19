package controller

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"susanoo/internal/event"
	"susanoo/internal/policy"
)

// IPv6 の LAN の監視（G8）。
//
// GW の LAN 側の処理が観測した近隣探索（ND）と、GW の問い合わせに答えた DHCPv6 のメッセージを受け取る。
//   - 機器の IPv6 アドレス：NS、RS、RA の送信元と、NA の対象のアドレスを、その機器のアドレスとして台帳に載せる
//   - なりすまし：GW の IPv6 アドレスを名乗るもの（ゲートウェイのなりすまし）と、ほかの機器が最近使っていたアドレスを
//     名乗るもの（アドレスのなりすまし）を検知結果にする
//   - 不正なルーター：ルーター方式では GW が LAN のルーターなので、LAN の機器のルーター広告（RA）は、端末の IPv6 の通信を
//     横取りする攻撃の疑いがある（IPv4 だけの LAN でも、端末は既定で RA に従う）。隔離したら、GW がそのルーターを名乗って
//     広告を取り消す RA を送り、端末の経路を元に戻す
//   - 不正な DHCPv6 のサーバー：GW は DHCPv6 のサーバーを動かさないので、GW の問い合わせに答えた LAN の機器は、
//     端末の DNS サーバーを差し替える攻撃（mitm6 など）の疑いがある

const (
	maxHostIPv6       = 8                // 機器ごとに覚える IPv6 アドレスの数
	ipv6OwnerWindow   = 10 * time.Minute // この間に使われたアドレスを、その機器のものとみなす
	raWithdrawGap     = 5 * time.Second  // 不正なルーターの広告を取り消す間隔の下限
	raWithdrawTimeout = 5 * time.Second
	ReasonRogueRouter = "不正なルーター広告"
	ReasonRogueDHCPv6 = "不正な DHCPv6 サーバー"
)

// NDObservation は LAN で観測した近隣探索。
type NDObservation struct {
	Frame          net.HardwareAddr // フレームの送信元
	Type           int              // ICMPv6 の種類（133〜136）
	Src, Target    netip.Addr
	Override       bool // NA の Override の印
	RouterLifetime int  // RA のルーターの寿命（秒）
	Prefixes       []netip.Prefix
	RDNSS          []netip.Addr
}

// DHCPv6Observation は、GW の問い合わせに答えた DHCPv6 のサーバーのメッセージ。
type DHCPv6Observation struct {
	Frame   net.HardwareAddr
	Src     netip.Addr
	DNS     []netip.Addr // 知らせた DNS サーバー
	Address []netip.Addr // 割り当てようとしたアドレス
}

// LAN6 は、GW の LAN 側の IPv6 アドレスを返せる LAN（ゲートウェイのなりすましの検知に使う）。
type LAN6 interface {
	Addrs6() []netip.Addr
}

// RAWithdrawer は、不正なルーターの広告を取り消す RA を送れる LAN。
type RAWithdrawer interface {
	WithdrawRA(ctx context.Context, src netip.Addr, mac net.HardwareAddr, prefixes []netip.Prefix, rdnss []netip.Addr) error
}

// ip6Entry は機器が使った IPv6 アドレス。
type ip6Entry struct {
	Addr netip.Addr `json:"addr"`
	Seen time.Time  `json:"seen"`
}

// raInfo は不正なルーターが最後に送った広告（取り消しに使う。保存しない）。
type raInfo struct {
	src      netip.Addr
	prefixes []netip.Prefix
	rdnss    []netip.Addr
}

// addrs は機器のアドレス（IPv4 と、リンクローカルでない IPv6）を返す。グループと隔離の判断に使う。
func (h *host) addrs() []netip.Addr {
	var out []netip.Addr
	if h.IP.IsValid() {
		out = append(out, h.IP)
	}
	for _, e := range h.IPv6 {
		if !e.Addr.IsLinkLocalUnicast() {
			out = append(out, e.Addr)
		}
	}
	return out
}

// hasAddr は、機器が a を使っているか（IPv4 か、近隣探索で見えた IPv6）を返す。
func (h *host) hasAddr(a netip.Addr) bool {
	return h.IP == a || slices.ContainsFunc(h.IPv6, func(e ip6Entry) bool { return e.Addr == a })
}

// addIPv6Locked は機器の IPv6 アドレスを覚える。数が上限を超えたら、最も古いものを忘れる。
// 隔離中の機器や、既定でないグループの機器のアドレスが増えたら、GW の遮断と DNS の判断に反映する。
func (c *Controller) addIPv6Locked(h *host, a netip.Addr, now time.Time) {
	if i := slices.IndexFunc(h.IPv6, func(e ip6Entry) bool { return e.Addr == a }); i >= 0 {
		h.IPv6[i].Seen = now
		return
	}
	defer func() {
		if a.IsLinkLocalUnicast() {
			return
		}
		switch {
		case c.isolatedHostLocked(h):
			c.syncLocked()
		case c.effectiveGroupLocked(c.hostGroupLocked(h), c.hostCanaryLocked(h)) != policy.DefaultGroup:
			c.refreshMembershipLocked()
		}
	}()
	h.IPv6 = append(h.IPv6, ip6Entry{Addr: a, Seen: now})
	if len(h.IPv6) > maxHostIPv6 {
		oldest := 0
		for i, e := range h.IPv6 {
			if e.Seen.Before(h.IPv6[oldest].Seen) {
				oldest = i
			}
		}
		h.IPv6 = slices.Delete(h.IPv6, oldest, oldest+1)
	}
	c.saveLocked() // アドレスが増えたときだけ保存する（見えるたびには保存しない）
}

// owner6Locked は、ipv6OwnerWindow の間に a を使った機器の MAC アドレスを返す。なければ空。
func (c *Controller) owner6Locked(a netip.Addr, now time.Time) string {
	var owner string
	var seen time.Time
	for _, h := range c.hosts {
		for _, e := range h.IPv6 {
			if e.Addr == a && now.Sub(e.Seen) < ipv6OwnerWindow && e.Seen.After(seen) {
				owner, seen = h.MAC, e.Seen
			}
		}
	}
	return owner
}

// trustedRouter は、mac が LAN のルーターとして認めた機器かを返す。
func (c *Controller) trustedRouter(mac string) bool {
	return slices.ContainsFunc(c.cfg.TrustedRouters, func(m string) bool { return strings.EqualFold(m, mac) })
}

// isolatedHostLocked は、機器か、機器に結び付いた端末が隔離中かを返す。
func (c *Controller) isolatedHostLocked(h *host) bool {
	if h.Isolation != "" {
		return true
	}
	d := c.devices[h.DeviceID]
	return d != nil && d.Isolation != ""
}

// ObserveND は LAN で観測した近隣探索を台帳に反映し、なりすましと不正なルーターを検知する。
func (c *Controller) ObserveND(o NDObservation) {
	lan := c.cfg.LAN
	if lan == nil || len(o.Frame) != 6 || slices.Equal(o.Frame, lan.MAC()) {
		return // GW 自身が送ったもの（広告の取り消しを含む）は見ない
	}
	var gwAddrs []netip.Addr
	if l6, ok := lan.(LAN6); ok {
		gwAddrs = l6.Addrs6()
	}
	claimed := o.Src // 名乗ったアドレス：NS、RS、RA は送信元、NA は対象
	if o.Type == 136 {
		claimed = o.Target
	}
	if !claimed.Is6() || claimed.Is4In6() || claimed.IsUnspecified() || claimed.IsMulticast() {
		claimed = netip.Addr{}
	}
	mac := o.Frame.String()
	now := c.now()
	var spoofReason, spoofType string
	rogue := false

	c.mu.Lock()
	h, isNew := c.hostLocked(mac, now)
	h.LastSeen = now
	c.dirty = true
	switch {
	case claimed.IsValid() && slices.Contains(gwAddrs, claimed):
		spoofReason, spoofType = ReasonGatewaySpoofing, event.FindingTypeGatewaySpoofing
	case claimed.IsValid():
		if owner := c.owner6Locked(claimed, now); owner != "" && owner != mac {
			spoofReason, spoofType = ReasonIPSpoofing, event.FindingTypeIPSpoofing
		} else {
			c.addIPv6Locked(h, claimed, now)
		}
	}
	if spoofReason != "" {
		if now.Sub(h.spoofAt) < spoofInterval {
			spoofReason = ""
		} else {
			h.spoofAt = now
		}
	}
	if o.Type == 134 && !c.trustedRouter(mac) {
		h.ra = &raInfo{src: o.Src, prefixes: slices.Clone(o.Prefixes), rdnss: slices.Clone(o.RDNSS)}
		if now.Sub(h.raAt) >= spoofInterval {
			h.raAt, rogue = now, true
		}
	}
	c.backLocked(h, now)
	if isNew {
		c.saveLocked()
	}
	snapshot := *h
	c.mu.Unlock()

	if isNew {
		c.recordNewHost(snapshot)
	}
	dev := &event.Device{UID: snapshot.DeviceID, MAC: mac, Hostname: snapshot.Hostname}
	if spoofReason != "" {
		dev.IP = claimed.String()
		msg := fmt.Sprintf("機器 %s が、IPv6 アドレス %s を名乗っています（%s）", mac, claimed, spoofReason)
		sev := event.SeverityHigh
		if spoofType == event.FindingTypeGatewaySpoofing {
			sev = event.SeverityCritical
		}
		c.log.Warn("なりすましを検知しました", "MAC", mac, "名乗ったアドレス", claimed, "種類", spoofReason)
		c.observe(c.finding(spoofType, spoofReason, msg, sev, dev), subject{mac: mac})
	}
	if rogue {
		dev.IP = o.Src.String()
		msg := fmt.Sprintf("機器 %s（%s）がルーター広告を送りました（ルーターの寿命 %d 秒、ネットワーク %s、DNS サーバー %s）。"+
			"端末の IPv6 の通信を横取りしようとしている恐れがあります", mac, o.Src, o.RouterLifetime, joinPrefixes(o.Prefixes), joinAddrs(o.RDNSS))
		c.log.Warn("不正なルーター広告を検知しました", "MAC", mac, "送信元", o.Src, "ネットワーク", joinPrefixes(o.Prefixes))
		c.observe(c.finding(event.FindingTypeRogueRouter, ReasonRogueRouter, msg, event.SeverityCritical, dev), subject{mac: mac})
	}
	if o.Type == 134 && !c.trustedRouter(mac) {
		c.withdrawIfIsolated(mac, now)
	}
}

// withdrawIfIsolated は、不正なルーターの機器が隔離中なら、その広告を取り消す RA を GW から送る（raWithdrawGap に 1 回まで）。
func (c *Controller) withdrawIfIsolated(mac string, now time.Time) {
	w, ok := c.cfg.LAN.(RAWithdrawer)
	if !ok {
		return
	}
	c.mu.Lock()
	h := c.hosts[mac]
	if h == nil || h.ra == nil || !c.isolatedHostLocked(h) || now.Sub(h.withdrawAt) < raWithdrawGap {
		c.mu.Unlock()
		return
	}
	h.withdrawAt = now
	ra := *h.ra
	c.mu.Unlock()
	hw, _ := net.ParseMAC(mac)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), raWithdrawTimeout)
		defer cancel()
		if err := w.WithdrawRA(ctx, ra.src, hw, ra.prefixes, ra.rdnss); err != nil {
			c.log.Error("不正なルーターの広告を取り消せません", "MAC", mac, "エラー", err)
			return
		}
		c.log.Info("隔離した不正なルーターの広告を取り消しました", "MAC", mac, "送信元", ra.src)
	}()
}

// ObserveDHCPv6 は、GW の問い合わせに答えた DHCPv6 のサーバーを検知する。
func (c *Controller) ObserveDHCPv6(o DHCPv6Observation) {
	lan := c.cfg.LAN
	if lan == nil || len(o.Frame) != 6 || slices.Equal(o.Frame, lan.MAC()) {
		return
	}
	mac := o.Frame.String()
	if c.trustedRouter(mac) {
		return
	}
	now := c.now()
	c.mu.Lock()
	h, isNew := c.hostLocked(mac, now)
	h.LastSeen = now
	c.dirty = true
	if o.Src.IsLinkLocalUnicast() && c.owner6Locked(o.Src, now) == "" {
		c.addIPv6Locked(h, o.Src, now)
	}
	report := now.Sub(h.dhcp6At) >= spoofInterval
	if report {
		h.dhcp6At = now
	}
	if isNew {
		c.saveLocked()
	}
	snapshot := *h
	c.mu.Unlock()
	if isNew {
		c.recordNewHost(snapshot)
	}
	if !report {
		return
	}
	msg := fmt.Sprintf("機器 %s（%s）が DHCPv6 のサーバーとして答えました（DNS サーバー %s、割り当てようとしたアドレス %s）。"+
		"端末の DNS サーバーを差し替える攻撃の恐れがあります", mac, o.Src, joinAddrs(o.DNS), joinAddrs(o.Address))
	c.log.Warn("不正な DHCPv6 サーバーを検知しました", "MAC", mac, "送信元", o.Src, "DNS サーバー", joinAddrs(o.DNS))
	dev := &event.Device{UID: snapshot.DeviceID, MAC: mac, IP: o.Src.String(), Hostname: snapshot.Hostname}
	c.observe(c.finding(event.FindingTypeRogueDHCPv6, ReasonRogueDHCPv6, msg, event.SeverityCritical, dev), subject{mac: mac})
}

func joinPrefixes(ps []netip.Prefix) string {
	if len(ps) == 0 {
		return "なし"
	}
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, "、")
}

func joinAddrs(as []netip.Addr) string {
	if len(as) == 0 {
		return "なし"
	}
	s := make([]string, len(as))
	for i, a := range as {
		s[i] = a.String()
	}
	return strings.Join(s, "、")
}
