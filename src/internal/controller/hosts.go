package controller

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"susanoo/internal/event"
	"susanoo/internal/policy"
)

// spoofInterval の間は、同じ機器のなりすましを 1 回だけ検知結果にする。
const spoofInterval = time.Minute

// ObserveLease は DHCP の割り当てと解放を台帳に反映する（DHCP サーバーから呼ぶ）。
func (c *Controller) ObserveLease(mac string, ip netip.Addr, hostname string, expiry time.Time, released bool) {
	now := c.now()
	c.mu.Lock()
	h, isNew := c.hostLocked(mac, now)
	h.LastSeen = now
	if hostname != "" {
		h.Hostname = hostname
	}
	if released {
		h.Lease = time.Time{}
	} else {
		h.Lease = expiry
		c.setHostIPLocked(h, ip)
	}
	c.backLocked(h, now)
	c.saveLocked()
	snapshot := *h
	c.mu.Unlock()

	activity := event.DHCPAssign
	if released {
		activity = event.DHCPRelease
	}
	e := event.New(event.ClassDHCPActivity, activity, event.SeverityInformational, now)
	e.DstEndpoint = &event.Endpoint{IP: ip.String(), MAC: mac, Hostname: hostname, UID: snapshot.DeviceID}
	c.observe(e, subject{mac: mac})
	if isNew {
		c.recordNewHost(snapshot)
	}
}

// ObserveNeighbor は LAN で観測した ARP（フレームの送信元 frame と、名乗ったアドレス senderIP）を台帳に反映し、
// なりすましを検知する（GW の LAN の監視から呼ぶ）。
func (c *Controller) ObserveNeighbor(frame net.HardwareAddr, senderIP netip.Addr) {
	lan := c.cfg.LAN
	if lan == nil || len(frame) != 6 || bytes.Equal(frame, lan.MAC()) {
		return
	}
	mac := frame.String()
	now := c.now()
	var reason, typ string

	c.mu.Lock()
	h, isNew := c.hostLocked(mac, now)
	h.LastSeen = now
	c.dirty = true
	if senderIP.Is4() && !senderIP.IsUnspecified() && lan.Prefix().Contains(senderIP) {
		owner := c.leaseOwnerLocked(senderIP, now)
		switch {
		case senderIP == lan.Addr():
			reason, typ = ReasonGatewaySpoofing, event.FindingTypeGatewaySpoofing
		case owner != "" && owner != mac:
			reason, typ = ReasonIPSpoofing, event.FindingTypeIPSpoofing
		default:
			c.setHostIPLocked(h, senderIP)
		}
	}
	if reason != "" {
		if now.Sub(h.spoofAt) < spoofInterval {
			reason = ""
		} else {
			h.spoofAt = now
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
	if reason == "" {
		return
	}
	msg := fmt.Sprintf("機器 %s が、アドレス %s を名乗っています（%s）", mac, senderIP, reason)
	sev := event.SeverityHigh
	if typ == event.FindingTypeGatewaySpoofing {
		sev = event.SeverityCritical
	}
	e := c.finding(typ, reason, msg, sev, &event.Device{UID: snapshot.DeviceID, MAC: mac, IP: senderIP.String(), Hostname: snapshot.Hostname})
	c.log.Warn("なりすましを検知しました", "MAC", mac, "名乗ったアドレス", senderIP, "種類", reason)
	c.observe(e, subject{mac: mac})
}

// hostLocked は機器を台帳から返す。なければ載せる。
func (c *Controller) hostLocked(mac string, now time.Time) (*host, bool) {
	if h := c.hosts[mac]; h != nil {
		return h, false
	}
	h := &host{MAC: mac, FirstSeen: now, LastSeen: now}
	c.hosts[mac] = h
	return h, true
}

// recordNewHost は初めて見た機器を検知結果にする（G8 の未登録の機器の検知）。
func (c *Controller) recordNewHost(h host) {
	ip := "-"
	if h.IP.IsValid() {
		ip = h.IP.String()
	}
	msg := fmt.Sprintf("新しい機器を検知しました（MAC %s、アドレス %s、ホスト名 %s）", h.MAC, ip, dash(h.Hostname))
	dev := &event.Device{MAC: h.MAC, Hostname: h.Hostname}
	if h.IP.IsValid() {
		dev.IP = h.IP.String()
	}
	c.observe(c.finding(event.FindingTypeNewDevice, "新しい機器", msg, event.SeverityLow, dev), subject{mac: h.MAC})
	c.log.Info("新しい機器を検知しました", "MAC", h.MAC, "アドレス", ip, "ホスト名", h.Hostname)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// setHostIPLocked は機器のアドレスを更新する。隔離中なら、GW の遮断を新しいアドレスに移す。
func (c *Controller) setHostIPLocked(h *host, ip netip.Addr) {
	if !ip.IsValid() || ip == h.IP {
		return
	}
	h.IP = ip
	c.dirty = true
	if h.Isolation != "" || (h.DeviceID != "" && c.devices[h.DeviceID] != nil && c.devices[h.DeviceID].Isolation != "") {
		c.saveLocked()
		c.syncLocked()
		return
	}
	c.refreshMembershipLocked()
}

// backLocked は、不在の端末に結び付いた機器が LAN で見えたら、ハートビートの途絶の確認を再開する。
// CLIENT が接続し直す時間を見込み、判定までの時間を 2 倍にする。
func (c *Controller) backLocked(h *host, now time.Time) {
	if h.DeviceID == "" {
		return
	}
	d := c.devices[h.DeviceID]
	if d == nil || !d.Away {
		return
	}
	d.Away, d.Lost, d.LastSeen = false, false, now.Add(c.cfg.HeartbeatTimeout)
	c.saveLocked()
	c.log.Info("不在だった端末が LAN に戻りました。ハートビートの確認を再開します", "端末", d.ID)
}

// leaseOwnerLocked は ip を割り当て中の機器の MAC アドレスを返す。なければ空。
func (c *Controller) leaseOwnerLocked(ip netip.Addr, now time.Time) string {
	for _, h := range c.hosts {
		if h.IP == ip && h.Lease.After(now) {
			return h.MAC
		}
	}
	return ""
}

// linkLocked は、端末の通信の送信元アドレス addr を使っている機器を探し、端末と結び付ける。
func (c *Controller) linkLocked(d *device, addr netip.Addr) {
	if !addr.IsValid() {
		return
	}
	var found *host
	for _, h := range c.hosts {
		if h.IP == addr && (found == nil || h.LastSeen.After(found.LastSeen)) {
			found = h
		}
	}
	if found == nil || found.DeviceID == d.ID {
		return
	}
	if found.DeviceID != "" {
		c.log.Warn("機器の結び付きを別の端末に移します", "MAC", found.MAC, "旧", found.DeviceID, "新", d.ID)
	}
	found.DeviceID = d.ID
	c.saveLocked()
	c.log.Info("端末と機器を結び付けました", "端末", d.ID, "MAC", found.MAC)
	if d.Isolation != "" {
		c.syncLocked()
		return
	}
	c.refreshMembershipLocked()
}

// linkedMACsLocked は端末に結び付いた機器の MAC アドレスを返す。
func (c *Controller) linkedMACsLocked(id string) []string {
	var macs []string
	for _, h := range c.hosts {
		if h.DeviceID == id {
			macs = append(macs, h.MAC)
		}
	}
	slices.Sort(macs)
	return macs
}

// triggerHost は機器への隔離が必要な検知に対応する。端末に結び付いた機器なら、端末を隔離する。
func (c *Controller) triggerHost(mac, reason string) {
	c.mu.Lock()
	h := c.hosts[mac]
	if h == nil {
		c.mu.Unlock()
		return
	}
	if h.DeviceID != "" && c.devices[h.DeviceID] != nil {
		id := h.DeviceID
		c.mu.Unlock()
		c.trigger(id, reason)
		return
	}
	defer c.mu.Unlock()
	if h.Isolation != "" {
		return
	}
	switch dec, level := c.decideLocked(c.hostGroupLocked(h), c.hostCanaryLocked(h), mac, reason); dec {
	case decidePending:
		if h.Pending == "" {
			h.Pending = reason
			c.saveLocked()
			c.auditLocked(actorSystem, ActionHostIsolatePending, mac, h.IP, map[string]any{"reason": reason})
			c.log.Warn("機器の隔離の承認を待っています", "MAC", mac, "理由", reason)
		}
	case decideIsolate:
		c.isolateHostLocked(h, level, reason, actorSystem)
	}
}

func (c *Controller) isolateHostLocked(h *host, level policy.IsolationLevel, reason, actor string) {
	h.Isolation, h.Reason, h.Since, h.Pending = level, reason, c.now(), ""
	c.saveLocked()
	c.auditLocked(actor, ActionHostIsolate, h.MAC, h.IP, map[string]any{"level": level, "reason": reason})
	c.log.Warn("機器を隔離しました", "MAC", h.MAC, "段階", level, "理由", reason, "操作", actor)
	c.syncLocked()
}

func (c *Controller) releaseHostLocked(h *host, actor string) {
	prev := h.Isolation
	h.Isolation, h.Reason, h.Since, h.Pending = "", "", time.Time{}, ""
	c.resetRiskLocked("host:" + h.MAC)
	c.saveLocked()
	c.auditLocked(actor, ActionHostRelease, h.MAC, h.IP, map[string]any{"previous": prev})
	c.log.Info("機器の隔離を解除しました", "MAC", h.MAC, "操作", actor)
	c.syncLocked()
}
