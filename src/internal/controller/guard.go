package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
)

// 端末の監視の強化（2m-1）。
//
//   - 指示の未適用：ハートビートは届くのに、端末が指示を適用しないままなら検知結果にする（乗っ取られた解析部は、ハートビートを
//     続けたまま指示を執行部に渡さないことができる。ハートビートの適用済みの版数は執行部が書くので偽れない）
//   - 端末の ARP の表のなりすまし：CLIENT が知らせた、GW のアドレスを指していた機器を、ゲートウェイのなりすましとして扱う
//   - 隔離中の更新サーバーの変更：指示に入れる更新サーバーが変わったら版数を上げ、CLIENT の自己隔離にも反映させる

// lagHeartbeats は、指示を適用していないと判断するまでに受け取るハートビートの数（応答で指示を受け取る機会の数）。
const lagHeartbeats = 3

// checkLagLocked は、端末が報告した適用済みの版数 applied が指示の版数より遅れ続けていないかを確かめ、遅れ続けていたら
// 検知結果を返す（ロックの外で observe する）。lagHeartbeats 回以上のハートビートを受け取り、ハートビートの途絶の
// 時間を超えても遅れていたら、遅れ続けているとする。追いついたら戻す。
func (c *Controller) checkLagLocked(d *device, applied uint64, now time.Time) *event.Event {
	if applied >= d.Version {
		if d.Lagging {
			d.Lagging = false
			c.dirty = true
			c.log.Info("端末が指示を適用しました", "端末", d.ID, "版数", applied)
		}
		d.lagSince, d.lagBeats = time.Time{}, 0
		return nil
	}
	if d.lagSince.IsZero() {
		d.lagSince = now
	}
	d.lagBeats++
	if d.Lagging || d.lagBeats < lagHeartbeats || now.Sub(d.lagSince) < c.cfg.HeartbeatTimeout {
		return nil
	}
	d.Lagging = true
	c.dirty = true
	msg := fmt.Sprintf("端末 %s はハートビートを送り続けていますが、%s 以上、指示を適用していません（適用済みの版数 %d、指示の版数 %d）。"+
		"CLIENT の解析部が乗っ取られて指示を渡していないか、指示の適用（自己隔離など）に失敗しています。GW の遮断は効いています",
		d.ID, now.Sub(d.lagSince).Round(time.Second), applied, d.Version)
	c.log.Warn("端末が指示を適用していません", "端末", d.ID, "適用済み", applied, "指示", d.Version)
	e := c.finding(event.FindingTypeCommandNotApplied, "指示の未適用", msg, event.SeverityHigh, deviceInfo(d))
	e.Unmapped = map[string]any{"applied_version": applied, "command_version": d.Version, "isolation": string(d.Isolation)}
	return e
}

// gatewayInfo は、端末に知らせる GW の LAN 側のアドレスと MAC アドレスを返す（GW の LAN がなければ nil）。
func (c *Controller) gatewayInfo() *api.GatewayInfo {
	lan := c.cfg.LAN
	if lan == nil || !lan.Addr().Is4() || len(lan.MAC()) != 6 {
		return nil
	}
	return &api.GatewayInfo{IP: lan.Addr(), MAC: lan.MAC().String()}
}

// prefixesHash は更新サーバーの一覧のハッシュを返す（なければ空）。
func prefixesHash(ps []netip.Prefix) string {
	if len(ps) == 0 {
		return ""
	}
	h := sha256.New()
	for _, p := range ps {
		h.Write([]byte(p.String() + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// reportARPPoisoning は、端末 id が知らせた ARP の表のなりすまし（e）で、GW のアドレスを指していた機器を、
// ゲートウェイのなりすましとして扱う。GW 自身と、台帳にない機器は扱わない。
func (c *Controller) reportARPPoisoning(id string, e *event.Event) {
	lan := c.cfg.LAN
	arp, _ := e.Unmapped["arp"].(map[string]any)
	observed, _ := arp["observed_mac"].(string)
	ip, _ := arp["ip"].(string)
	hw, err := net.ParseMAC(observed)
	if lan == nil || err != nil || len(hw) != 6 || ip != lan.Addr().String() || hw.String() == lan.MAC().String() {
		return
	}
	mac := hw.String()
	now := c.now()
	c.mu.Lock()
	h := c.hosts[mac]
	if h == nil || h.DeviceID == id || now.Sub(h.spoofAt) < spoofInterval {
		c.mu.Unlock()
		if h == nil {
			c.log.Warn("端末の ARP の表で GW のアドレスを指していた機器は、台帳にありません", "端末", id, "MAC", mac)
		}
		return
	}
	h.spoofAt = now
	snapshot := *h
	c.mu.Unlock()
	msg := fmt.Sprintf("機器 %s が、端末 %s だけに GW のアドレス %s を名乗っていました（端末の ARP の表のなりすまし。%s）", mac, id, ip, ReasonGatewaySpoofing)
	f := c.finding(event.FindingTypeGatewaySpoofing, ReasonGatewaySpoofing, msg, event.SeverityCritical,
		&event.Device{UID: snapshot.DeviceID, MAC: mac, Hostname: snapshot.Hostname})
	f.Unmapped = map[string]any{"reported_by": id}
	c.log.Warn("端末だけに宛てたゲートウェイのなりすましを検知しました", "MAC", mac, "知らせた端末", id)
	c.observe(f, subject{mac: mac})
}
