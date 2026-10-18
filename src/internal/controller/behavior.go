package controller

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"susanoo/internal/behavior"
	"susanoo/internal/event"
	"susanoo/internal/fsutil"
)

// 振る舞いの検知（G6）。GW の観測（通信の記録、DNS の問い合わせ、ARP の要求）を behavior.Detector に渡し、
// 検知した振る舞いを検知結果にして、検知ルールで評価する（既定のルールは試験運用）。

const (
	behaviorFile         = "behavior.json" // 新しい宛先の急増の学習で覚えた宛先
	behaviorSaveInterval = 5 * time.Minute
)

// initBehavior は振る舞いの検知を用意し、覚えた宛先を読む。
func (c *Controller) initBehavior() error {
	eng := c.engine.Load()
	c.detector = behavior.New(eng.Behavior(), eng.Watches)
	data, err := os.ReadFile(filepath.Join(c.cfg.Dir, behaviorFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := c.detector.Restore(data); err != nil {
		return fmt.Errorf("controller: %s を解析できません: %w", behaviorFile, err)
	}
	return nil
}

// saveBehavior は覚えた宛先を保存する。force でなければ、前の保存から behaviorSaveInterval が経つまで保存しない
// （覚えた宛先は多いので、台帳のように頻繁には書かない）。
func (c *Controller) saveBehavior(force bool) {
	c.behaviorMu.Lock()
	defer c.behaviorMu.Unlock()
	now := c.now()
	if !force && now.Sub(c.behaviorSaved) < behaviorSaveInterval {
		return
	}
	data := c.detector.Snapshot(force)
	if data == nil {
		return
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(c.cfg.Dir, behaviorFile), data, 0o600); err != nil {
		c.log.Error("振る舞いの検知で覚えた宛先を保存できません", "エラー", err)
		return
	}
	c.behaviorSaved = now
}

// behaviorTarget は、観測の対象を台帳で解決し、振る舞いの検知の単位と、検知結果の評価に使う対象を返す。
func (c *Controller) behaviorTarget(s subject) (behavior.Subject, target, subject) {
	c.mu.Lock()
	t := c.resolveLocked(s)
	c.mu.Unlock()
	sub := behavior.Subject{Key: t.key, Name: t.name(), Group: t.group}
	switch {
	case t.key != "":
	case s.mac != "":
		sub.Key, sub.Name = "mac:"+s.mac, s.mac
	case s.ip.IsValid():
		sub.Key, sub.Name = "ip:"+s.ip.String(), s.ip.String()
	}
	next := subject{device: t.device, mac: cmp.Or(t.mac, s.mac), ip: s.ip}
	return sub, t, next
}

// reportBehavior は、検知した振る舞いを検知結果にして保存し、検知ルールで評価する。
func (c *Controller) reportBehavior(findings []behavior.Finding, t target, s subject) {
	for _, f := range findings {
		dev := &event.Device{UID: t.device, MAC: cmp.Or(t.mac, s.mac)}
		if s.ip.IsValid() {
			dev.IP = s.ip.String()
		}
		e := c.finding(f.Kind, f.Title, f.Message, f.Severity, dev)
		e.DstEndpoint, e.Traffic = f.Dst, f.Traffic
		if len(f.Details) > 0 {
			e.Unmapped = map[string]any{"behavior": f.Details}
		}
		c.observe(e, s)
	}
}

// ObserveARPRequest は、LAN の機器 frame が LAN のアドレス target を ARP で探したことを受け取る（LAN 内のスキャンの検知）。
func (c *Controller) ObserveARPRequest(frame net.HardwareAddr, target netip.Addr) {
	lan := c.cfg.LAN
	if lan == nil || len(frame) != 6 || string(frame) == string(lan.MAC()) || !lan.Prefix().Contains(target) {
		return
	}
	if !c.detector.Enabled(behavior.KindInternalScan) {
		return
	}
	sub, t, s := c.behaviorTarget(subject{mac: frame.String()})
	c.reportBehavior(c.detector.ARPRequest(sub, target, c.now()), t, s)
}
