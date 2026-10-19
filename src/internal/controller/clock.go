package controller

import (
	"fmt"
	"slices"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
)

// 時刻のずれと資源の上限（2l）。
//
// CONTROLLER は、端末のハートビートに入っている端末の時刻と受け取った時刻の差を記録し、直近の中央値が上限を超えたら
// 検知結果にする（記録の時系列の精度が落ちるため。時刻の改ざんの疑いもある）。CONTROLLER の機器の時刻が同期しているかも
// 状態に表示する（端末の時刻は、この機器の時刻と比べるため）。CLIENT が報告した資源の使用量は台帳に記録する。

const (
	DefaultMaxClockSkew = 2 * time.Minute
	clockSamples        = 5 // 中央値をとるハートビートの数
	minClockSamples     = 3 // これだけ集まるまでは判断しない（一時的な通信の遅れで判断しないように）
)

// recordClockLocked は端末の時刻のずれを記録し、上限を超えたら検知結果を返す（ロックの外で observe する）。
// ずれが上限の半分以下に戻ったら、ずれていないことにする。
func (c *Controller) recordClockLocked(d *device, hb api.Heartbeat, now time.Time) *event.Event {
	d.ClockSynced = hb.ClockSynced
	if hb.Time.IsZero() {
		return nil
	}
	d.clock = append(d.clock, hb.Time.Sub(now))
	if len(d.clock) > clockSamples {
		d.clock = d.clock[len(d.clock)-clockSamples:]
	}
	if len(d.clock) < minClockSamples {
		return nil
	}
	sorted := slices.Sorted(slices.Values(d.clock))
	offset := sorted[len(sorted)/2]
	d.ClockOffset = offset.Round(100 * time.Millisecond)
	switch {
	case !d.ClockSkewed && offset.Abs() > c.cfg.MaxClockSkew:
		d.ClockSkewed = true
		c.dirty = true
		msg := fmt.Sprintf("端末 %s の時刻が CONTROLLER より %s（上限 %s）。記録の時系列の精度が落ちます。端末の時刻の同期（NTP）を確かめてください。"+
			"意図せずに時刻を変えられた恐れもあります", d.ID, describeOffset(offset), c.cfg.MaxClockSkew)
		c.log.Warn("端末の時刻がずれています", "端末", d.ID, "ずれ", d.ClockOffset)
		e := c.finding(event.FindingTypeClockSkew, "端末の時刻のずれ", msg, event.SeverityLow, deviceInfo(d))
		e.Unmapped = map[string]any{"clock_offset": d.ClockOffset.Seconds(), "max_clock_skew": c.cfg.MaxClockSkew.Seconds()}
		return e
	case d.ClockSkewed && offset.Abs() <= c.cfg.MaxClockSkew/2:
		d.ClockSkewed = false
		c.dirty = true
		c.log.Info("端末の時刻のずれが直りました", "端末", d.ID, "ずれ", d.ClockOffset)
	}
	return nil
}

// describeOffset は時刻のずれを「5m0s 進んでいます」の形にする。
func describeOffset(d time.Duration) string {
	if d < 0 {
		return (-d).Round(time.Second).String() + " 遅れています"
	}
	return d.Round(time.Second).String() + " 進んでいます"
}

// recordResourcesLocked は CLIENT が報告した資源の使用量を記録する。監視の間引きを始めたかやめたらログに残す
// （始めたときの検知結果は CLIENT が送る）。
func (c *Controller) recordResourcesLocked(d *device, hb api.Heartbeat) {
	r := hb.Resources
	if r != nil && (r.CPUPercent < 0 || r.MemoryBytes < 0) {
		r = nil
	}
	was := d.Resources != nil && d.Resources.Throttled
	d.Resources = r
	switch now := r != nil && r.Throttled; {
	case now && !was:
		c.log.Warn("端末が資源の上限を超え、監視を間引いています", "端末", d.ID, "CPU", r.CPUPercent, "メモリ(MiB)", r.MemoryBytes>>20)
	case !now && was:
		c.log.Info("端末が監視の間引きをやめました", "端末", d.ID)
	}
}

// clockSynced は CONTROLLER の機器の時刻が同期しているかを返す（分からなければ nil）。
func (c *Controller) clockSynced() *bool {
	if c.cfg.ClockSynced == nil {
		return nil
	}
	synced, err := c.cfg.ClockSynced()
	if err != nil {
		return nil
	}
	return &synced
}

// warnClock は、CONTROLLER の機器の時刻が同期していなければ警告する。
func (c *Controller) warnClock() {
	if s := c.clockSynced(); s != nil && !*s {
		c.log.Warn("この機器の時刻が同期していません。端末の時刻のずれはこの機器の時刻と比べて判断するので、NTP などで時刻を合わせてください")
	}
}
