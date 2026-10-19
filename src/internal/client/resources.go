package client

import (
	"crypto/rand"
	"fmt"
	"math"
	"runtime/debug"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/platform"
)

// 資源の上限（2l）。執行部は、CLIENT（執行部、解析部、その子のプロセス）の CPU とメモリの使用量を定期的に測り、
// 上限を超えたら Platform に監視を間引かせて、検知結果を CONTROLLER に送る。使用量はハートビートで報告する。

const (
	DefaultResourceInterval = 5 * time.Second
	// resourceWindow は CPU の使用率を平均する時間。起動した直後の読み込みで間引かないよう、この長さを測るまでは
	// CPU では判断しない。間引きも最低でもこの間は続ける（始めたりやめたりを繰り返さないように）。
	resourceWindow = 30 * time.Second
	releaseCPU     = 0.8 // CPU の使用率が上限のこの割合を下回ったら、間引きをやめる
	releaseMemory  = 0.9 // メモリも同じ
)

type cpuSample struct {
	at  time.Time
	cpu time.Duration
}

// resourceMonitor は資源の使用量の記録と、間引くかの判断。
type resourceMonitor struct {
	cpuLimit float64 // 1 つの CPU に対する割合（%）。0 なら CPU では判断しない
	memLimit int64   // バイト。0 ならメモリでは判断しない
	samples  []cpuSample
	usage    api.ResourceUsage
	measured bool
	since    time.Time // 間引きを始めた時刻
}

// observe は測った使用量を記録し、間引きを始めるなら 1、やめるなら -1、変わらなければ 0 を返す。
func (m *resourceMonitor) observe(now time.Time, u platform.Usage) int {
	if n := len(m.samples); n > 0 && u.CPU < m.samples[n-1].cpu {
		m.samples = m.samples[:0] // 子のプロセスが終わって合計が減った。測り直す
	}
	m.samples = append(m.samples, cpuSample{now, u.CPU})
	// 最も古い記録が resourceWindow より前の最後のものになるように、それより古いものを捨てる。
	for len(m.samples) > 2 && now.Sub(m.samples[1].at) >= resourceWindow {
		m.samples = m.samples[1:]
	}
	first := m.samples[0]
	span := now.Sub(first.at)
	cpu := 0.0
	if span > 0 {
		cpu = float64(u.CPU-first.cpu) / float64(span) * 100
	}
	m.usage = api.ResourceUsage{CPUPercent: math.Round(cpu*10) / 10, MemoryBytes: u.Memory, Throttled: m.usage.Throttled, Dropped: u.Dropped}
	m.measured = true
	cpuOver := m.cpuLimit > 0 && span >= resourceWindow && cpu > m.cpuLimit
	memOver := m.memLimit > 0 && u.Memory > m.memLimit
	switch {
	case !m.usage.Throttled && (cpuOver || memOver):
		m.usage.Throttled, m.since = true, now
		return 1
	case m.usage.Throttled && now.Sub(m.since) >= resourceWindow &&
		(m.cpuLimit == 0 || cpu < m.cpuLimit*releaseCPU) && (m.memLimit == 0 || float64(u.Memory) < float64(m.memLimit)*releaseMemory):
		m.usage.Throttled = false
		return -1
	}
	return 0
}

// resourceUsage はハートビートで報告する資源の使用量を返す（まだ測っていなければ nil）。
func (l *Local) resourceUsage() *api.ResourceUsage {
	l.resMu.Lock()
	defer l.resMu.Unlock()
	if !l.res.measured {
		return nil
	}
	u := l.res.usage
	return &u
}

// clockSynced は端末の時刻が同期しているかを返す（分からなければ nil）。
func (l *Local) clockSynced() *bool {
	c, ok := l.cfg.Platform.(platform.Clock)
	if !ok {
		return nil
	}
	synced, err := c.ClockSynchronized()
	if err != nil {
		return nil
	}
	return &synced
}

const mib = 1 << 20

// checkResources は資源の使用量を測り、上限を超えたら監視を間引かせて検知結果を返す。下がったら間引きをやめる。
func (l *Local) checkResources() *event.Event {
	rp, ok := l.cfg.Platform.(platform.Resources)
	if !ok {
		return nil
	}
	u, err := rp.Usage()
	if err != nil {
		l.log.Debug("資源の使用量を測れません", "エラー", err)
		return nil
	}
	now := l.cfg.Now()
	l.resMu.Lock()
	change := l.res.observe(now, u)
	usage := l.res.usage
	l.resMu.Unlock()
	switch change {
	case 1:
		rp.SetThrottle(true)
		if l.cfg.MemoryLimit > 0 && usage.MemoryBytes > l.cfg.MemoryLimit {
			debug.FreeOSMemory()
		}
		msg := fmt.Sprintf("CLIENT が資源の上限を超えたため、監視を間引いています（CPU %.1f%%、上限 %g%%。メモリ %d MiB、上限 %d MiB）。"+
			"検知結果は間引きません。大量の操作で監視を妨げようとしている恐れもあります",
			usage.CPUPercent, l.cfg.CPULimit, usage.MemoryBytes/mib, l.cfg.MemoryLimit/mib)
		l.log.Warn("資源の上限を超えたため、監視を間引きます", "CPU", usage.CPUPercent, "メモリ(MiB)", usage.MemoryBytes/mib)
		e := event.New(event.ClassDetectionFinding, event.FindingCreate, event.SeverityLow, now)
		e.Message = msg
		e.FindingInfo = &event.FindingInfo{UID: rand.Text(), Title: "CLIENT の資源の上限", Desc: msg, Types: []string{event.FindingTypeResourceLimit}}
		e.Device = &event.Device{Hostname: l.hostname}
		e.Unmapped = map[string]any{"cpu_percent": usage.CPUPercent, "cpu_limit": l.cfg.CPULimit, "memory_bytes": usage.MemoryBytes, "memory_limit": l.cfg.MemoryLimit}
		return e
	case -1:
		rp.SetThrottle(false)
		l.log.Info("資源の使用量が下がったため、監視の間引きをやめました", "CPU", usage.CPUPercent, "メモリ(MiB)", usage.MemoryBytes/mib, "捨てたイベント", usage.Dropped)
	}
	return nil
}
