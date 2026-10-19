package client

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/platform"
	"susanoo/internal/platform/platformtest"
	"susanoo/internal/sign"
)

// resourcePlatform は、資源の使用量と時刻の同期の状態を試験から決められる Platform。
type resourcePlatform struct {
	*platformtest.Fake
	mu       sync.Mutex
	usage    platform.Usage
	throttle []bool
	synced   bool
}

func (p *resourcePlatform) Usage() (platform.Usage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.usage, nil
}

func (p *resourcePlatform) SetThrottle(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.throttle = append(p.throttle, on)
}

func (p *resourcePlatform) ClockSynchronized() (bool, error) { return p.synced, nil }

func (p *resourcePlatform) set(u platform.Usage) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.usage = u
}

func (p *resourcePlatform) throttles() []bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.throttle)
}

// CPU の使用率は resourceWindow を測ってから判断し、間引きは最低でも resourceWindow 続ける。メモリはすぐに判断する。
func TestResourceMonitor(t *testing.T) {
	m := resourceMonitor{cpuLimit: 10, memLimit: 100 << 20}
	at, cpu := time.Unix(1_000_000, 0), time.Duration(0)
	obs := func(d, used time.Duration, mem int64) int {
		at, cpu = at.Add(d), cpu+used
		return m.observe(at, platform.Usage{CPU: cpu, Memory: mem})
	}
	if c := obs(0, 0, 10<<20); c != 0 || !m.measured {
		t.Fatalf("最初の記録 = %d", c)
	}
	// 5 秒ごとに 2 秒（40%）使っても、30 秒を測るまでは間引かない（起動した直後の読み込み）。
	for i := range 5 {
		if c := obs(5*time.Second, 2*time.Second, 10<<20); c != 0 {
			t.Fatalf("%d 回目で判断しました（%d）", i, c)
		}
	}
	if c := obs(5*time.Second, 2*time.Second, 10<<20); c != 1 || !m.usage.Throttled || m.usage.CPUPercent != 40 {
		t.Fatalf("30 秒の平均が上限を超えたのに間引きません: %d %+v", c, m.usage)
	}
	since := at
	// 使わなくなっても、平均が上限の 8 割を下回り、30 秒たつまでは続ける。
	released := time.Time{}
	for range 12 {
		if c := obs(5*time.Second, 0, 10<<20); c == -1 {
			released = at
			break
		} else if c != 0 {
			t.Fatalf("間引き中に %d", c)
		}
	}
	if released.Sub(since) != 30*time.Second || m.usage.Throttled || m.usage.CPUPercent != 0 {
		t.Fatalf("間引きをやめた時刻 = 始めてから %s（%+v）", released.Sub(since), m.usage)
	}
	// メモリが上限を超えたら、すぐに間引く。上限の 9 割を下回るまでは続ける。
	if c := obs(5*time.Second, 0, 200<<20); c != 1 {
		t.Fatalf("メモリの上限を超えても間引きません: %d", c)
	}
	for range 8 {
		if c := obs(5*time.Second, 0, 95<<20); c != 0 {
			t.Fatalf("上限の 9 割を超えているのに %d", c)
		}
	}
	if c := obs(5*time.Second, 0, 50<<20); c != -1 {
		t.Fatalf("メモリが下がっても間引きをやめません: %d", c)
	}
	// 子のプロセスが終わって CPU の時間の合計が減っても、測り直して続ける。
	cpu = 0
	if c := obs(5*time.Second, 0, 10<<20); c != 0 || len(m.samples) != 1 {
		t.Fatalf("合計が減ったときの記録 = %d（%d 件）", c, len(m.samples))
	}
	// 上限が 0 の資源では判断しない。
	m2 := resourceMonitor{}
	if c := m2.observe(at, platform.Usage{Memory: 1 << 40}); c != 0 {
		t.Fatalf("上限のない資源で判断しました: %d", c)
	}
}

// 執行部は資源の使用量を測ってハートビートで報告し、上限を超えたら Platform に間引かせて検知結果を送る。
func TestLocalResources(t *testing.T) {
	env := pkitest.New(t)
	p := &resourcePlatform{Fake: platformtest.New(caps), synced: true}
	p.set(platform.Usage{CPU: time.Second, Memory: 128 << 20, Dropped: 3})
	l, err := NewLocal(LocalConfig{
		Cert: env.Leaf(t, pki.RoleClient, "pc-001"), CA: env.CA.Pool(), CommandKey: env.Signer.PublicKey(), StateDir: t.TempDir(),
		Controller: netip.MustParseAddrPort("127.0.0.1:1"), Platform: p, Logger: quiet,
		CPULimit: 10, MemoryLimit: 64 << 20, ResourceInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := func() api.Heartbeat {
		t.Helper()
		env, err := l.Heartbeat(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		v, _ := sign.NewVerifier(l.key.Public().(ed25519.PublicKey))
		payload, err := v.Verify(sign.PurposeHeartbeat, env)
		if err != nil {
			t.Fatal(err)
		}
		var hb api.Heartbeat
		if err := json.Unmarshal(payload, &hb); err != nil {
			t.Fatal(err)
		}
		return hb
	}
	if hb := heartbeat(); hb.Resources != nil || hb.ClockSynced == nil || !*hb.ClockSynced {
		t.Errorf("測る前のハートビート: 資源 %+v、時刻の同期 %v", hb.Resources, hb.ClockSynced)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan event.Event, 16)
	go l.Watch(ctx, out)
	select {
	case e := <-out:
		if e.FindingInfo == nil || !slices.Contains(e.FindingInfo.Types, event.FindingTypeResourceLimit) || e.Unmapped["memory_bytes"] != int64(128<<20) {
			t.Fatalf("検知結果 = %+v", e)
		}
		if err := e.Validate(); err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("メモリの上限を超えても検知結果を送りません")
	}
	if got := p.throttles(); !slices.Equal(got, []bool{true}) {
		t.Errorf("間引きの指示 = %v", got)
	}
	hb := heartbeat()
	if r := hb.Resources; r == nil || !r.Throttled || r.MemoryBytes != 128<<20 || r.Dropped != 3 {
		t.Errorf("ハートビートの資源 = %+v", hb.Resources)
	}
	// 上限を超え続けても、検知結果は 1 回だけ送る。
	time.Sleep(100 * time.Millisecond)
	select {
	case e := <-out:
		t.Errorf("2 つ目の検知結果: %+v", e)
	default:
	}
}
