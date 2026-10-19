//go:build linux

package linux

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"susanoo/internal/event"
	"susanoo/internal/nft"
	"susanoo/internal/policy"
)

// プロセス単位の通信の制御（C7）。nftables が外向きの新しい TCP と UDP の接続の最初のパケットを NFQUEUE に渡し、
// ここで接続したプロセス（sock_diag と /proc）と宛先をルールで判断する。拒否なら印を付けてパケットを戻し（NF_REPEAT）、
// テーブルの先頭のルールで拒否を返す。試験運用（monitor）では通して、拒否に当たったことだけを検知結果にする。
// CLIENT が止まると、nftables はパケットを判断を待たずに通す（bypass）。

const (
	appWorkers        = 4
	appWorkQueue      = 1024
	appFindingDedupe  = 10 * time.Minute
	appOwnerRescan    = 100 * time.Millisecond // /proc を調べ直す間隔の下限
	domainRefresh     = 5 * time.Minute
	domainKeep        = 30 * time.Minute // 引いたアドレスを覚えておく時間（DNS の答えが変わっても、しばらくは同じ宛先とみなす）
	domainLookupLimit = 5 * time.Second
)

// appFirewall はプロセス単位の通信の制御。
type appFirewall struct {
	nft     nft.Runner
	queue   uint16
	log     *slog.Logger
	procs   *procCache
	agents  *agentMatcher
	out     chan<- *event.Event // 検知結果（Watch が送る。いっぱいなら捨てる）
	self    int
	open    func(queue uint16) (*nfqueue, error)
	resolve func(ctx context.Context, name string) ([]netip.Addr, error)
	owner   func(flowKey) int // 接続の持ち主のプロセスを探す（試験で差し替える）

	ac       atomic.Pointer[policy.AppControl]
	domains  domainCache
	owners   ownerCache
	limiter  *limiter
	overflow overflowLog

	mu     sync.Mutex
	q      *nfqueue
	cancel context.CancelFunc
	done   chan struct{}

	fmu      sync.Mutex
	findings map[string]time.Time
}

func newAppFirewall(runner nft.Runner, procs *procCache, agents *agentMatcher, out chan<- *event.Event, log *slog.Logger) *appFirewall {
	f := &appFirewall{nft: runner, queue: nft.AppsQueue, log: log, procs: procs, agents: agents, out: out, self: os.Getpid(),
		open: openNFQueue, limiter: newLimiter(10, 50), findings: map[string]time.Time{}}
	f.resolve = func(ctx context.Context, name string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	}
	f.owner = f.owners.find
	f.domains.addrs = map[string]map[netip.Addr]time.Time{}
	f.domains.kick = make(chan struct{}, 1)
	return f
}

// set は制御のルールを置き換える。ac が nil ならキューを閉じ、テーブルを消す。
func (f *appFirewall) set(ctx context.Context, ac *policy.AppControl, exempt []netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ac == nil {
		f.ac.Store(nil)
		f.stopLocked()
		return f.nft.Run(ctx, nft.DeleteTable(nft.AppsTable))
	}
	f.ac.Store(ac)
	f.domains.set(ac.Domains())
	if f.q == nil {
		q, err := f.open(f.queue)
		if err != nil {
			return err
		}
		// キューに結び付いてからテーブルを作る（結び付く前に渡されたパケットは、判断を待たずに通る）。
		rctx, cancel := context.WithCancel(context.Background())
		f.q, f.cancel, f.done = q, cancel, make(chan struct{})
		go f.serve(rctx, q, f.done)
		go f.domains.run(rctx, f.resolve, f.log)
	}
	script, err := nft.AppControl{Queue: f.queue, Exempt: exempt}.Script()
	if err == nil {
		err = f.nft.Run(ctx, script)
	}
	if err != nil {
		f.stopLocked()
		return err
	}
	return nil
}

func (f *appFirewall) stopLocked() {
	if f.q == nil {
		return
	}
	f.cancel()
	f.q.close()
	<-f.done
	f.q = nil
}

// serve はキューのパケットを受け取り、判断する働き手に渡す。働き手が追いつかなければ、判断を待たずに通す。
func (f *appFirewall) serve(ctx context.Context, q *nfqueue, done chan struct{}) {
	defer close(done)
	work := make(chan nfqPacket, appWorkQueue)
	var wg sync.WaitGroup
	for range appWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range work {
				verdict, mark := f.decide(p)
				q.verdict(p.id, verdict, mark)
			}
		}()
	}
	defer func() { close(work); wg.Wait() }()
	buf := make([]byte, 64<<10)
	for ctx.Err() == nil {
		pkts, overflow, err := q.read(buf)
		if overflow {
			f.overflow.note(f.log, "プロセス単位の通信の制御", time.Now())
		}
		if err != nil {
			if ctx.Err() == nil {
				f.log.Error("プロセス単位の通信の制御のキューを読めません。接続は判断を待たずに通ります", "エラー", err)
			}
			return
		}
		for _, p := range pkts {
			select {
			case work <- p:
			default:
				q.verdict(p.id, nfAccept, 0)
				f.overflow.note(f.log, "プロセス単位の通信の制御の判断", time.Now())
			}
		}
	}
}

// decide はパケットの接続を判断し、判断（と印）を返す。
func (f *appFirewall) decide(p nfqPacket) (uint32, uint32) {
	ac := f.ac.Load()
	k, ok := parseIPPacket(p.payload)
	if ac == nil || !ok {
		return nfAccept, 0
	}
	pid := f.owner(k)
	if pid == f.self || (pid > 0 && f.isChild(pid)) {
		return nfAccept, 0 // CLIENT 自身（CONTROLLER との管理通信、ドメインの名前の問い合わせ）
	}
	var proc *event.Process
	var anc []ancestor
	if pid > 0 {
		proc, anc = f.procs.inspect(pid)
	}
	conn := policy.AppConn{Dst: k.dst.Addr(), Port: k.dst.Port(), Proto: k.proto}
	if proc != nil {
		conn.Name = proc.Name
		if proc.File != nil {
			conn.Exe = proc.File.Path
		}
	}
	tag, hasAgent := f.agents.of(proc, anc)
	if hasAgent {
		conn.Agent = tag.Name
	}
	action, rule := ac.Decide(conn, f.domains.lookup)
	if action == policy.AppAllow {
		return nfAccept, 0
	}
	f.report(ac, rule, conn, k, proc, anc, pid)
	if ac.Mode == policy.AppEnforce {
		return nfRepeat, nft.AppsDenyMark
	}
	return nfAccept, 0
}

func (f *appFirewall) isChild(pid int) bool {
	_, ppid := readStatus(procPath(pid, "status"))
	return ppid == f.self
}

// report は拒否した（試験運用なら拒否に当たった）接続を検知結果にする。同じプロセス、宛先、扱いは 10 分に 1 件にまとめる。
func (f *appFirewall) report(ac *policy.AppControl, rule *policy.AppRule, c policy.AppConn, k flowKey, proc *event.Process, anc []ancestor, pid int) {
	action := "deny"
	if ac.Mode == policy.AppMonitor {
		action = "would_deny"
	}
	now := time.Now()
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s", c.Exe, c.Agent, k.proto, k.dst, action)
	f.fmu.Lock()
	if t, ok := f.findings[key]; (ok && now.Sub(t) < appFindingDedupe) || !f.limiter.allow(now) {
		f.fmu.Unlock()
		return
	}
	if len(f.findings) > 4096 {
		for k, t := range f.findings {
			if now.Sub(t) >= appFindingDedupe {
				delete(f.findings, k)
			}
		}
	}
	f.findings[key] = now
	f.fmu.Unlock()

	ruleName := "既定（default: deny）"
	if rule != nil {
		ruleName = rule.Name
	}
	verb, title, sev := "拒否しました", "アプリの通信の拒否", event.SeverityMedium
	if action == "would_deny" {
		verb, title, sev = "通しました（試験運用。enforce なら拒否します）", "アプリの通信の拒否（試験運用）", event.SeverityLow
	}
	msg := fmt.Sprintf("%s から %s（%s）への接続を%s（ルール %s）", who(proc, pid), k.dst, k.proto, verb, ruleName)
	e := event.New(event.ClassDetectionFinding, event.FindingCreate, sev, now)
	e.Message = msg
	e.FindingInfo = &event.FindingInfo{UID: randomID(), Title: title, Desc: msg, Types: []string{event.FindingTypeAppControl}}
	e.Evidences = []event.Evidence{{Process: proc}}
	e.DstEndpoint = &event.Endpoint{IP: k.dst.Addr().String(), Port: int(k.dst.Port())}
	e.Connection = &event.Connection{ProtocolName: k.proto, DirectionID: 2}
	e.Unmapped = map[string]any{"app_control": map[string]any{"action": action, "mode": string(ac.Mode), "rule": ruleName, "exe": c.Exe}}
	f.agents.annotate(e, proc, anc)
	select {
	case f.out <- e:
	default:
	}
}

// ownerCache はパケットの接続の持ち主のプロセスを探す。sock_diag でソケットを探し、/proc でプロセスに結び付ける。
type ownerCache struct {
	mu     sync.Mutex
	owners map[uint32]int
	last   time.Time
}

// find は、送り元 k.src から宛先 k.dst への接続を持つプロセスの番号を返す（分からなければ 0）。
// IPv4 の接続は、IPv6 の両方に使うソケット（::）からのこともあるので、両方を探す。
func (o *ownerCache) find(k flowKey) int {
	inode := findSocket(k)
	if inode == 0 {
		return 0
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if pid, ok := o.owners[inode]; ok {
		return pid
	}
	if time.Since(o.last) < appOwnerRescan {
		time.Sleep(appOwnerRescan - time.Since(o.last))
	}
	o.owners, o.last = socketOwners(), time.Now()
	return o.owners[inode]
}

// findSocket は接続のソケットの i ノード番号を返す（見つからなければ 0）。
func findSocket(k flowKey) uint32 {
	fams := []uint8{syscall.AF_INET6}
	if k.src.Addr().Is4() {
		fams = []uint8{syscall.AF_INET, syscall.AF_INET6}
	}
	proto, states := uint8(syscall.IPPROTO_TCP), uint32(1<<tcpSynSent|1<<tcpEstablished)
	if k.proto == "udp" {
		proto, states = syscall.IPPROTO_UDP, tcpAllStates
	}
	for _, fam := range fams {
		socks, _ := dumpSockets(fam, proto, states)
		for _, s := range socks {
			if s.inode == 0 || s.local.Port() != k.src.Port() {
				continue
			}
			if proto == syscall.IPPROTO_TCP {
				if s.local.Addr() == k.src.Addr() && s.peer == k.dst {
					return s.inode
				}
				continue
			}
			localOK := s.local.Addr() == k.src.Addr() || s.local.Addr().IsUnspecified()
			peerOK := s.peer.Port() == 0 || s.peer == k.dst
			if localOK && peerOK {
				return s.inode
			}
		}
	}
	return 0
}

// domainCache はルールのドメインを引いたアドレスを覚える。
type domainCache struct {
	mu    sync.Mutex
	want  []string
	addrs map[string]map[netip.Addr]time.Time
	kick  chan struct{}
}

func (d *domainCache) set(domains []string) {
	d.mu.Lock()
	d.want = slices.Clone(domains)
	d.mu.Unlock()
	select {
	case d.kick <- struct{}{}:
	default:
	}
}

// run はルールが変わったときと、domainRefresh ごとに、ドメインを引き直す。
func (d *domainCache) run(ctx context.Context, resolve func(context.Context, string) ([]netip.Addr, error), log *slog.Logger) {
	t := time.NewTicker(domainRefresh)
	defer t.Stop()
	for {
		d.mu.Lock()
		want := slices.Clone(d.want)
		d.mu.Unlock()
		for _, name := range want {
			lctx, cancel := context.WithTimeout(ctx, domainLookupLimit)
			addrs, err := resolve(lctx, name)
			cancel()
			if err != nil {
				log.Warn("プロセス単位の通信の制御のドメインを引けません（覚えているアドレスで比べます）", "ドメイン", name, "エラー", err)
				continue
			}
			d.add(name, addrs, time.Now())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-d.kick:
		}
	}
}

func (d *domainCache) add(name string, addrs []netip.Addr, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	m := d.addrs[name]
	if m == nil {
		m = map[netip.Addr]time.Time{}
		d.addrs[name] = m
	}
	for _, a := range addrs {
		m[a.Unmap()] = now
	}
	for a, t := range m {
		if now.Sub(t) > domainKeep {
			delete(m, a)
		}
	}
}

// lookup はドメインの、覚えているアドレスを返す。
func (d *domainCache) lookup(name string) []netip.Addr {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []netip.Addr
	for a := range d.addrs[name] {
		out = append(out, a)
	}
	return out
}
