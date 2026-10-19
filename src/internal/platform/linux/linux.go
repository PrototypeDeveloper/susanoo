//go:build linux

// Package linux は Linux の Platform の実装。
//
//   - おとりの監視（C5）：fanotify を使う。権限がなく使えないときは inotify に切り替える
//     （inotify では触ったプロセスが分からない）
//   - プロセスの監視（C1）：fanotify の FAN_OPEN_EXEC（exec.go）
//   - 通信とプロセスの結び付け（C2）：sock_diag と /proc（conn.go）
//   - ファイルの監視と大量の変更の検知（C3）、永続化と権限の設定の場所の変更、認証情報の読み取りの検知（C4、C8、C9）：
//     fanotify の FID 方式（files.go）
//   - 権限昇格の検知（C4）：プロセスの起動のときに祖先の利用者を調べる（exec.go、proc.go）
//   - カーネルモジュールの読み込みの検知（C4）：/proc/modules を定期的に読む（modules.go）
//   - AI エージェントの帰属（C9）：プロセスの祖先に設定したエージェントがあれば、イベントに unmapped.agent を付ける（agent.go）
//   - 自己隔離（C6）：nft コマンドで専用のテーブルを作る。テーブルが消されていないかも確かめる（C10）
//
// 使える機能は Capabilities で申告する（C12）。
package linux

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"susanoo/internal/event"
	"susanoo/internal/honeytoken"
	"susanoo/internal/nft"
	"susanoo/internal/platform"
	"susanoo/internal/policy"
)

// dedupeWindow の間は、同じおとりへの同じプロセスの接触を 1 件にまとめる。
// 1 回の読み込みでも open と access が続けて届くため。
const dedupeWindow = 30 * time.Second

// fileEvent はおとりのファイルへの操作。
type fileEvent struct {
	token int    // おとりの番号
	op    string // honeytoken.Op*
	pid   int    // 分からなければ 0
}

// watcher はおとりのファイルを監視する仕組み。
type watcher interface {
	name() string
	// run はイベントを out に送り続け、ctx が終わるか close されたら返る。
	run(ctx context.Context, out chan<- fileEvent) error
	close() error
}

// source はイベントを出す監視の仕組み。
type source interface {
	run(ctx context.Context, emit func(*event.Event)) error
	close() error
}

// Config は Platform の設定。
type Config struct {
	Tokens        []honeytoken.Token // 監視するおとり
	NFT           nft.Runner         // 自己隔離に使う。nil なら自己隔離しない
	ProcessEvents bool               // プロセスの起動と終了を記録する
	NetworkEvents bool               // 通信と発信元のプロセスを記録する
	Files         FileConfig         // ファイルの監視。場所がなければ監視しない
	ConnPoll      time.Duration      // 通信の一覧を取る間隔。既定 DefaultConnPoll
	KernelModules bool               // カーネルモジュールの読み込みを検知する
	ModulePoll    time.Duration      // カーネルモジュールの一覧を読む間隔。既定 10 秒
	Logons        LogonConfig        // ログオンの記録（C4）
	Agents        []AgentSpec        // 見分ける AI エージェント。nil なら DefaultAgents、空なら見分けない
	EvidenceLogs  []string           // 証拠として末尾を集めるログ。nil なら DefaultEvidenceLogs、空なら集めない
	AppControl    bool               // プロセス単位の通信の制御（C7）を使う（NFT が必要）
	Logger        *slog.Logger
	Now           func() time.Time
}

// TableChecker は nft のテーブルがあるかを確かめられる Runner（nft.Command が満たす）。
type TableChecker interface {
	TableExists(ctx context.Context, table string) (bool, error)
}

// Platform は Linux の Platform。
type Platform struct {
	cfg      Config
	caps     platform.Capabilities
	newWatch func([]string) (watcher, error)
	sources  map[platform.Capability]func() (source, error)
	procs    *procCache
	agents   *agentMatcher
	apps     *appFirewall      // プロセス単位の通信の制御（使えなければ nil）
	extra    chan *event.Event // 監視の仕組みの外から出る検知結果（プロセス単位の通信の制御）
	hostname string
	self     int

	throttled atomic.Bool   // 資源の上限を超えて、監視を間引いている（2l）
	thinner   *limiter      // 間引いている間に通すイベントの数
	dropped   atomic.Uint64 // 間引いている間に捨てたイベントの数

	neigh neighborPins // 固定した ARP の表のエントリ（2m-1）
}

var _ platform.Platform = (*Platform)(nil)

// New は使える機能を調べて Platform を作る。
func New(cfg Config) *Platform {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Agents == nil {
		cfg.Agents = DefaultAgents()
	}
	p := &Platform{cfg: cfg, self: os.Getpid(), sources: map[platform.Capability]func() (source, error){}, procs: newProcCache(), agents: newAgentMatcher(cfg.Agents),
		extra: make(chan *event.Event, 256), thinner: newLimiter(throttleRate, throttleBurst)}
	p.hostname, _ = os.Hostname()
	p.caps = platform.Capabilities{OS: runtime.GOOS, Arch: runtime.GOARCH, Kernel: kernelRelease()}

	if paths := p.paths(); len(paths) > 0 {
		for _, newWatch := range []func([]string) (watcher, error){newFanotify, newInotify} {
			w, err := newWatch(paths)
			if err != nil {
				cfg.Logger.Info("おとりの監視の方式を切り替えます", "理由", err)
				continue
			}
			cfg.Logger.Info("おとりを監視します", "方式", w.name(), "件数", len(paths))
			w.close()
			p.newWatch = newWatch
			p.caps.Features = append(p.caps.Features, platform.CapHoneytoken)
			break
		}
	}
	candidates := []struct {
		enabled bool
		cap     platform.Capability
		name    string
		open    func() (source, error)
	}{
		{cfg.ProcessEvents, platform.CapProcessEvents, "プロセスの監視", func() (source, error) { return newExecMonitor(p.procs, p.agents, cfg.Logger) }},
		{cfg.NetworkEvents, platform.CapNetworkEvents, "通信の監視", func() (source, error) { return newConnMonitor(cfg.ConnPoll, p.procs, p.agents, &p.throttled) }},
		{cfg.Files.enabled(), platform.CapFileEvents, "ファイルの監視", func() (source, error) { return newFileMonitor(cfg.Files, p.procs, p.agents, cfg.Logger) }},
		{cfg.KernelModules, platform.CapKernelModules, "カーネルモジュールの監視", func() (source, error) { return newModuleMonitor(cfg.ModulePoll) }},
		{cfg.Logons.Enabled, platform.CapLogons, "ログオンの記録", func() (source, error) { return newLogonMonitor(cfg.Logons, cfg.Logger) }},
	}
	for _, c := range candidates {
		if !c.enabled {
			continue
		}
		s, err := c.open()
		if err != nil {
			cfg.Logger.Info(c.name+"を使えません", "理由", err)
			continue
		}
		s.close()
		p.sources[c.cap] = c.open
		p.caps.Features = append(p.caps.Features, c.cap)
	}
	if cfg.NFT != nil && os.Geteuid() == 0 {
		p.caps.Features = append(p.caps.Features, platform.CapIsolation)
		if cfg.AppControl {
			p.apps = newAppFirewall(cfg.NFT, p.procs, p.agents, p.extra, cfg.Logger)
			p.caps.Features = append(p.caps.Features, platform.CapAppControl)
		}
	}
	if err := evidenceLogsValid(cfg.EvidenceLogs); err != nil {
		cfg.Logger.Warn(err.Error())
	} else {
		p.caps.Features = append(p.caps.Features, platform.CapEvidence)
	}
	return p
}

var _ platform.Collector = (*Platform)(nil)

var _ platform.AppFirewall = (*Platform)(nil)

// SetAppControl はプロセス単位の通信の制御のルールを置き換える（platform.AppFirewall）。
func (p *Platform) SetAppControl(ctx context.Context, ac *policy.AppControl, exempt []netip.Addr) error {
	if p.apps == nil {
		return errors.New("linux: プロセス単位の通信の制御は使えません（root と nft が必要です）")
	}
	return p.apps.set(ctx, ac, exempt)
}

func (p *Platform) paths() []string {
	paths := make([]string, len(p.cfg.Tokens))
	for i, t := range p.cfg.Tokens {
		paths[i] = t.Path
	}
	return paths
}

func (p *Platform) Capabilities() platform.Capabilities { return p.caps }

// Watch は、使えるすべての監視のイベントを out に送る。ctx が終わるまで返らない。
// 途中で止まった監視はログに残し、ほかの監視は続ける。
func (p *Platform) Watch(ctx context.Context, out chan<- event.Event) error {
	emit := func(e *event.Event) {
		if p.thin(e) {
			return
		}
		if e.Device == nil {
			e.Device = &event.Device{Hostname: p.hostname}
		}
		select {
		case out <- *e:
		case <-ctx.Done():
		}
	}
	var wg sync.WaitGroup
	start := func(name string, run func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := run(ctx); err != nil && ctx.Err() == nil {
				p.cfg.Logger.Error(name+"が止まりました", "エラー", err)
			}
		}()
	}
	if p.newWatch != nil {
		start("おとりの監視", func(ctx context.Context) error { return p.watchHoneytokens(ctx, emit) })
	}
	start("監視の外からの検知結果", func(ctx context.Context) error {
		for {
			select {
			case e := <-p.extra:
				emit(e)
			case <-ctx.Done():
				return nil
			}
		}
	})
	for feature, open := range p.sources {
		s, err := open()
		if err != nil {
			p.cfg.Logger.Error("監視を始められません", "機能", feature, "エラー", err)
			continue
		}
		start(string(feature), func(ctx context.Context) error {
			go func() { <-ctx.Done(); s.close() }()
			return s.run(ctx, emit)
		})
	}
	<-ctx.Done()
	wg.Wait()
	return ctx.Err()
}

type dedupeKey struct{ token, pid int }

// watchHoneytokens はおとりへの接触を検知結果のイベントとして送る。
func (p *Platform) watchHoneytokens(ctx context.Context, emit func(*event.Event)) error {
	w, err := p.newWatch(p.paths())
	if err != nil {
		return err
	}
	defer w.close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	evs := make(chan fileEvent, 64)
	errc := make(chan error, 1)
	go func() { errc <- w.run(ctx, evs) }()
	go func() { <-ctx.Done(); w.close() }()

	last := map[dedupeKey]time.Time{}
	for {
		select {
		case fe := <-evs:
			if fe.pid == p.self {
				continue
			}
			now := p.cfg.Now()
			key := dedupeKey{fe.token, fe.pid}
			if t, ok := last[key]; ok && now.Sub(t) < dedupeWindow {
				continue
			}
			last[key] = now
			pruneOld(last, now)
			proc, anc := p.procs.inspect(fe.pid)
			e := honeytoken.Finding(p.cfg.Tokens[fe.token], fe.op, proc, now)
			p.agents.annotate(e, proc, anc)
			emit(e)
		case err := <-errc:
			if err == nil {
				err = ctx.Err()
			}
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func pruneOld(last map[dedupeKey]time.Time, now time.Time) {
	if len(last) < 1024 {
		return
	}
	for k, t := range last {
		if now.Sub(t) >= dedupeWindow {
			delete(last, k)
		}
	}
}

// IsolationActive は自己隔離のテーブルがあるかを返す。確かめられなければエラーを返す。
func (p *Platform) IsolationActive(ctx context.Context) (bool, error) {
	tc, ok := p.cfg.NFT.(TableChecker)
	if !ok {
		return false, errors.New("linux: 自己隔離のテーブルを確かめられません")
	}
	return tc.TableExists(ctx, nft.ClientTable)
}

// Isolate は nft で自己隔離する。管理通信は段階にかかわらず常に許可し、
// 解除の指示を受け取れるようにする（全遮断は GW の役割）。
func (p *Platform) Isolate(ctx context.Context, iso platform.Isolation) error {
	if p.cfg.NFT == nil {
		return errors.New("linux: 自己隔離は設定されていません")
	}
	rules := nft.ClientIsolation{Management: iso.Management, AllowDHCP: true}
	if iso.Level == policy.IsolateManagementAndUpdates {
		rules.Updates = iso.Updates
	}
	script, err := rules.Script()
	if err != nil {
		return err
	}
	return p.cfg.NFT.Run(ctx, script)
}

// Release は自己隔離のテーブルを削除する。
func (p *Platform) Release(ctx context.Context) error {
	if p.cfg.NFT == nil {
		return errors.New("linux: 自己隔離は設定されていません")
	}
	return p.cfg.NFT.Run(ctx, nft.DeleteTable(nft.ClientTable))
}

func kernelRelease() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	b := make([]byte, 0, len(u.Release))
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
