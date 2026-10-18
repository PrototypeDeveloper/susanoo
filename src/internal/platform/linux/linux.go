//go:build linux

// Package linux は Linux の Platform の実装。
//
//   - おとりの監視（C5）：fanotify を使う。権限がなく使えないときは inotify に切り替える
//     （inotify では触ったプロセスが分からない）
//   - プロセスの監視（C1）：fanotify の FAN_OPEN_EXEC（exec.go）
//   - 通信とプロセスの結び付け（C2）：sock_diag と /proc（conn.go）
//   - ファイルの監視と大量の変更の検知（C3）：fanotify の FID 方式（files.go）
//   - 自己隔離（C6）：nft コマンドで専用のテーブルを作る。テーブルが消されていないかも確かめる（C10）
//
// 使える機能は Capabilities で申告する（C12）。
package linux

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"runtime"
	"sync"
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
	hostname string
	self     int
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
	p := &Platform{cfg: cfg, self: os.Getpid(), sources: map[platform.Capability]func() (source, error){}}
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
		{cfg.ProcessEvents, platform.CapProcessEvents, "プロセスの監視", func() (source, error) { return newExecMonitor(cfg.Logger) }},
		{cfg.NetworkEvents, platform.CapNetworkEvents, "通信の監視", func() (source, error) { return newConnMonitor(cfg.ConnPoll) }},
		{len(cfg.Files.Paths) > 0 || len(cfg.Files.Protect) > 0, platform.CapFileEvents, "ファイルの監視", func() (source, error) { return newFileMonitor(cfg.Files, cfg.Logger) }},
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
	}
	return p
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
			emit(honeytoken.Finding(p.cfg.Tokens[fe.token], fe.op, processInfo(fe.pid), now))
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
