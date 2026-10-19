package main

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"susanoo/internal/client"
	"susanoo/internal/config"
	"susanoo/internal/honeytoken"
	"susanoo/internal/keys"
	"susanoo/internal/nft"
	"susanoo/internal/platform/linux"
	"susanoo/internal/privsep"
)

// clientConfig は CLIENT モードの設定ファイル。相対パスは設定ファイルのあるディレクトリから数える。
type clientConfig struct {
	Controller        string            `json:"controller"`           // CONTROLLER のアドレスとポート
	PKIDir            string            `json:"pki_dir"`              // 端末の鍵と証明書のディレクトリ
	StateDir          string            `json:"state_dir"`            // 適用した指示とおとりの記録の保存先
	HeartbeatInterval config.Duration   `json:"heartbeat_interval"`   // 既定 5s
	Honeytokens       []honeytoken.Spec `json:"honeytokens"`          // 置くおとり
	NFT               string            `json:"nft"`                  // nft コマンドの場所。既定 /usr/sbin/nft
	Isolation         *bool             `json:"isolation"`            // false なら自己隔離しない。既定 true
	ProcessMonitor    *bool             `json:"process_monitor"`      // プロセスの監視（C1）。既定 true
	ConnectionMonitor *bool             `json:"connection_monitor"`   // 通信とプロセスの結び付け（C2）。既定 true
	Files             *fileConfig       `json:"files"`                // ファイルの監視（C3、C4、C8、C9）。省略すると既定の場所を監視する
	KernelModules     *bool             `json:"kernel_modules"`       // カーネルモジュールの読み込みの検知（C4）。既定 true
	Logons            *logonConfig      `json:"logons"`               // ログオンの記録（C4）。省略すると既定の情報源を使う
	Agents            []linux.AgentSpec `json:"agents"`               // 見分ける AI エージェント（C9）。省略すると既定の一覧、空（[]）なら見分けない
	Evidence          *evidenceConfig   `json:"evidence"`             // 証拠の保全（C11）
	AppControl        *bool             `json:"app_control"`          // プロセス単位の通信の制御（C7。ルールはポリシーのグループの apps）。既定 true
	Separation        *bool             `json:"privilege_separation"` // 権限の分離（C10）。既定 true（root で動かすとき）
	User              string            `json:"analyzer_user"`        // 解析部を動かす利用者。既定 nobody
	Resources         *resourceConfig   `json:"resources"`            // 資源の上限（2l）
}

// resourceConfig は CLIENT の資源の上限。超えたら監視を間引き、検知結果を送る。CPU とメモリを確実に抑えるには、
// systemd のユニットの CPUQuota と MemoryMax も使う（このプロセスの上限は、間引いて使用量を下げるためのもの）。
type resourceConfig struct {
	CPUPercent int `json:"cpu_percent"` // CPU の使用率の上限（1 つの CPU を使い切ると 100）。既定 10
	MemoryMB   int `json:"memory_mb"`   // 実メモリの上限（MiB。執行部、解析部、その子の合計）。既定 256
}

// 資源の上限の既定値と範囲。
const (
	defaultCPUPercent = 10
	defaultMemoryMB   = 256
	maxCPUPercent     = 1000
	minMemoryMB       = 8
	maxMemoryMB       = 65536
	minGoMemoryLimit  = 32 << 20 // Go のメモリの回収の目安の下限（小さすぎると回収ばかりして CPU を使う）
)

// resourceLimits は設定ファイルの resources を、CPU の使用率の上限とメモリの上限（バイト）にする。
func resourceLimits(r *resourceConfig) (float64, int64, error) {
	cpu, mem := defaultCPUPercent, defaultMemoryMB
	if r != nil {
		cpu, mem = cmp.Or(r.CPUPercent, cpu), cmp.Or(r.MemoryMB, mem)
	}
	if cpu < 1 || cpu > maxCPUPercent {
		return 0, 0, fmt.Errorf("resources.cpu_percent は 1〜%d で書いてください", maxCPUPercent)
	}
	if mem < minMemoryMB || mem > maxMemoryMB {
		return 0, 0, fmt.Errorf("resources.memory_mb は %d〜%d で書いてください", minMemoryMB, maxMemoryMB)
	}
	return float64(cpu), int64(mem) << 20, nil
}

// goMemoryLimit は、メモリの上限から、執行部と解析部のそれぞれの Go のメモリの回収の目安を決める（上限の半分）。
func goMemoryLimit(limit int64) int64 { return max(limit/2, minGoMemoryLimit) }

// defaultAnalyzerUser は解析部を動かす既定の利用者。専用の利用者（susanoo など）を作って指定するのが望ましい。
const defaultAnalyzerUser = "nobody"

// evidenceConfig は証拠の保全の設定。
type evidenceConfig struct {
	Logs []string `json:"logs"` // 末尾を集めるログ（絶対パス）。省略すると既定の場所、空（[]）なら集めない
}

// logonConfig はログオンの記録の設定。
type logonConfig struct {
	Enabled     *bool    `json:"enabled"`      // 既定 true
	SessionsDir string   `json:"sessions_dir"` // systemd-logind のセッションのディレクトリ。既定 /run/systemd/sessions
	AuthLogs    []string `json:"auth_logs"`    // 失敗したログオンを読む認証のログ。省略すると既定の場所、空（[]）なら読まない
	Journal     *bool    `json:"journal"`      // 認証のログのファイルがないとき journalctl でジャーナルを読む。既定 true
	Journalctl  string   `json:"journalctl"`   // journalctl の場所。既定 /usr/bin/journalctl
}

// logonSettings は設定ファイルの logons を Platform の設定にする。パスは絶対パスに限る。
func logonSettings(l *logonConfig) (linux.LogonConfig, error) {
	if l == nil {
		return linux.LogonConfig{Enabled: true, Journal: true}, nil
	}
	out := linux.LogonConfig{Enabled: l.Enabled == nil || *l.Enabled, SessionsDir: l.SessionsDir, AuthLogs: l.AuthLogs,
		Journal: l.Journal == nil || *l.Journal, Journalctl: l.Journalctl}
	for _, p := range append([]string{l.SessionsDir, l.Journalctl}, l.AuthLogs...) {
		if p != "" && !filepath.IsAbs(p) {
			return out, fmt.Errorf("logons のパス %q は絶対パスで書いてください", p)
		}
	}
	return out, nil
}

// fileConfig はファイルの監視の設定。各一覧は、省略すると既定の場所、空（[]）なら監視しない。
type fileConfig struct {
	Watch       []string              `json:"watch"`       // 重要な場所（ファイルかディレクトリ）。変更を記録する（C3）
	Persistence []string              `json:"persistence"` // 永続化の場所（自動起動、cron、サービスなど）。変更を検知結果にする（C4）
	Privilege   []string              `json:"privilege"`   // 権限の設定の場所（利用者、sudo、PAM など）。変更を検知結果にする（C4）
	Sensitive   []linux.SensitiveSpec `json:"sensitive"`   // 認証情報のファイルと、ふだん読むプログラム。それ以外の読み取りを検知結果にする（C8、C9）
	Protect     []string              `json:"protect"`     // 大量の変更を監視する場所（下の階層を含む）
	MassFiles   int                   `json:"mass_files"`  // 既定 200
	MassWindow  config.Duration       `json:"mass_window"` // 既定 30s
	Wide        []string              `json:"wide"`        // 守る場所の外の大量の変更を監視するファイルシステム（その上の場所）。省略すると /、/home、/srv
	WideFiles   int                   `json:"wide_files"`  // 守る場所の外で、この数以上の既存のファイルを書き換えるか消したら検知する。既定 1000
}

// fileSettings は設定ファイルの files を、省略した一覧に既定の場所を入れて、Platform の設定にする。
func fileSettings(f *fileConfig) linux.FileConfig {
	cfg := linux.FileConfig{
		Paths: linux.DefaultWatchPaths(), Persistence: linux.DefaultPersistencePaths(), Privilege: linux.DefaultPrivilegePaths(),
		Sensitive: linux.DefaultSensitive(), Protect: linux.DefaultProtectPaths(), Wide: linux.DefaultWidePaths(),
	}
	if f == nil {
		return cfg
	}
	if f.Watch != nil {
		cfg.Paths = f.Watch
	}
	if f.Persistence != nil {
		cfg.Persistence = f.Persistence
	}
	if f.Privilege != nil {
		cfg.Privilege = f.Privilege
	}
	if f.Sensitive != nil {
		cfg.Sensitive = f.Sensitive
	}
	if f.Protect != nil {
		cfg.Protect = f.Protect
	}
	if f.Wide != nil {
		cfg.Wide = f.Wide
	}
	cfg.WideFiles = f.WideFiles
	cfg.MassFiles, cfg.MassWindow = f.MassFiles, f.MassWindow.Or(0)
	return cfg
}

// check は、設定の中身だけで分かる誤り（ファイルを使わずに確かめられるもの）を返す。CLIENT の起動のときと、
// Web コンソールで保存する前に使う。
func (cfg *clientConfig) check() error {
	if _, err := netip.ParseAddrPort(cfg.Controller); err != nil {
		return fmt.Errorf("controller %q はアドレスとポート（例: 192.168.10.1:8443）で書いてください", cfg.Controller)
	}
	if cfg.PKIDir == "" || cfg.StateDir == "" {
		return errors.New("pki_dir と state_dir は必須です")
	}
	if _, _, err := resourceLimits(cfg.Resources); err != nil {
		return err
	}
	if _, err := logonSettings(cfg.Logons); err != nil {
		return err
	}
	for _, h := range cfg.Honeytokens {
		if !filepath.IsAbs(h.Path) {
			return fmt.Errorf("honeytokens の %q は絶対パスで書いてください", h.Path)
		}
		if _, err := honeytoken.Generate(h.Kind); err != nil {
			return fmt.Errorf("honeytokens の %s: %w", h.Path, err)
		}
	}
	return nil
}

func runClient(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("client", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "/etc/susanoo/client.json", "設定ファイル")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	var cfg clientConfig
	if err := config.Load(*path, &cfg); err != nil {
		return fail(stderr, err)
	}
	if err := cfg.check(); err != nil {
		return fail(stderr, err)
	}
	pkiDir := config.Resolve(*path, cfg.PKIDir)
	stateDir := config.Resolve(*path, cfg.StateDir)
	addr, _ := netip.ParseAddrPort(cfg.Controller) // check で確かめてある
	ca, err := loadCA(pkiDir)
	if err != nil {
		return fail(stderr, err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	cert, err := loadLeaf(pkiDir, fileClientCert, fileClientKey)
	if err != nil {
		return fail(stderr, err)
	}
	releaseKey, err := loadReleaseKey(pkiDir)
	if err != nil {
		return fail(stderr, err)
	}
	commandKey, err := loadCommandKey(pkiDir)
	if err != nil {
		return fail(stderr, err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fail(stderr, err)
	}

	log := newLogger(stderr)
	tokens, warnings, err := honeytoken.Plant(cfg.Honeytokens, filepath.Join(stateDir, "honeytokens.json"), time.Now())
	if err != nil {
		return fail(stderr, err)
	}
	for _, w := range warnings {
		log.Warn(w.Error())
	}
	logons, err := logonSettings(cfg.Logons)
	if err != nil {
		return fail(stderr, err)
	}
	cpuLimit, memLimit, _ := resourceLimits(cfg.Resources) // check で確かめてある
	debug.SetMemoryLimit(goMemoryLimit(memLimit))
	pcfg := linux.Config{
		Logons:        logons,
		Tokens:        tokens,
		ProcessEvents: cfg.ProcessMonitor == nil || *cfg.ProcessMonitor,
		NetworkEvents: cfg.ConnectionMonitor == nil || *cfg.ConnectionMonitor,
		Files:         fileSettings(cfg.Files),
		KernelModules: cfg.KernelModules == nil || *cfg.KernelModules,
		Agents:        cfg.Agents,
		AppControl:    cfg.AppControl == nil || *cfg.AppControl,
		Logger:        log,
	}
	if cfg.Evidence != nil {
		pcfg.EvidenceLogs = cfg.Evidence.Logs
	}
	if cfg.Isolation == nil || *cfg.Isolation {
		pcfg.NFT = nft.Command{Path: cfg.NFT}
	}
	separate := cfg.Separation == nil || *cfg.Separation
	if separate && os.Geteuid() != 0 {
		log.Warn("root でないため、権限を分離せずに 1 つのプロセスで動きます")
		separate = false
	}
	if separate {
		log = log.With("役割", "執行部")
		pcfg.Logger = log
	}
	p := linux.New(pcfg)

	interval := cfg.HeartbeatInterval.Or(client.DefaultHeartbeatInterval)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var updatedTo atomic.Value  // 入れ替えたリリースの版数
	var restartFor atomic.Value // 起動し直す理由（認証局の証明書の更新）
	local, err := client.NewLocal(client.LocalConfig{
		ReleaseKey:    releaseKey,
		OnUpdate:      func(v string) { updatedTo.Store(v); cancel() },
		OnRestart:     func(reason string) { restartFor.Store(reason); cancel() },
		Cert:          cert,
		CA:            pool,
		CACert:        ca,
		CAPath:        filepath.Join(pkiDir, fileCACert),
		CertPath:      filepath.Join(pkiDir, fileClientCert), // 更新した証明書で置き換える（M1）
		CommandKey:    commandKey,
		StateDir:      stateDir,
		Controller:    addr,
		CheckInterval: interval,
		Platform:      p,
		Logger:        log,
		CPULimit:      cpuLimit,
		MemoryLimit:   memLimit,
	})
	if err != nil {
		return fail(stderr, err)
	}
	log.Info("CLIENT モードで起動しました", "端末", local.ID(), "機能", p.Capabilities().Features, "おとり", len(tokens))
	local.Restore(ctx)

	if separate {
		hello := privsep.Hello{Controller: addr.String(), CA: [][]byte{ca.Raw}, Chain: cert.Certificate, HeartbeatInterval: interval,
			MemoryLimit: goMemoryLimit(memLimit)}
		err = runExecutor(ctx, local, hello, cmp.Or(cfg.User, defaultAnalyzerUser), log)
	} else {
		var agent *client.Agent
		agent, err = client.New(client.Config{
			Controller: addr, CA: pool, Chain: cert.Certificate, HeartbeatInterval: interval, Executor: local, Logger: log,
		})
		if err == nil {
			err = agent.Run(ctx)
		}
	}
	if v, ok := updatedTo.Load().(string); ok {
		log.Info("新しい版に入れ替えたので終わります。起動し直してください", "版数", v)
		return exitUpdated
	}
	if reason, ok := restartFor.Load().(string); ok {
		log.Info("起動し直すために終わります", "理由", reason)
		return exitUpdated
	}
	if err != nil {
		return fail(stderr, err)
	}
	log.Info("停止しました")
	return exitOK
}

// runExecutor は CLIENT の執行部（C10）。自分自身を利用者 user で起動し直して解析部とし、capability を
// 必要最小限まで手放してから、解析部の要求に応える。解析部が止まったらエラーを返す（systemd などで起動し直す前提）。
func runExecutor(ctx context.Context, local *client.Local, hello privsep.Hello, user string, log *slog.Logger) error {
	analyzer, conn, err := privsep.Spawn(user, nil, "client", "analyzer")
	if err != nil {
		return err
	}
	wait := func() {
		select {
		case <-analyzer.Exited:
		case <-time.After(5 * time.Second):
			log.Warn("解析部が終わりません", "PID", analyzer.Pid)
		}
	}
	if err := privsep.DropCapabilities(privsep.ExecutorCaps); err != nil {
		conn.Close()
		wait()
		return err
	}
	if err := privsep.Harden(); err != nil {
		conn.Close()
		wait()
		return err
	}
	log.Info("権限を分離しました", "解析部の PID", analyzer.Pid, "解析部の利用者", user)
	err = privsep.Serve(ctx, conn, local, hello, log)
	wait() // 解析部は、つながりが切れると終わる
	return err
}

// runAnalyzer は CLIENT の解析部（C10）。執行部が非特権の利用者で起動し、fd 3 でつなぐ。
// 設定ファイルや鍵は読まず、必要な情報は執行部から受け取る。執行部とのつながりが切れたら終わり、
// シグナルでは終わらない（止めるのは執行部）。
func runAnalyzer(stderr io.Writer) int {
	signal.Ignore(os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	log := newLogger(stderr).With("役割", "解析部")
	if os.Geteuid() == 0 {
		return fail(stderr, errors.New("解析部を root で動かすことはできません"))
	}
	if err := privsep.Harden(); err != nil {
		return fail(stderr, err)
	}
	if err := privsep.SetName("susanoo"); err != nil {
		log.Warn("プロセス名を付けられません", "エラー", err)
	}
	f, err := privsep.OpenConnFD()
	if err != nil {
		return fail(stderr, err)
	}
	remote, hello, err := privsep.Dial(f, log)
	if err != nil {
		return fail(stderr, err)
	}
	if hello.MemoryLimit > 0 {
		debug.SetMemoryLimit(hello.MemoryLimit)
	}
	addr, err := netip.ParseAddrPort(hello.Controller)
	if err != nil {
		return fail(stderr, err)
	}
	pool, err := hello.CertPool()
	if err != nil {
		return fail(stderr, err)
	}
	agent, err := client.New(client.Config{
		Controller: addr, CA: pool, Chain: hello.Chain, HeartbeatInterval: hello.HeartbeatInterval, Executor: remote, Logger: log,
	})
	if err != nil {
		return fail(stderr, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-remote.Done(); cancel() }()
	agent.Run(ctx)
	return exitOK
}

func runKeygen(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("client keygen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", "/etc/susanoo/client", "鍵を置くディレクトリ")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	keyPath := filepath.Join(*dir, fileClientKey)
	if _, err := os.Stat(keyPath); !errors.Is(err, fs.ErrNotExist) {
		return fail(stderr, fmt.Errorf("%s が既にあります。作り直す場合は先に消してください", keyPath))
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return fail(stderr, err)
	}
	priv, err := keys.Generate()
	if err != nil {
		return fail(stderr, err)
	}
	if err := keys.SavePrivate(keyPath, priv); err != nil {
		return fail(stderr, err)
	}
	pubPath := filepath.Join(*dir, fileClientPub)
	if err := keys.SavePublic(pubPath, priv.Public().(ed25519.PublicKey)); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "端末の鍵を作りました。\n次に %s を CONTROLLER に渡し、「susanoo ctl issue」で証明書を発行してください"+
		"（登録コードを使うときは、keygen は要らず「susanoo client enroll」だけで済みます）。\n", pubPath)
	return exitOK
}
