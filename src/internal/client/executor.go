package client

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/fsutil"
	"susanoo/internal/pki"
	"susanoo/internal/platform"
	"susanoo/internal/policy"
	"susanoo/internal/sign"
)

// Executor は CLIENT の執行部（C10）。特権が必要な働きと、端末の秘密鍵を受け持つ。
//
// 権限を分離しないときは Local をそのまま使う。分離するときは、root で動く執行部のプロセスの Local に、
// 非特権の解析部（Agent）から privsep でつなぐ。どちらでも、指示の署名の検証、ハートビートの中身、
// 署名の用途の制限は執行部が行うので、解析部を乗っ取られても隔離を解除したり、鍵を持ち出したりはできない。
type Executor interface {
	// Heartbeat は、執行部の状態（適用済みの指示、隔離、機能）を載せた署名付きのハートビートを作る。
	Heartbeat(ctx context.Context) (sign.Envelope, error)
	// Apply は CONTROLLER の署名付きの指示を検証し、適用済みより新しければ適用する。
	Apply(ctx context.Context, cmd sign.Envelope) error
	// SignTLS は TLS 1.3 のクライアント認証（CertificateVerify）の署名を作る。ほかの用途には署名しない。
	SignTLS(ctx context.Context, message []byte) ([]byte, error)
	// RenewCert は、CONTROLLER から受け取った更新した証明書の連なり（DER。先頭が端末の証明書）を確かめて保存する（M1）。
	RenewCert(ctx context.Context, chain [][]byte) error
	// Watch は検知したイベントを out に送り続け、ctx が終わったら返る。
	Watch(ctx context.Context, out chan<- event.Event) error
	// NextEvidence は、まだ CONTROLLER に受け取られていない最も古い証拠（署名付き）と、その ID を返す（C11）。
	NextEvidence(ctx context.Context) (id string, env sign.Envelope, ok bool, err error)
	// AckEvidence は、証拠 id が CONTROLLER に受け取られたことを記録する。
	AckEvidence(ctx context.Context, id string) error
}

// ErrExecutorStopped は、別のプロセスの執行部とのつながりが切れたことを表す。解析部はこれを受け取ったら止まる。
var ErrExecutorStopped = errors.New("client: 執行部とのつながりが切れました")

// LocalConfig は執行部の設定。
type LocalConfig struct {
	Cert          tls.Certificate   // 端末の証明書と秘密鍵（ed25519）
	CA            *x509.CertPool    // 内部の認証局。更新した証明書を確かめる。nil なら更新を受け付けない
	CertPath      string            // 更新した証明書を保存するファイル。空なら保存しない
	CommandKey    ed25519.PublicKey // CONTROLLER の指示を検証する公開鍵
	StateDir      string            // 適用した指示を記録するディレクトリ
	Controller    netip.AddrPort    // 隔離中も許可する管理通信の宛先
	CheckInterval time.Duration     // 自己隔離のルールが消されていないかを確かめる間隔。既定 DefaultHeartbeatInterval
	Platform      platform.Platform
	Logger        *slog.Logger
	Now           func() time.Time
}

// state は適用した指示。
type state struct {
	Version   uint64                `json:"version"`
	Isolation policy.IsolationLevel `json:"isolation,omitempty"` // 適用した自己隔離
	Updates   []netip.Prefix        `json:"updates,omitempty"`
	Commanded policy.IsolationLevel `json:"commanded,omitempty"` // 指示された隔離（自己隔離を使えない端末でも記録する。証拠を集めるきっかけの判断に使う）
	Evidence  uint64                `json:"evidence,omitempty"`  // 応えた証拠の要求の番号
	Apps      *policy.AppControl    `json:"apps,omitempty"`      // 指示されたプロセス単位の通信の制御（C7）
}

// Local は同じプロセスで動く執行部。
type Local struct {
	cfg      LocalConfig
	log      *slog.Logger
	id       pki.Identity
	leaf     *x509.Certificate // 今の証明書（mu で守る）
	key      ed25519.PrivateKey
	signer   *sign.Signer
	verifier *sign.Verifier
	bootID   string
	hostname string

	mu      sync.Mutex // 状態と自己隔離の操作を守る
	state   state
	counter uint64

	collectMu sync.Mutex // 証拠は 1 つずつ集める
	fileMu    sync.Mutex // 証拠のファイルを守る
}

var _ Executor = (*Local)(nil)

// NewLocal は証明書から端末 ID を読み、前回の状態を読み込んで執行部を作る。
func NewLocal(cfg LocalConfig) (*Local, error) {
	if cfg.Platform == nil || !cfg.Controller.IsValid() {
		return nil, errors.New("client: CONTROLLER のアドレスと Platform は必須です")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = DefaultHeartbeatInterval
	}
	id, leaf, err := identity(cfg.Cert.Certificate)
	if err != nil {
		return nil, err
	}
	key, ok := cfg.Cert.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("client: 端末の秘密鍵が ed25519 ではありません")
	}
	signer, err := sign.NewSigner(key)
	if err != nil {
		return nil, err
	}
	verifier, err := sign.NewVerifier(cfg.CommandKey)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	st, err := loadState(statePath(cfg.StateDir))
	if err != nil {
		return nil, err
	}
	if st.Commanded == "" {
		st.Commanded = st.Isolation // 証拠の保全より前の状態ファイル
	}
	hostname, _ := os.Hostname()
	return &Local{
		cfg: cfg, log: cfg.Logger.With("端末", id.ID), id: id, leaf: leaf, key: key, signer: signer, verifier: verifier,
		bootID: rand.Text(), hostname: hostname, state: st,
	}, nil
}

// ID は端末 ID を返す。
func (l *Local) ID() string { return l.id.ID }

// Restore は起動時に、前回の指示に従って隔離をかけ直す。隔離していなければ、前回の解除の途中で
// 止まった場合に備えて、残っている隔離のルールを消す。
func (l *Local) Restore(ctx context.Context) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state.Isolation != "" {
		if err := l.isolate(ctx); err != nil {
			l.log.Error("前回の隔離を適用し直せません", "エラー", err)
		} else {
			l.log.Warn("前回の指示に従って、隔離を続けます", "段階", l.state.Isolation)
		}
	} else if l.cfg.Platform.Capabilities().Has(platform.CapIsolation) {
		if err := l.cfg.Platform.Release(ctx); err != nil {
			l.log.Warn("残っている隔離のルールを消せません", "エラー", err)
		}
	}
	if l.state.Apps != nil {
		if err := l.setApps(ctx, l.state.Apps); err != nil {
			l.log.Error("前回のプロセス単位の通信の制御を適用し直せません", "エラー", err)
		} else {
			l.log.Info("前回の指示に従って、プロセス単位の通信の制御を続けます", "扱い", l.state.Apps.Mode)
		}
	}
}

// setApps はプロセス単位の通信の制御を Platform に渡す（C7）。使えない端末では何もしない。
func (l *Local) setApps(ctx context.Context, ac *policy.AppControl) error {
	fw, ok := l.cfg.Platform.(platform.AppFirewall)
	if !ok || !l.cfg.Platform.Capabilities().Has(platform.CapAppControl) {
		if ac != nil {
			l.log.Warn("この端末ではプロセス単位の通信の制御を使えません（GW の外部通信の制御だけが効きます）")
		}
		return nil
	}
	// CONTROLLER（と同居する GW の DNS）への通信は制御しない（指示を受け取れなくならないように）。
	return fw.SetAppControl(ctx, ac, []netip.Addr{l.cfg.Controller.Addr()})
}

// appControlMode は、今効いているプロセス単位の通信の制御の扱いを返す（効いていなければ空）。l.mu を持って呼ぶ。
func (l *Local) appControlMode() policy.AppMode {
	if l.state.Apps == nil || !l.cfg.Platform.Capabilities().Has(platform.CapAppControl) {
		return ""
	}
	return l.state.Apps.Mode
}

// sameApps は 2 つのプロセス単位の通信の制御が同じかを返す。
func sameApps(a, b *policy.AppControl) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// Heartbeat は署名付きのハートビートを作る。状態の項目は執行部が自分の状態で埋める。
func (l *Local) Heartbeat(context.Context) (sign.Envelope, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.counter++
	payload, err := json.Marshal(api.Heartbeat{
		DeviceID:     l.id.ID,
		BootID:       l.bootID,
		Counter:      l.counter,
		Time:         l.cfg.Now().UTC(),
		Hostname:     l.hostname,
		Applied:      l.state.Version,
		Isolation:    l.state.Isolation,
		AppControl:   l.appControlMode(),
		Capabilities: l.cfg.Platform.Capabilities(),
	})
	if err != nil {
		return sign.Envelope{}, err
	}
	return l.signer.Sign(sign.PurposeHeartbeat, payload), nil
}

// Apply は指示を検証し、新しい指示なら適用する。
func (l *Local) Apply(ctx context.Context, env sign.Envelope) error {
	payload, err := l.verifier.Verify(sign.PurposeCommand, env)
	if err != nil {
		return fmt.Errorf("指示の署名を検証できません: %w", err)
	}
	var cmd api.Command
	if err := json.Unmarshal(payload, &cmd); err != nil {
		return fmt.Errorf("指示を解析できません: %w", err)
	}
	if cmd.DeviceID != l.id.ID {
		return fmt.Errorf("ほかの端末（%s）への指示です", cmd.DeviceID)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if cmd.Version <= l.state.Version {
		return nil
	}
	prev := l.state
	// 証拠は、隔離されたときと、管理者が求めたときに集める（C11）。
	collect := ""
	switch {
	case cmd.Isolation != "" && prev.Commanded == "":
		collect = api.EvidenceReasonIsolation
	case cmd.Evidence > prev.Evidence:
		collect = api.EvidenceReasonRequest
	}
	next := state{Version: cmd.Version, Isolation: cmd.Isolation, Updates: cmd.Updates, Commanded: cmd.Isolation, Evidence: max(prev.Evidence, cmd.Evidence), Apps: cmd.Apps}
	// プロセス単位の通信の制御（C7）は、隔離より先に適用する。失敗したら何も変えずにエラーを返し、次の応答で試し直す。
	appsChanged := !sameApps(prev.Apps, cmd.Apps)
	if appsChanged {
		if err := l.setApps(ctx, cmd.Apps); err != nil {
			return fmt.Errorf("指示（プロセス単位の通信の制御）を適用できません: %w", err)
		}
		if cmd.Apps == nil {
			l.log.Info("指示に従って、プロセス単位の通信の制御をやめました")
		} else {
			l.log.Info("指示に従って、プロセス単位の通信の制御を適用しました", "扱い", cmd.Apps.Mode, "既定", cmd.Apps.Default, "ルール", len(cmd.Apps.Rules))
		}
	}
	if !l.cfg.Platform.Capabilities().Has(platform.CapIsolation) {
		// 自己隔離を使えない端末は、GW の遮断だけで隔離される。指示の版数だけを記録する。
		l.state = state{Version: cmd.Version, Commanded: next.Commanded, Evidence: next.Evidence, Apps: next.Apps}
		l.save()
		if cmd.Isolation != "" && prev.Commanded == "" {
			l.log.Warn("この端末では自己隔離を使えません。GW の遮断で隔離されます", "段階", cmd.Isolation)
		}
		l.startCollect(collect, cmd.Version, cmd.Isolation)
		return nil
	}
	l.state = next
	changed := cmd.Isolation != prev.Isolation || !slices.Equal(cmd.Updates, prev.Updates)
	switch {
	case !changed: // 隔離は変わらない（証拠の要求など）
	case cmd.Isolation == "":
		err = l.cfg.Platform.Release(ctx)
	default:
		err = l.isolate(ctx)
	}
	if err != nil {
		l.state = prev
		if appsChanged {
			l.setApps(ctx, prev.Apps) // 先に適用したプロセス単位の通信の制御も戻す
		}
		return fmt.Errorf("指示（隔離 %q）を適用できません: %w", cmd.Isolation, err)
	}
	l.save()
	switch {
	case !changed:
	case cmd.Isolation == "":
		l.log.Info("指示に従って、隔離を解除しました")
	default:
		l.log.Warn("指示に従って、自己隔離しました", "段階", cmd.Isolation)
	}
	l.startCollect(collect, cmd.Version, cmd.Isolation)
	return nil
}

// tlsClientContext は TLS 1.3 のクライアントの CertificateVerify の署名の対象に含まれる文脈の文字列（RFC 8446 4.4.3）。
const tlsClientContext = "TLS 1.3, client CertificateVerify\x00"

// SignTLS は TLS 1.3 のクライアント認証の署名を作る。署名の対象は「0x20 が 64 バイト、文脈の文字列、
// ハンドシェイクのハッシュ（SHA-256 か SHA-384）」の形に限る。
func (l *Local) SignTLS(_ context.Context, message []byte) ([]byte, error) {
	n := len(message) - 64 - len(tlsClientContext)
	if (n != 32 && n != 48) || strings.Trim(string(message[:64]), " ") != "" || string(message[64:64+len(tlsClientContext)]) != tlsClientContext {
		return nil, errors.New("client: TLS 1.3 のクライアント認証でない署名の要求です")
	}
	return ed25519.Sign(l.key, message), nil
}

// RenewCert は、更新した証明書が内部の認証局の発行したもので、持ち主（端末 ID）と鍵が今の証明書と同じで、
// 期限が今の証明書より先であることを確かめてから、保存して使い始める。
func (l *Local) RenewCert(_ context.Context, chainDER [][]byte) error {
	if l.cfg.CA == nil {
		return errors.New("client: 認証局がないため、更新した証明書を確かめられません")
	}
	if len(chainDER) == 0 || len(chainDER) > 4 {
		return errors.New("client: 更新した証明書の連なりが不正です")
	}
	var chain []*x509.Certificate
	inter := x509.NewCertPool()
	for i, der := range chainDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("client: 更新した証明書を解析できません: %w", err)
		}
		chain = append(chain, c)
		if i > 0 {
			inter.AddCert(c)
		}
	}
	cert := chain[0]
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: l.cfg.CA, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: l.cfg.Now(),
	}); err != nil {
		return fmt.Errorf("client: 更新した証明書を検証できません: %w", err)
	}
	if id, err := pki.IdentityFromCert(cert); err != nil || id != l.id {
		return fmt.Errorf("client: 更新した証明書の持ち主が違います（%v）", id)
	}
	if pub, ok := cert.PublicKey.(ed25519.PublicKey); !ok || !pub.Equal(l.key.Public()) {
		return errors.New("client: 更新した証明書の鍵が端末の鍵と違います")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !cert.NotAfter.After(l.leaf.NotAfter) {
		return errors.New("client: 更新した証明書の期限が今の証明書より先ではありません")
	}
	if l.cfg.CertPath != "" {
		if err := pki.WriteChainFile(l.cfg.CertPath, chain...); err != nil {
			return err
		}
	}
	l.leaf = cert
	l.log.Info("端末の証明書を更新しました", "期限", cert.NotAfter.Local().Format(time.DateTime))
	return nil
}

// Watch は Platform のイベントを送り、自己隔離のルールが消されていないかを定期的に確かめる（C10）。
// Platform の監視が止まっても、確認は続ける。
func (l *Local) Watch(ctx context.Context, out chan<- event.Event) error {
	errc := make(chan error, 1)
	go func() { errc <- l.cfg.Platform.Watch(ctx, out) }()
	t := time.NewTicker(l.cfg.CheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if errc != nil {
				<-errc
			}
			return ctx.Err()
		case err := <-errc:
			errc = nil
			if ctx.Err() == nil {
				l.log.Error("検知の仕組みが止まりました。自己隔離の確認とハートビートは続けます", "エラー", err)
			}
		case <-t.C:
			if e := l.checkTamper(ctx); e != nil {
				select {
				case out <- *e:
				case <-ctx.Done():
				}
			}
		}
	}
}

// checkTamper は、隔離中に自己隔離のルールが消されていないかを確かめる。消されていたら入れ直し、
// 改ざんの検知結果を返す。
func (l *Local) checkTamper(ctx context.Context) *event.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state.Isolation == "" || !l.cfg.Platform.Capabilities().Has(platform.CapIsolation) {
		return nil
	}
	active, err := l.cfg.Platform.IsolationActive(ctx)
	if err != nil || active {
		return nil
	}
	l.log.Error("自己隔離のルールが消されていました。入れ直します")
	if err := l.isolate(ctx); err != nil {
		l.log.Error("自己隔離のルールを入れ直せません", "エラー", err)
	}
	msg := "隔離中に自己隔離のルールが消されていたため、入れ直しました。管理者の権限を奪われている恐れがあります"
	e := event.New(event.ClassDetectionFinding, event.FindingCreate, event.SeverityHigh, l.cfg.Now())
	e.Message = msg
	e.FindingInfo = &event.FindingInfo{UID: rand.Text(), Title: "防御の仕組みの改ざん", Desc: msg, Types: []string{event.FindingTypeTamper}}
	e.Device = &event.Device{Hostname: l.hostname}
	return e
}

// isolate は今の状態の隔離を適用する。l.mu を持って呼ぶ。
func (l *Local) isolate(ctx context.Context) error {
	return l.cfg.Platform.Isolate(ctx, platform.Isolation{
		Level:      l.state.Isolation,
		Management: []netip.AddrPort{l.cfg.Controller},
		Updates:    l.state.Updates,
	})
}

// save は状態を記録する。l.mu を持って呼ぶ。
func (l *Local) save() {
	if err := saveState(statePath(l.cfg.StateDir), l.state); err != nil {
		l.log.Error("適用した指示を記録できません", "エラー", err)
	}
}

// identity は証明書の連なりの先頭から端末 ID を読む。CLIENT の証明書でなければエラーを返す。
func identity(chain [][]byte) (pki.Identity, *x509.Certificate, error) {
	if len(chain) == 0 {
		return pki.Identity{}, nil, errors.New("client: 端末の証明書がありません")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return pki.Identity{}, nil, err
	}
	id, err := pki.IdentityFromCert(leaf)
	if err != nil {
		return pki.Identity{}, nil, err
	}
	if id.Role != pki.RoleClient {
		return pki.Identity{}, nil, fmt.Errorf("client: 端末の証明書ではありません（役割 %q）", id.Role)
	}
	return id, leaf, nil
}

// executorSigner は TLS のクライアント認証の署名を執行部に頼む crypto.Signer。
type executorSigner struct {
	pub ed25519.PublicKey
	ex  Executor
}

func (s executorSigner) Public() crypto.PublicKey { return s.pub }

func (s executorSigner) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("client: ed25519 の署名はハッシュを使いません")
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	return s.ex.SignTLS(ctx, message)
}

func statePath(dir string) string { return filepath.Join(dir, "state.json") }

func loadState(path string) (state, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return state{}, nil
	}
	if err != nil {
		return state{}, err
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return state{}, fmt.Errorf("client: 状態ファイル %s を解析できません: %w", path, err)
	}
	return s, nil
}

func saveState(path string, s state) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, append(data, '\n'), 0o600)
}
