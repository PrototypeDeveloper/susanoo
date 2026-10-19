package main

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"susanoo/internal/config"
	"susanoo/internal/controller"
	"susanoo/internal/dhcp"
	"susanoo/internal/dns"
	"susanoo/internal/egress"
	"susanoo/internal/flow"
	"susanoo/internal/gw"
	"susanoo/internal/intel"
	"susanoo/internal/keys"
	"susanoo/internal/nft"
	"susanoo/internal/notify"
	"susanoo/internal/pki"
	"susanoo/internal/platform/linux"
	"susanoo/internal/policy"
	"susanoo/internal/privsep"
	"susanoo/internal/sign"
)

// gwConfig は GW モードの設定ファイル。相対パスは設定ファイルのあるディレクトリから数える。
type gwConfig struct {
	Listen           string          `json:"listen"`               // 管理通信の待ち受けアドレス（LAN 側のアドレスとポート）
	PKIDir           string          `json:"pki_dir"`              // ctl init で作ったディレクトリ
	StateDir         string          `json:"state_dir"`            // 台帳、監査ログ、イベントの保存先
	Policy           string          `json:"policy"`               // ポリシーのファイル
	HeartbeatTimeout config.Duration `json:"heartbeat_timeout"`    // 既定 30s
	MaxClockSkew     config.Duration `json:"max_clock_skew"`       // 端末の時刻のずれの上限。既定 2m
	NFT              string          `json:"nft"`                  // nft コマンドの場所。既定 /usr/sbin/nft
	Enforce          *bool           `json:"enforce"`              // false なら GW で遮断しない。既定 true
	Router           *routerConfig   `json:"router"`               // ルーター方式（G1）。省略すると転送と NAT を設定しない
	Bridge           *bridgeConfig   `json:"bridge"`               // ブリッジ方式（G1）。router と一緒には使えない
	DHCP             *dhcpConfig     `json:"dhcp"`                 // DHCP サーバー（G8）。router が必要
	DNS              *dnsConfig      `json:"dns"`                  // DNS リゾルバ（G3）。router が必要
	FlowLog          *bool           `json:"flow_log"`             // 通信の記録（G5）。router が必要。既定 true
	Separation       *bool           `json:"privilege_separation"` // 権限の分離（G12）。既定 true（root で動かすとき）
	ControllerUser   string          `json:"controller_user"`      // CONTROLLER を動かす利用者。既定 susanoo-ctl
	LANUser          string          `json:"lan_user"`             // LAN 側の処理を動かす利用者。既定 susanoo-net
	Notify           *notify.Config  `json:"notify"`               // 管理者への通知（M7）。宛先の URL やパスワードを含むので、このファイルは root だけが読めるようにする
}

type dnsConfig struct {
	Upstreams  []upstreamConfig `json:"upstreams"`   // 上流の DNS サーバー。順に問い合わせる
	LogQueries *bool            `json:"log_queries"` // 問い合わせを記録する。既定 true
}

type upstreamConfig struct {
	Address string `json:"address"`  // アドレスとポート（例: 192.168.0.1:53、DoT なら 203.0.113.53:853）
	TLSName string `json:"tls_name"` // DNS over TLS で証明書を確かめる名前。空なら平文
}

type routerConfig struct {
	LAN        string    `json:"lan"`         // LAN 側のインターフェース
	WAN        string    `json:"wan"`         // WAN 側のインターフェース
	WANDHCP    bool      `json:"wan_dhcp"`    // WAN 側のアドレスを DHCP で得る
	AdminPorts *[]uint16 `json:"admin_ports"` // LAN から受け付ける管理用のポート。既定 [22]
	// TrustedRouters は、LAN のルーター（や DHCPv6 のサーバー）として認める機器の MAC アドレス。その RA と DHCPv6 を不正としない。
	TrustedRouters []string        `json:"trusted_routers"`
	NDProbe        config.Duration `json:"nd_probe_interval"` // ルーター要請と DHCPv6 の問い合わせで、不正なルーターとサーバーを探す間隔。既定 5m
	// IPv6 は LAN の IPv6 を転送する（LAN 側のインターフェースに設定した /64 の IPv6 アドレスのネットワークを RA で知らせ、
	// WAN 側のアドレスに変換して送り出す）。既定 false（LAN の IPv6 の転送を遮断する）。
	IPv6       bool            `json:"ipv6"`
	RAInterval config.Duration `json:"ra_interval"` // GW のルーター広告の間隔。既定 200s
}

// defaultRAInterval は GW のルーター広告の既定の間隔。端末のルーター要請には、間隔によらずすぐに答える。
const defaultRAInterval = 200 * time.Second

// listenDNS6 は GW の LAN 側の IPv6 アドレスで DNS を待ち受ける。起動の直後はアドレスの重複の確認が終わっておらず
// 使えない（EADDRNOTAVAIL）ことがあるので、10 秒まで待ってやり直す。
func listenDNS6(ctx context.Context, addr netip.Addr) (net.PacketConn, net.Listener, error) {
	deadline := time.Now().Add(10 * time.Second)
	for {
		pc, tl, err := dns.Listen(addr, 0)
		if err == nil || !errors.Is(err, syscall.EADDRNOTAVAIL) || time.Now().After(deadline) {
			return pc, tl, err
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// lanIPv6 は、IPv6 を転送するときに LAN に知らせる GW の IPv6 アドレスとネットワークを返す（SLAAC のため /64 に限る）。
func lanIPv6(lan string) (netip.Addr, netip.Prefix, error) {
	addr, prefix, err := gw.InterfacePrefix6(lan)
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, fmt.Errorf("router.ipv6 には、LAN 側のインターフェースに /64 の IPv6 アドレス（ULA など）が必要です: %w", err)
	}
	if prefix.Bits() != 64 {
		return netip.Addr{}, netip.Prefix{}, fmt.Errorf("router.ipv6 には、LAN 側の IPv6 アドレスのネットワークを /64 にしてください（%s）", prefix)
	}
	return addr, prefix, nil
}

// bridgeConfig はブリッジ方式（G1）の設定。GW は上流のルーターと LAN の間に透過のブリッジとして入り、アドレスの変換と DHCP は
// 上流のルーターに任せる。ブリッジとポートの装置は管理者が用意する（ブリッジに GW のアドレスを設定する）。
type bridgeConfig struct {
	Name           string          `json:"name"`              // ブリッジの装置（例 br0）。GW の管理通信のアドレスを持つ
	LAN            string          `json:"lan"`               // LAN 側のポート
	WAN            string          `json:"wan"`               // 上流のルーター側のポート
	Gateway        string          `json:"gateway"`           // 上流のルーターのアドレス（なりすましを検知する）。省略するとブリッジの既定の経路から
	WANDHCP        bool            `json:"wan_dhcp"`          // ブリッジのアドレスを上流の DHCP で得る
	AdminPorts     *[]uint16       `json:"admin_ports"`       // LAN から受け付ける管理用のポート。既定 [22]
	TrustedRouters []string        `json:"trusted_routers"`   // LAN にいてよいルーターの MAC アドレス（その RA と DHCPv6 を不正としない）
	NDProbe        config.Duration `json:"nd_probe_interval"` // 不正なルーターと DHCPv6 のサーバーを探す間隔。既定 5m
}

// lanSide は、GW の LAN の側の装置と方式（ルーター方式かブリッジ方式か）をまとめる。
type lanSide struct {
	Port      string     // ARP と近隣探索を監視し、外部通信の制御で LAN とみなす装置（ルーター方式の LAN、ブリッジの LAN 側のポート）
	AddrIface string     // GW のアドレスを持つ装置（ルーター方式の LAN、ブリッジ）
	Family    nft.Family // nftables のテーブルの種類
	Router    *routerConfig
	Bridge    *bridgeConfig
}

// lanSide は LAN の側の設定を返す。ルーター方式でもブリッジ方式でもなければ nil。
func (c gwConfig) lanSide() *lanSide {
	switch {
	case c.Router != nil:
		return &lanSide{Port: c.Router.LAN, AddrIface: c.Router.LAN, Family: nft.Inet, Router: c.Router}
	case c.Bridge != nil:
		return &lanSide{Port: c.Bridge.LAN, AddrIface: c.Bridge.Name, Family: nft.Bridge, Bridge: c.Bridge}
	}
	return nil
}

func (s *lanSide) trustedRouters() ([]string, error) {
	var macs []string
	what := "router"
	if s.Router != nil {
		macs = s.Router.TrustedRouters
	} else {
		macs, what = s.Bridge.TrustedRouters, "bridge"
	}
	var out []string
	for _, m := range macs {
		hw, err := net.ParseMAC(m)
		if err != nil || len(hw) != 6 {
			return nil, fmt.Errorf("%s.trusted_routers の %q は MAC アドレスで書いてください", what, m)
		}
		out = append(out, hw.String())
	}
	return out, nil
}

func (s *lanSide) ndProbe() time.Duration {
	if s.Router != nil {
		return s.Router.NDProbe.Or(defaultNDProbe)
	}
	return s.Bridge.NDProbe.Or(defaultNDProbe)
}

func (s *lanSide) adminPorts() []uint16 {
	var p *[]uint16
	if s.Router != nil {
		p = s.Router.AdminPorts
	} else {
		p = s.Bridge.AdminPorts
	}
	if p == nil {
		return []uint16{22}
	}
	return *p
}

// gateways は、GW のアドレスのほかになりすましを検知するゲートウェイ（ブリッジ方式の上流のルーター）のアドレスを返す。
func (s *lanSide) gateways() ([]netip.Addr, error) {
	if s.Bridge == nil {
		return nil, nil
	}
	if s.Bridge.Gateway != "" {
		a, err := netip.ParseAddr(s.Bridge.Gateway)
		if err != nil || !a.Is4() {
			return nil, fmt.Errorf("bridge.gateway %q は IPv4 のアドレスで書いてください", s.Bridge.Gateway)
		}
		return []netip.Addr{a}, nil
	}
	a, err := gw.DefaultGateway4(s.Bridge.Name)
	if err != nil {
		return nil, nil // 既定の経路がなければ、上流のルーターのなりすましは検知しない
	}
	return []netip.Addr{a}, nil
}

// defaultNDProbe は、不正なルーターと DHCPv6 のサーバーを探す既定の間隔。
const defaultNDProbe = 5 * time.Minute

type dhcpConfig struct {
	Range     string          `json:"range"`      // 割り当てる範囲（例: 192.168.10.100-192.168.10.199）
	LeaseTime config.Duration `json:"lease_time"` // 既定 1h
	DNS       []string        `json:"dns"`        // 端末に知らせる DNS サーバー
}

// configCheckInterval は設定ファイルの変更を確かめる間隔（G12）。
const configCheckInterval = 30 * time.Second

// GW の非特権のプロセスを動かす既定の利用者。導入するときに作る。互いに干渉できないよう、別々の利用者にする。
const (
	defaultControllerUser = "susanoo-ctl" // CONTROLLER
	defaultLANUser        = "susanoo-net" // LAN 側の処理
)

// 状態のディレクトリの中の、部品ごとのディレクトリ。権限を分けるときは、それぞれを使う非特権のプロセスの利用者に持たせる。
func controllerDir(stateDir string) string { return filepath.Join(stateDir, "controller") } // 台帳、監査ログ、イベント
func lanDir(stateDir string) string        { return filepath.Join(stateDir, "lan") }        // DHCP の貸し出し

func runGW(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("gw", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "/etc/susanoo/gw.json", "設定ファイル")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	var cfg gwConfig
	if err := config.Load(*path, &cfg); err != nil {
		return fail(stderr, err)
	}
	pkiDir := config.Resolve(*path, cfg.PKIDir)
	stateDir := config.Resolve(*path, cfg.StateDir)
	policyPath := config.Resolve(*path, cfg.Policy)
	listen, err := netip.ParseAddrPort(cfg.Listen)
	if err != nil {
		return fail(stderr, fmt.Errorf("listen %q はアドレスとポート（例: 192.168.10.1:8443）で書いてください", cfg.Listen))
	}
	if cfg.Router != nil && cfg.Bridge != nil {
		return fail(stderr, errors.New("router と bridge は一緒に使えません（どちらかの方式にしてください）"))
	}
	if b := cfg.Bridge; b != nil {
		if b.Name == "" || b.LAN == "" || b.WAN == "" {
			return fail(stderr, errors.New("bridge には name、lan、wan が必要です"))
		}
		if cfg.DHCP != nil {
			return fail(stderr, errors.New("ブリッジ方式では dhcp を使えません（上流のルーターの DHCP を使います）"))
		}
	}
	if side := cfg.lanSide(); side != nil {
		if _, err := side.trustedRouters(); err != nil {
			return fail(stderr, err)
		}
		if _, err := side.gateways(); err != nil {
			return fail(stderr, err)
		}
		if side.ndProbe() < time.Second {
			return fail(stderr, errors.New("nd_probe_interval は 1s 以上にしてください"))
		}
	}
	if r := cfg.Router; r != nil {
		if d := r.RAInterval.Or(defaultRAInterval); d < 4*time.Second || d > 1800*time.Second {
			return fail(stderr, errors.New("router.ra_interval は 4s から 30m にしてください"))
		}
	}
	if cfg.DHCP != nil && cfg.Router == nil {
		return fail(stderr, errors.New("dhcp を使うには router の設定が必要です"))
	}
	if cfg.DNS != nil && cfg.lanSide() == nil {
		return fail(stderr, errors.New("dns を使うには router か bridge の設定が必要です"))
	}
	upstreams, err := parseUpstreams(cfg.DNS)
	if err != nil {
		return fail(stderr, err)
	}
	if cfg.Notify != nil {
		if err := cfg.Notify.Validate(); err != nil {
			return fail(stderr, err)
		}
	}

	policyData, err := os.ReadFile(policyPath)
	if err != nil {
		return fail(stderr, err)
	}
	pol, err := policy.Parse(policyData)
	if err != nil {
		return fail(stderr, err)
	}
	log := newLogger(stderr)
	if cfg.Notify != nil && len(cfg.Notify.Destinations) > 0 {
		if fi, err := os.Stat(*path); err == nil && fi.Mode().Perm()&0o044 != 0 {
			log.Warn("設定ファイルに通知の宛先（URL やパスワード）があるのに、ほかの利用者も読めます。chmod 600 で root だけが読めるようにしてください", "ファイル", *path)
		}
	}
	// 認証局の秘密鍵は執行部だけが持ち、端末の証明書の発行と、自分の証明書の更新に使う（M1）。
	ca, err := pki.LoadCA(pkiDir)
	if err != nil {
		return fail(stderr, err)
	}
	warnIssuerExpiry(ca, time.Now(), log)
	if _, err := renewOwnCerts(ca, pkiDir, time.Now(), log); err != nil {
		return fail(stderr, err)
	}
	cert, err := loadLeaf(pkiDir, fileControllerCert, fileControllerKey)
	if err != nil {
		return fail(stderr, err)
	}
	signKey, err := keys.LoadPrivate(filepath.Join(pkiDir, fileSignKey))
	if err != nil {
		return fail(stderr, err)
	}
	// 配布したポリシーの版は、執行部だけが読み書きできる保存先に置く（M2）。最初は設定のファイルの版を使う。
	policyPub, err := keys.LoadPublic(filepath.Join(pkiDir, filePolicyPub))
	if err != nil {
		return fail(stderr, fmt.Errorf("%w。ctl policy keygen -dir %s でポリシーの署名の鍵を作ってください", err, pkiDir))
	}
	store, err := policy.OpenStore(filepath.Join(stateDir, "policy"), policyPub, pol)
	if err != nil {
		return fail(stderr, err)
	}
	if pol.Version > store.Max() {
		log.Warn("設定のポリシーのファイルの版は使いません。変えるときは ctl policy push で配布してください", "ファイルの版数", pol.Version, "適用中の版数", store.Max())
	}
	// 脅威情報（G7）も、執行部だけが読み書きできる保存先に置く。
	intelStore, err := intel.OpenStore(filepath.Join(stateDir, "intel"), policyPub)
	if err != nil {
		return fail(stderr, err)
	}
	intelSet, intelPayload := intelStore.Current()
	current, canary := store.Policies()
	for _, d := range []string{controllerDir(stateDir), lanDir(stateDir)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fail(stderr, err)
		}
	}

	separate := cfg.Separation == nil || *cfg.Separation
	if separate && os.Geteuid() != 0 {
		log.Warn("root でないため、権限を分離せずに 1 つのプロセスで動きます")
		separate = false
	}
	if separate {
		log = log.With("役割", "執行部")
	}

	// nftables のルールを入れ、ソケットを開く。権限を分けるときも、ここまでは root で行う。
	g, err := prepareGW(ctx, cfg, store.Effective(), listen, log)
	if err != nil {
		return fail(stderr, err)
	}
	g.ca, g.pkiDir = ca, pkiDir
	pols := &gwPolicies{store: store, engine: g.engine, enforcer: g.gwEnforcer, log: log}
	intels := &gwIntel{store: intelStore, runner: nft.Command{Path: cfg.NFT}, log: log}
	if side := cfg.lanSide(); side != nil {
		intels.lanIface, intels.family = side.Port, side.Family
		if g.files.flowLog != nil {
			intels.group = flow.DefaultBlockGroup
		}
		if err := intels.apply(ctx, intelSet); err != nil {
			return fail(stderr, err)
		}
	}
	curData, canData, err := policyBytes(current, canary)
	if err != nil {
		return fail(stderr, err)
	}
	defer g.files.close()
	watched := []string{*path, policyPath}

	if separate {
		ch := gwControllerHello{
			Config: cfg, Policy: curData, Canary: canData, CA: ca.Root.Raw, Chain: cert.Certificate,
			Key: cert.PrivateKey.(ed25519.PrivateKey), SignKey: signKey, StateDir: stateDir, RulesKey: policyPub, Intel: intelPayload,
		}
		lh := gwLANHello{Config: cfg, Policy: curData, Canary: canData, StateDir: stateDir, Intel: intelSet.Blocklist()}
		users := [2]string{cmp.Or(cfg.ControllerUser, defaultControllerUser), cmp.Or(cfg.LANUser, defaultLANUser)}
		err = runGWExecutor(ctx, g, pols, intels, ch, lh, users, watched, stateDir, log)
	} else {
		err = runGWInProcess(ctx, g, pols, intels, cfg, cert, signKey, policyPub, watched, stateDir, log)
	}
	if g.engine != nil {
		cur, _ := store.Policies()
		failOpen(g.engine, intels, g.bridgeOpen, cur.OnFailure, upstreams, log)
	}
	if err != nil {
		return fail(stderr, err)
	}
	log.Info("停止しました")
	return exitOK
}

// gwPrepared は GW の執行部が持つもの。
type gwPrepared struct {
	enforcer   controller.Enforcer         // 端末単位の遮断（G9）。nil なら GW で遮断しない
	gwEnforcer *gw.Enforcer                // enforcer と同じもの（ポリシーの切り替えで更新サーバーを差し替える）
	engine     *egress.Engine              // 外部通信の制御（nftables に反映する側）。nil ならルーター方式でもブリッジ方式でもない
	bridgeOpen func(context.Context) error // ブリッジ方式で、停止中に DNS の向け直しをやめる（ルーター方式では nil）
	files      gwFiles
	ca         *pki.CA // 内部の認証局（秘密鍵を含む）
	pkiDir     string  // 認証局と CONTROLLER の鍵のディレクトリ
}

// renewCheckInterval は、CONTROLLER と管理者の証明書の更新の時期を確かめる間隔。
const renewCheckInterval = 12 * time.Hour

// renewOwnCerts は、CONTROLLER と管理者の証明書の有効期間の残りが 3 分の 1 を切っていたら、同じ鍵で更新して
// ファイルを置き換える（M1）。更新した CONTROLLER の証明書を返す（更新しなければ nil）。
func renewOwnCerts(ca *pki.CA, pkiDir string, now time.Time, log *slog.Logger) (*x509.Certificate, error) {
	var renewed *x509.Certificate
	for _, file := range []string{fileControllerCert, fileAdminCert} {
		path := filepath.Join(pkiDir, file)
		chain, err := pki.ReadChainFile(path)
		if errors.Is(err, fs.ErrNotExist) && file == fileAdminCert {
			continue // 管理者の証明書を別の場所に置いている
		}
		if err != nil {
			return nil, err
		}
		cert := chain[0]
		id, err := pki.IdentityFromCert(cert)
		if err != nil {
			return nil, err
		}
		if !ca.CanIssue(id.Role) {
			continue // 二段構えでは、管理者の証明書はルートの認証局で更新する（ctl root admin）
		}
		// 発行用の認証局の証明書を差し替えたら（ctl init -issuer）、期限を待たずに今の連なりで発行し直す。
		if !pki.RenewalDue(cert, now) && sameChain(chain[1:], ca.ChainOf(cert)[1:]) {
			continue
		}
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%s は ed25519 の証明書ではありません", path)
		}
		next, err := ca.Issue(pub, id, now)
		if err != nil {
			return nil, err
		}
		if err := pki.WriteChainFile(path, ca.ChainOf(next)...); err != nil {
			return nil, err
		}
		log.Info("証明書を更新しました", "ファイル", path, "期限", next.NotAfter.Local().Format(time.DateTime))
		if file == fileControllerCert {
			renewed = next
		}
	}
	return renewed, nil
}

// warnIssuerExpiry は、二段構えの発行用の認証局の証明書の期限が近ければ知らせる。知らせたら true を返す。
// 期限を過ぎると、端末と CONTROLLER の証明書を更新できない（発行する証明書の期限は発行用の認証局の期限までになる）。
func warnIssuerExpiry(ca *pki.CA, now time.Time, log *slog.Logger) bool {
	if !ca.TwoTier() || ca.ExpiresAt().Sub(now) >= issuerWarnBefore {
		return false
	}
	log.Warn("発行用の認証局の証明書の期限が近づいています。管理者が ctl root sign-issuer で署名し直し、ctl init -issuer で入れ替えて GW を起動し直してください",
		"期限", ca.ExpiresAt().Local().Format(time.DateTime))
	return true
}

// sameChain は、二つの証明書の並びが同じかを返す。
func sameChain(a, b []*x509.Certificate) bool {
	return slices.EqualFunc(a, b, func(x, y *x509.Certificate) bool { return x.Equal(y) })
}

// renewLoop は renewCheckInterval ごとに自分の証明書を確かめ、CONTROLLER の証明書を更新したら renewed を呼ぶ。
func renewLoop(ctx context.Context, g *gwPrepared, log *slog.Logger, renewed func(*x509.Certificate)) {
	t := time.NewTicker(renewCheckInterval)
	warned := time.Now() // 起動のときに一度知らせている
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if now.Sub(warned) >= 24*time.Hour && warnIssuerExpiry(g.ca, now, log) {
				warned = now
			}
			cert, err := renewOwnCerts(g.ca, g.pkiDir, now, log)
			if err != nil {
				log.Error("証明書を更新できません", "エラー", err)
			} else if cert != nil {
				renewed(cert)
			}
		}
	}
}

// caIssuer は内部の認証局で端末の証明書を発行する（controller.Issuer）。役割は端末に限る。
type caIssuer struct {
	ca  *pki.CA
	log *slog.Logger
}

func (i caIssuer) IssueClient(_ context.Context, id string, pub ed25519.PublicKey) ([]*x509.Certificate, error) {
	cert, err := i.ca.Issue(pub, pki.Identity{Role: pki.RoleClient, ID: id}, time.Now())
	if err != nil {
		return nil, err
	}
	i.log.Info("端末の証明書を発行しました", "端末", id, "期限", cert.NotAfter.Local().Format(time.DateTime))
	return i.ca.ChainOf(cert), nil
}

// prepareGW は、ルーター方式と外部通信の制御と通信の記録のルールを入れ、使うソケットを開く。root で行う。
func prepareGW(ctx context.Context, cfg gwConfig, pol *policy.Policy, listen netip.AddrPort, log *slog.Logger) (_ *gwPrepared, err error) {
	runner := nft.Command{Path: cfg.NFT}
	g := &gwPrepared{}
	defer func() {
		if err != nil {
			g.files.close()
		}
	}()
	if cfg.Enforce == nil || *cfg.Enforce {
		g.gwEnforcer = &gw.Enforcer{NFT: runner, ManagementPort: listen.Port(), Updates: pol.AllUpdatePrefixes()}
		g.enforcer = g.gwEnforcer
	} else {
		log.Warn("GW での遮断は無効です（enforce: false）")
	}
	ln, err := net.Listen("tcp", listen.String())
	if err != nil {
		return nil, err
	}
	if g.files.listener, err = ln.(*net.TCPListener).File(); err != nil {
		ln.Close()
		return nil, err
	}
	ln.Close()

	side := cfg.lanSide()
	if side == nil {
		return g, nil
	}
	if g.gwEnforcer != nil {
		g.gwEnforcer.Family = side.Family
	}
	lanAddr, lanPrefix, lanMAC, err := gw.InterfaceAddr(side.AddrIface)
	if err != nil {
		return nil, err
	}
	var lanAddr6 netip.Addr
	if r := side.Router; r != nil && r.IPv6 {
		if lanAddr6, _, err = lanIPv6(r.LAN); err != nil {
			return nil, err
		}
	}
	if listen.Addr() != lanAddr {
		log.Warn("管理通信の待ち受けアドレスが LAN 側のアドレスと違います", "listen", listen, "LAN", lanAddr)
	}
	openARP, openND := gw.OpenARPSocket, gw.OpenNDSocket
	if side.Bridge != nil {
		openARP, openND = gw.OpenARPSocketPort, gw.OpenNDSocketPort // ブリッジのポートでは種類を問わずに受け取る
	}
	if g.files.arp, err = openARP(side.Port); err != nil {
		return nil, err
	}
	if g.files.nd, err = openND(side.Port); err != nil {
		log.Warn("IPv6 の近隣探索を監視できません", "エラー", err)
		g.files.nd = nil
	}
	if r := side.Router; r != nil {
		router := &gw.Router{
			Rules: nft.Router{LAN: r.LAN, WAN: r.WAN, ManagementPort: listen.Port(), AdminPorts: side.adminPorts(), DHCP: cfg.DHCP != nil, DNS: cfg.DNS != nil, WANDHCP: r.WANDHCP, IPv6: r.IPv6},
			NFT:   runner,
		}
		if err := router.Apply(ctx); err != nil {
			return nil, err
		}
		log.Info("ルーター方式を設定しました", "LAN", r.LAN, "WAN", r.WAN, "LAN のネットワーク", lanPrefix)
	} else {
		b := side.Bridge
		trusted, _ := side.trustedRouters() // 起動のときに確かめてある
		rules := nft.BridgeRules{Bridge: b.Name, LAN: b.LAN, WAN: b.WAN, ManagementPort: listen.Port(), AdminPorts: side.adminPorts(),
			WANDHCP: b.WANDHCP, MAC: lanMAC, TrustedRouters: trusted}
		open, err := rules.Script() // DNS を向け直さないルール（停止中に使う）
		if err != nil {
			return nil, err
		}
		if cfg.DNS != nil {
			rules.DNS = lanAddr
		}
		script, err := rules.Script()
		if err != nil {
			return nil, err
		}
		if err := runner.Run(ctx, script); err != nil {
			return nil, err
		}
		g.bridgeOpen = func(ctx context.Context) error { return runner.Run(ctx, open) }
		log.Info("ブリッジ方式を設定しました", "ブリッジ", b.Name, "LAN", b.LAN, "WAN", b.WAN, "LAN のネットワーク", lanPrefix)
	}

	// 外部通信の制御（G2、G4）は常に有効にする。DNS の制御（G3）は dns の設定があるときだけ。
	// ブリッジ方式の DNS の向け直しは BridgeRules が行う。
	ecfg := egress.Config{Policy: pol, LAN: side.Port, Family: side.Family, NFT: runner, Logger: log}
	if cfg.DNS != nil && side.Router != nil {
		ecfg.DNS, ecfg.DNS6 = lanAddr, lanAddr6
	}
	if g.engine, err = egress.New(ecfg); err != nil {
		return nil, err
	}
	if err := g.engine.Apply(ctx); err != nil {
		return nil, err
	}
	if cfg.DHCP != nil {
		pc, err := dhcp.Listen(side.Port)
		if err != nil {
			return nil, err
		}
		g.files.dhcp, err = pc.(*net.UDPConn).File()
		pc.Close()
		if err != nil {
			return nil, err
		}
	}
	if cfg.DNS != nil {
		pc, tl, err := dns.Listen(lanAddr, 0)
		if err != nil {
			return nil, err
		}
		g.files.dnsUDP, err = pc.(*net.UDPConn).File()
		pc.Close()
		if err != nil {
			tl.Close()
			return nil, err
		}
		g.files.dnsTCP, err = tl.(*net.TCPListener).File()
		tl.Close()
		if err != nil {
			return nil, err
		}
		if lanAddr6.IsValid() {
			pc6, tl6, err := listenDNS6(ctx, lanAddr6)
			if err != nil {
				return nil, err
			}
			g.files.dnsUDP6, err = pc6.(*net.UDPConn).File()
			pc6.Close()
			if err != nil {
				tl6.Close()
				return nil, err
			}
			g.files.dnsTCP6, err = tl6.(*net.TCPListener).File()
			tl6.Close()
			if err != nil {
				return nil, err
			}
		}
	}
	if cfg.FlowLog == nil || *cfg.FlowLog {
		if err := startFlowLog(ctx, side.Port, side.Family, runner); err != nil {
			if side.Bridge == nil {
				return nil, err
			}
			// bridge のテーブルで NFLOG を使えないカーネルでは、接続の終わりの記録（conntrack）だけを続ける。
			log.Warn("ブリッジの通信の最初のパケットを受け取れません。SNI と HTTP の Host は記録しません", "エラー", err)
		}
		socks, err := flow.OpenSockets(flow.DefaultLogGroup, flow.DefaultBlockGroup)
		if err != nil {
			return nil, err
		}
		g.files.flowCT, g.files.flowLog = socks.Conntrack, socks.NFLOG
	}
	return g, nil
}

// gwFiles は執行部が開いて、CONTROLLER と LAN 側の処理に渡すソケット。使わないものは nil。
type gwFiles struct {
	listener *os.File // 管理通信（TCP）
	arp      *os.File // ARP の監視（AF_PACKET）
	nd       *os.File // IPv6 の近隣探索の監視（AF_PACKET。使えなければ nil）
	dhcp     *os.File // DHCP（UDP 67）
	dnsUDP   *os.File // DNS（UDP 53）
	dnsTCP   *os.File // DNS（TCP 53）
	dnsUDP6  *os.File // DNS（IPv6 の UDP 53。IPv6 を転送するとき）
	dnsTCP6  *os.File // DNS（IPv6 の TCP 53）
	flowCT   *os.File // conntrack のイベント（netlink）
	flowLog  *os.File // NFLOG（netlink）
}

type fileEntry struct {
	name string
	file **os.File
}

// controllerEntries は CONTROLLER に渡すソケットを返す。
func (f *gwFiles) controllerEntries() []fileEntry {
	return []fileEntry{{"listener", &f.listener}}
}

// lanEntries は LAN 側の処理に渡すソケットを返す。
func (f *gwFiles) lanEntries() []fileEntry {
	return []fileEntry{
		{"arp", &f.arp}, {"nd", &f.nd}, {"dhcp", &f.dhcp}, {"dns_udp", &f.dnsUDP}, {"dns_tcp", &f.dnsTCP}, {"dns_udp6", &f.dnsUDP6}, {"dns_tcp6", &f.dnsTCP6},
		{"flow_conntrack", &f.flowCT}, {"flow_nflog", &f.flowLog},
	}
}

func (f *gwFiles) close() {
	for _, e := range append(f.controllerEntries(), f.lanEntries()...) {
		if *e.file != nil {
			(*e.file).Close()
		}
	}
}

// inherit は、entries の開いているソケットと peer（nil でなければ）を受け継がせる順に並べ、名前と fd の番号の対応を返す。
func inherit(entries []fileEntry, peer *os.File) ([]*os.File, map[string]int) {
	var files []*os.File
	fds := map[string]int{}
	for _, e := range entries {
		if *e.file != nil {
			fds[e.name] = privsep.ConnFD + 1 + len(files)
			files = append(files, *e.file)
		}
	}
	if peer != nil {
		fds["peer"] = privsep.ConnFD + 1 + len(files)
		files = append(files, peer)
	}
	return files, fds
}

// openInherited は、受け継いだソケットを entries と peer に開く。知らない名前があればエラーにする。
func openInherited(fds map[string]int, entries []fileEntry) (peer *os.File, err error) {
	known := map[string]**os.File{}
	for _, e := range entries {
		known[e.name] = e.file
	}
	for name, fd := range fds {
		f, err := privsep.InheritedFile(fd, name)
		if err != nil {
			return nil, err
		}
		switch dst, ok := known[name]; {
		case name == "peer":
			peer = f
		case ok:
			*dst = f
		default:
			f.Close()
			return nil, fmt.Errorf("知らないソケット %q を渡されました", name)
		}
	}
	return peer, nil
}

// gwControllerHello は、執行部が CONTROLLER に渡す情報。CONTROLLER は設定ファイルや鍵のファイルを読まない。
type gwControllerHello struct {
	Config   gwConfig       `json:"config"`
	Policy   []byte         `json:"policy"`           // 今の版
	Canary   []byte         `json:"canary,omitempty"` // 先行適用の版
	CA       []byte         `json:"ca"`               // 内部の認証局の証明書（DER）
	Chain    [][]byte       `json:"chain"`            // CONTROLLER の証明書（DER）
	Key      []byte         `json:"key"`              // CONTROLLER の TLS の秘密鍵（ed25519）
	SignKey  []byte         `json:"sign_key"`         // 指示に署名する秘密鍵（ed25519）
	RulesKey []byte         `json:"rules_key"`        // 検知ルールの署名を確かめる公開鍵（policy.pub）
	Intel    []byte         `json:"intel,omitempty"`  // 執行部が使っている脅威情報（署名を確かめた中身）
	StateDir string         `json:"state_dir"`        // 状態のディレクトリ
	Files    map[string]int `json:"files"`            // 受け継がせたソケット（listener と、LAN 側の処理とつながる peer）
}

// gwLANHello は、執行部が LAN 側の処理に渡す情報。鍵は渡さない。
type gwLANHello struct {
	Config   gwConfig        `json:"config"`
	Policy   []byte          `json:"policy"`
	Canary   []byte          `json:"canary,omitempty"`
	Intel    intel.Blocklist `json:"intel"` // DNS で引かせない脅威情報のドメイン
	StateDir string          `json:"state_dir"`
	Files    map[string]int  `json:"files"` // ARP、DHCP、DNS、通信の記録のソケットと、CONTROLLER とつながる peer
}

// runGWExecutor は GW の執行部（G12）。部品ごとの状態のディレクトリを非特権の利用者に渡し、ソケットを受け継がせて
// CONTROLLER（users[0]）と LAN 側の処理（users[1]。ルーター方式のときだけ）を起動してから、CAP_NET_ADMIN だけを残して
// それぞれの要求に応える。設定ファイルの変更は執行部が確かめて CONTROLLER に知らせる。
// どちらかが止まったら、もう一方も止めてエラーを返す（systemd などで起動し直す前提）。
func runGWExecutor(ctx context.Context, g *gwPrepared, pols *gwPolicies, intels *gwIntel, ch gwControllerHello, lh gwLANHello, users [2]string, watched []string, stateDir string, log *slog.Logger) error {
	withLAN := g.files.arp != nil
	type account struct{ uid, gid uint32 }
	var accounts [2]account
	for i, u := range users {
		if i == 1 && !withLAN {
			accounts[1] = accounts[0]
			break
		}
		uid, gid, err := privsep.LookupUser(u)
		if err != nil {
			key := [2]string{"controller_user", "lan_user"}[i]
			return fmt.Errorf("%w。専用の利用者を作るか（例: useradd --system --no-create-home --shell /usr/sbin/nologin %s）、設定の %s で指定してください", err, u, key)
		}
		if uid == 0 {
			return errors.New("GW の非特権のプロセスを root で動かすことはできません")
		}
		accounts[i] = account{uid, gid}
	}
	if withLAN && accounts[0].uid == accounts[1].uid {
		return errors.New("CONTROLLER と LAN 側の処理は、互いに干渉できないよう、別々の利用者（controller_user と lan_user）で動かしてください")
	}
	if err := os.Chmod(stateDir, 0o711); err != nil {
		return err
	}
	for i, d := range []string{controllerDir(stateDir), lanDir(stateDir)} {
		if err := chownTree(d, int(accounts[i].uid), int(accounts[i].gid)); err != nil {
			return err
		}
	}

	var ctrlPeer, lanPeer *os.File
	if withLAN {
		var err error
		if ctrlPeer, lanPeer, err = privsep.Socketpair(); err != nil {
			return err
		}
		defer ctrlPeer.Close()
		defer lanPeer.Close()
	}
	type part struct {
		name  string
		child *privsep.Child
		conn  *os.File
	}
	var parts []part
	wait := func() {
		for _, p := range parts {
			select {
			case <-p.child.Exited:
			case <-time.After(5 * time.Second):
				log.Warn("GW の非特権のプロセスが終わりません", "部品", p.name, "PID", p.child.Pid)
			}
		}
	}
	stop := func() {
		for _, p := range parts {
			p.conn.Close()
		}
		wait()
	}
	files, fds := inherit(g.files.controllerEntries(), ctrlPeer)
	ch.Files = fds
	child, conn, err := privsep.Spawn(users[0], files, "gw", "controller")
	if err != nil {
		return err
	}
	parts = append(parts, part{"CONTROLLER", child, conn})
	if withLAN {
		files, fds := inherit(g.files.lanEntries(), lanPeer)
		lh.Files = fds
		child, conn, err := privsep.Spawn(users[1], files, "gw", "lan")
		if err != nil {
			stop()
			return err
		}
		parts = append(parts, part{"LAN 側の処理", child, conn})
	}
	g.files.close() // 非特権のプロセスが受け継いだので、こちらの写しは閉じる
	if withLAN {
		ctrlPeer.Close()
		lanPeer.Close()
	}
	for _, step := range []func() error{
		func() error { return privsep.DropCapabilities(privsep.GWExecutorCaps) },
		privsep.Harden,
	} {
		if err := step(); err != nil {
			stop()
			return err
		}
	}
	attrs := []any{"CONTROLLER の PID", parts[0].child.Pid, "CONTROLLER の利用者", users[0]}
	if withLAN {
		attrs = append(attrs, "LAN 側の処理の PID", parts[1].child.Pid, "LAN 側の処理の利用者", users[1])
	}
	log.Info("権限を分離しました", attrs...)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	changes := make(chan string, 4)
	go watchFiles(ctx, watched, configCheckInterval, func(p string) { notifyChange(ctx, changes, p) })
	certs := make(chan []byte, 1)
	go renewLoop(ctx, g, log, func(c *x509.Certificate) {
		select {
		case certs <- c.Raw:
		case <-ctx.Done():
		}
	})
	lanPolicies := make(chan controller.PolicyState, 1)
	lanIntel := make(chan intel.Blocklist, 1)
	if withLAN {
		pols.notifyLAN = func(st controller.PolicyState) {
			select {
			case <-lanPolicies: // 届けていない古いものは捨てる
			default:
			}
			lanPolicies <- st
		}
		intels.notifyLAN = func(b intel.Blocklist) {
			select {
			case <-lanIntel:
			default:
			}
			lanIntel <- b
		}
	}
	ctrlEx := privsep.GWExecutor{Quarantine: g.enforcer, Issuer: caIssuer{g.ca, log}, Policies: pols, Intel: intels}
	if g.engine != nil {
		ctrlEx.Membership = g.engine
	}
	errc := make(chan error, len(parts))
	serve := func(p part, ex privsep.GWExecutor, hello any, out privsep.GWNotices) {
		go func() {
			if err := privsep.ServeGW(ctx, p.conn, ex, hello, out, log); err != nil {
				errc <- fmt.Errorf("%s: %w", p.name, err)
				return
			}
			errc <- nil
		}()
	}
	serve(parts[0], ctrlEx, ch, privsep.GWNotices{Changes: changes, Certs: certs})
	if withLAN {
		serve(parts[1], privsep.GWExecutor{Learner: g.engine}, lh, privsep.GWNotices{Policies: lanPolicies, Intel: lanIntel})
	}
	err = <-errc
	cancel()
	for range len(parts) - 1 {
		if e := <-errc; err == nil {
			err = e
		}
	}
	wait() // 非特権のプロセスは、つながりが切れると終わる
	return err
}

// runGWInProcess は、権限を分けずに、CONTROLLER と LAN 側の処理を同じプロセスで動かす（root でないときなど）。
func runGWInProcess(ctx context.Context, g *gwPrepared, pols *gwPolicies, intels *gwIntel, cfg gwConfig, cert tls.Certificate, signKey ed25519.PrivateKey, rulesKey ed25519.PublicKey, watched []string, stateDir string, log *slog.Logger) error {
	signer, err := sign.NewSigner(signKey)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	changes := make(chan string, 4)
	go watchFiles(ctx, watched, configCheckInterval, func(p string) { notifyChange(ctx, changes, p) })
	certs := make(chan tls.Certificate, 1)
	go renewLoop(ctx, g, log, func(c *x509.Certificate) {
		select {
		case certs <- pki.TLSChain(g.ca.ChainOf(c), cert.PrivateKey.(ed25519.PrivateKey)):
		case <-ctx.Done():
		}
	})
	current, canary := pols.store.Policies()
	intelSet, _ := intels.store.Current()
	c := &gwController{cfg: cfg, pol: current, canary: canary, pool: g.ca.Pool(), root: g.ca.Root, cert: cert, signer: signer, rulesKey: rulesKey, stateDir: stateDir,
		intel: intels, intelSet: intelSet,
		listener: g.files.listener, quarantine: g.enforcer, issuer: caIssuer{g.ca, log}, policies: pols, changes: changes, certs: certs, log: log}
	var lanPart *gwLAN
	if g.engine != nil {
		if lanPart, err = newGWLAN(cfg, current, canary, stateDir, g.files, g.engine, g.engine, log); err != nil {
			return err
		}
		c.egress, c.lan = lanPart, lanPart
		c.trusted, _ = cfg.lanSide().trustedRouters() // 起動のときに確かめてある
		pols.notifyLAN = func(st controller.PolicyState) { lanPart.setPolicyState(st) }
		lanPart.setIntel(intelSet.Blocklist())
		intels.notifyLAN = lanPart.setIntel
	}
	lanErr := make(chan error, 1)
	err = c.run(ctx, func(ctrl *controller.Controller) {
		if lanPart == nil {
			return
		}
		go func() {
			if err := lanPart.run(ctx, ctrl); err != nil && ctx.Err() == nil {
				lanErr <- err
				cancel()
			}
		}()
	})
	if err != nil {
		return err
	}
	select {
	case err := <-lanErr:
		return err
	default:
	}
	return nil
}

// startPart は、GW の非特権のプロセスとして動き始めるときの共通の準備をする。
func startPart(stderr io.Writer, role string) (*slog.Logger, *os.File, error) {
	signal.Ignore(os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	log := newLogger(stderr).With("役割", role)
	if os.Geteuid() == 0 {
		return nil, nil, errors.New("GW の非特権のプロセスを root で動かすことはできません")
	}
	if err := privsep.Harden(); err != nil {
		return nil, nil, err
	}
	if err := privsep.SetName("susanoo"); err != nil {
		log.Warn("プロセス名を付けられません", "エラー", err)
	}
	conn, err := privsep.OpenConnFD()
	return log, conn, err
}

// runGWController は GW の CONTROLLER（G12）。執行部が非特権の利用者で起動し、fd 3 でつなぐ。
// 執行部か LAN 側の処理とのつながりが切れたら終わり、シグナルでは終わらない（止めるのは執行部）。
func runGWController(stderr io.Writer) int {
	log, conn, err := startPart(stderr, "CONTROLLER")
	if err == nil {
		err = serveGWController(conn, log)
	}
	if err != nil {
		return fail(stderr, err)
	}
	return exitOK
}

// serveGWController は、執行部とのつながり conn で設定と鍵とソケットを受け取り、CONTROLLER を動かす。
func serveGWController(conn *os.File, log *slog.Logger) error {
	var hello gwControllerHello
	remote, err := privsep.DialGW(conn, &hello, log)
	if err != nil {
		return err
	}
	defer remote.Close()
	cfg := hello.Config
	pol, canary, err := parsePolicies(hello.Policy, hello.Canary)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(hello.CA)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if len(hello.Chain) == 0 {
		return errors.New("CONTROLLER の証明書がありません")
	}
	leaf, err := x509.ParseCertificate(hello.Chain[0])
	if err != nil {
		return err
	}
	signer, err := sign.NewSigner(ed25519.PrivateKey(hello.SignKey))
	if err != nil {
		return err
	}
	var files gwFiles
	peer, err := openInherited(hello.Files, files.controllerEntries())
	if err != nil {
		return err
	}
	if files.listener == nil {
		return errors.New("管理通信の待ち受けを渡されていません")
	}
	key := ed25519.PrivateKey(hello.Key)
	certs := make(chan tls.Certificate, 1)
	if len(hello.RulesKey) != ed25519.PublicKeySize {
		return errors.New("検知ルールの署名を確かめる公開鍵がありません")
	}
	var intelSet *intel.Set
	if len(hello.Intel) > 0 {
		if intelSet, err = intel.Parse(hello.Intel); err != nil {
			return err
		}
	}
	// 二段構えでは、CONTROLLER の証明書に発行用の認証局の証明書が連なる。更新した証明書にも同じものを連ねる。
	chain := []*x509.Certificate{leaf}
	for _, der := range hello.Chain[1:] {
		inter, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		chain = append(chain, inter)
	}
	c := &gwController{cfg: cfg, pol: pol, canary: canary, pool: pool, root: ca, cert: pki.TLSChain(chain, key), signer: signer,
		rulesKey: ed25519.PublicKey(hello.RulesKey), intel: remote, intelSet: intelSet, stateDir: hello.StateDir, listener: files.listener, issuer: remote, policies: remote, changes: remote.Changes(), certs: certs, log: log}
	if cfg.Enforce == nil || *cfg.Enforce {
		c.quarantine = remote
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-remote.Done(); cancel() }()
	go func() {
		// 執行部が更新した証明書は、自分の鍵の証明書であることを確かめてから使う。
		for {
			select {
			case der := <-remote.Certs():
				next, err := x509.ParseCertificate(der)
				if err != nil || !next.PublicKey.(ed25519.PublicKey).Equal(key.Public()) {
					log.Error("執行部から届いた CONTROLLER の証明書が不正です")
					continue
				}
				certs <- pki.TLSChain(append([]*x509.Certificate{next}, chain[1:]...), key)
			case <-ctx.Done():
				return
			}
		}
	}()
	var link *privsep.LANLink
	if side := cfg.lanSide(); side != nil {
		if peer == nil {
			return errors.New("LAN 側の処理とのつながりを渡されていません")
		}
		link = privsep.ConnectLAN(peer, log)
		defer link.Close()
		go func() { <-link.Done(); cancel() }()
		addr, prefix, mac, err := gw.InterfaceAddr(side.AddrIface)
		if err != nil {
			return err
		}
		gateways, err := side.gateways()
		if err != nil {
			return err
		}
		c.lan = &remoteLAN{addr: addr, prefix: prefix, mac: mac, link: link, addrs6: &gw.Addrs6Cache{Name: side.AddrIface}, gateways: gateways}
		if c.trusted, err = side.trustedRouters(); err != nil {
			return err
		}
		c.egress = membershipFanout{remote, link}
	}
	return c.run(ctx, func(ctrl *controller.Controller) {
		if link != nil {
			link.SetObserver(ctrl)
		}
	})
}

// remoteLAN は、CONTROLLER の側から見た GW の LAN（controller.LAN）。在席の確認は LAN 側の処理に頼む。
type remoteLAN struct {
	addr     netip.Addr
	prefix   netip.Prefix
	mac      net.HardwareAddr
	link     *privsep.LANLink
	addrs6   *gw.Addrs6Cache
	gateways []netip.Addr // ブリッジ方式の上流のルーター
}

func (r *remoteLAN) Gateways() []netip.Addr { return r.gateways }

func (r *remoteLAN) Addrs6() []netip.Addr { return r.addrs6.Get() }
func (r *remoteLAN) WithdrawRA(ctx context.Context, src netip.Addr, mac net.HardwareAddr, prefixes []netip.Prefix, rdnss []netip.Addr) error {
	return r.link.WithdrawRA(ctx, src, mac, prefixes, rdnss)
}

func (r *remoteLAN) Addr() netip.Addr      { return r.addr }
func (r *remoteLAN) Prefix() netip.Prefix  { return r.prefix }
func (r *remoteLAN) MAC() net.HardwareAddr { return r.mac }
func (r *remoteLAN) Probe(ctx context.Context, ip netip.Addr) (net.HardwareAddr, bool) {
	return r.link.Probe(ctx, ip)
}

// membershipFanout は、端末のグループと隔離の状態を、執行部（nftables への反映）と LAN 側の処理
// （DNS の判断と、DHCP で割り当てないアドレス）の両方に渡す（controller.Egress）。
type membershipFanout struct {
	executor privsep.MembershipSetter
	lan      privsep.MembershipSetter
}

func (f membershipFanout) SetMembership(ctx context.Context, m egress.Membership) error {
	return errors.Join(f.executor.SetMembership(ctx, m), f.lan.SetMembership(ctx, m))
}

// runGWLAN は GW の LAN 側の処理（G12）。執行部が非特権の利用者で起動し、fd 3 でつなぐ。
// 執行部か CONTROLLER とのつながりが切れたら終わり、シグナルでは終わらない（止めるのは執行部）。
func runGWLAN(stderr io.Writer) int {
	log, conn, err := startPart(stderr, "LAN 側の処理")
	if err == nil {
		err = serveGWLAN(conn, log)
	}
	if err != nil {
		return fail(stderr, err)
	}
	return exitOK
}

// serveGWLAN は、執行部とのつながり conn で設定とソケットを受け取り、LAN 側の処理を動かす。
func serveGWLAN(conn *os.File, log *slog.Logger) error {
	var hello gwLANHello
	remote, err := privsep.DialGW(conn, &hello, log)
	if err != nil {
		return err
	}
	defer remote.Close()
	if hello.Config.lanSide() == nil {
		return errors.New("ルーター方式でもブリッジ方式でもないのに LAN 側の処理を起動されました")
	}
	pol, canary, err := parsePolicies(hello.Policy, hello.Canary)
	if err != nil {
		return err
	}
	var files gwFiles
	peer, err := openInherited(hello.Files, files.lanEntries())
	if err != nil {
		return err
	}
	if peer == nil {
		return errors.New("CONTROLLER とのつながりを渡されていません")
	}
	lanPart, err := newGWLAN(hello.Config, pol, canary, hello.StateDir, files, remote, nil, log)
	if err != nil {
		return err
	}
	lanPart.setIntel(hello.Intel)
	go func() {
		for {
			select {
			case st := <-remote.Policies():
				lanPart.setPolicyState(st)
			case b := <-remote.Intel():
				lanPart.setIntel(b)
			case <-remote.Done():
				return
			}
		}
	}()
	link := privsep.ConnectController(peer, log)
	defer link.Close()
	link.Serve(lanPart)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-remote.Done():
		case <-link.Done():
		}
		cancel()
	}()
	return lanPart.run(ctx, link)
}

// gwController は GW の CONTROLLER の部分。権限を分けないときは、同じプロセスで LAN 側の処理と直接つなぐ。
type gwController struct {
	cfg        gwConfig
	pol        *policy.Policy // 今の版
	canary     *policy.Policy // 先行適用の版（なければ nil）
	pool       *x509.CertPool
	root       *x509.Certificate // 内部の認証局（ルート）の証明書。登録した端末に渡す
	trusted    []string          // LAN のルーターとして認める機器の MAC アドレス
	cert       tls.Certificate
	signer     *sign.Signer
	rulesKey   ed25519.PublicKey       // 検知ルールの署名を確かめる公開鍵
	intel      controller.IntelManager // 脅威情報の配布（執行部）
	intelSet   *intel.Set              // 執行部が使っている脅威情報
	stateDir   string
	listener   *os.File
	quarantine controller.Enforcer      // 端末単位の遮断。nil なら GW で遮断しない
	egress     controller.Egress        // 端末のグループの受け渡し。nil ならルーター方式でない
	lan        controller.LAN           // GW の LAN。nil ならルーター方式でない
	issuer     controller.Issuer        // 端末の証明書の発行（執行部）
	policies   controller.PolicyManager // ポリシーの配布（執行部）
	changes    <-chan string            // 設定ファイルの変更
	certs      <-chan tls.Certificate   // 更新した CONTROLLER の証明書
	log        *slog.Logger
}

// run は CONTROLLER を動かす。started は CONTROLLER を作った直後に呼ぶ（LAN 側の処理の知らせの渡し先にするため）。
// ctx が終わるまで返らない。
func (c *gwController) run(ctx context.Context, started func(*controller.Controller)) error {
	ln, err := net.FileListener(c.listener)
	if err != nil {
		return err
	}
	ccfg := controller.Config{
		Dir:              controllerDir(c.stateDir),
		CA:               c.pool,
		Cert:             c.cert,
		Signer:           c.signer,
		Policy:           c.pol,
		Canary:           c.canary,
		Policies:         c.policies,
		Enforcer:         c.quarantine,
		Issuer:           c.issuer,
		Root:             c.root,
		TrustedRouters:   c.trusted,
		RulesKey:         c.rulesKey,
		Intel:            c.intel,
		IntelSet:         c.intelSet,
		HeartbeatTimeout: c.cfg.HeartbeatTimeout.Or(controller.DefaultHeartbeatTimeout),
		MaxClockSkew:     c.cfg.MaxClockSkew.Or(controller.DefaultMaxClockSkew),
		ClockSynced:      linux.ClockSynchronized,
		Logger:           c.log,
	}
	if c.lan != nil {
		ccfg.LAN = c.lan
		ccfg.Egress = c.egress
	}
	if n := c.cfg.Notify; n != nil && len(n.Destinations) > 0 {
		if ccfg.Notifier, err = notify.New(*n, notify.Options{Logger: c.log}); err != nil {
			ln.Close()
			return err
		}
	}
	ctrl, err := controller.New(ccfg)
	if err != nil {
		ln.Close()
		return err
	}
	if started != nil {
		started(ctrl)
	}
	go func() {
		for {
			select {
			case p := <-c.changes:
				ctrl.ReportChange(p)
			case cert := <-c.certs:
				ctrl.SetCertificate(cert)
			case <-ctx.Done():
				return
			}
		}
	}()
	c.log.Info("GW モードで起動しました", "ポリシー", c.pol.Name, "版数", c.pol.Version, "対応", c.pol.Response)
	return ctrl.Serve(ctx, ln)
}

// gwLAN は GW の LAN 側の処理（DNS、DHCP、ARP の監視、通信の記録）。LAN から届くデータを解析するので、
// 権限を分けるときは CONTROLLER と別の利用者で動かす。見つけたことは LANObserver（CONTROLLER）に知らせる。
type gwLAN struct {
	cfg      gwConfig
	stateDir string
	files    gwFiles
	lan      *gw.LAN
	side     *lanSide
	gateways []netip.Addr // ブリッジ方式の上流のルーター
	addrs6   *gw.Addrs6Cache
	ecfg     egress.Config                 // DNS の判断の設定（ポリシーを切り替えるときに作り直す）
	engine   atomic.Pointer[egress.Engine] // DNS の判断（nftables への反映は learner に任せる）
	intel    atomic.Pointer[intel.Matcher] // DNS で引かせない脅威情報のドメイン
	members  atomic.Pointer[egress.Membership]
	forward  privsep.MembershipSetter // 端末のグループを nftables にも反映する（権限を分けないとき）。nil なら反映しない
	isolated atomic.Pointer[map[netip.Addr]bool]
	sink     atomic.Pointer[privsep.LANObserver]
	log      *slog.Logger
}

// newGWLAN は LAN 側の処理を作る。DNS の判断には今の版と先行適用の版（canary。なければ nil）を使い、
// DNS で得たアドレスは learner に加えさせる。
func newGWLAN(cfg gwConfig, pol, canary *policy.Policy, stateDir string, files gwFiles, learner privsep.Learner, forward privsep.MembershipSetter, log *slog.Logger) (*gwLAN, error) {
	side := cfg.lanSide()
	lan, err := gw.NewLANOn(side.Port, side.AddrIface, files.arp)
	if err != nil {
		return nil, err
	}
	gateways, err := side.gateways()
	if err != nil {
		return nil, err
	}
	if files.nd != nil {
		if err := lan.AttachND(files.nd); err != nil {
			return nil, err
		}
	}
	l := &gwLAN{cfg: cfg, stateDir: stateDir, files: files, lan: lan, side: side, gateways: gateways, addrs6: &gw.Addrs6Cache{Name: side.AddrIface}, forward: forward, log: log}
	l.isolated.Store(&map[netip.Addr]bool{})
	l.members.Store(&egress.Membership{})
	l.ecfg = egress.Config{
		LAN:    side.Port,
		Remote: learnOnly{learner},
		OnLearn: func(group, name string, blocked bool) {
			if s := l.sink.Load(); s != nil {
				(*s).RecordLearned(group, name, blocked)
			}
		},
		Logger: log,
	}
	if cfg.DNS != nil {
		l.ecfg.DNS = lan.Addr()
	}
	if err := l.setPolicy(pol, canary); err != nil {
		return nil, err
	}
	return l, nil
}

// setPolicy は DNS の判断を、今の版と先行適用の版のポリシーで作り直す。端末のグループは引き継ぐ。
func (l *gwLAN) setPolicy(current, canary *policy.Policy) error {
	ecfg := l.ecfg
	ecfg.Policy = policy.WithCanary(current, canary)
	e, err := egress.New(ecfg)
	if err != nil {
		return err
	}
	e.SetMembership(context.Background(), *l.members.Load())
	e.SetIntel(l.intel.Load())
	l.engine.Store(e)
	return nil
}

// setIntel は、DNS で引かせない脅威情報のドメインを切り替える。
func (l *gwLAN) setIntel(b intel.Blocklist) {
	m := b.Matcher()
	l.intel.Store(m)
	l.engine.Load().SetIntel(m)
	n := 0
	for _, p := range b.Lists {
		n += len(p.Domains)
	}
	if b.Version > 0 {
		l.log.Info("DNS で引かせない脅威情報のドメインを切り替えました", "版数", b.Version, "ドメイン", n)
	}
}

// setPolicyState は執行部が切り替えたポリシーに従う。
func (l *gwLAN) setPolicyState(st controller.PolicyState) {
	current, canary, err := parsePolicies(st.Current, st.Canary)
	if err == nil {
		err = l.setPolicy(current, canary)
	}
	if err != nil {
		l.log.Error("切り替えたポリシーを DNS の判断に使えません", "エラー", err)
		return
	}
	l.log.Info("DNS の判断のポリシーを切り替えました", "版数", current.Version)
}

// Decide は DNS の問い合わせへの対応を決める（dns.Policy）。
func (l *gwLAN) Decide(client netip.Addr, q dns.Question) dns.Verdict {
	return l.engine.Load().Decide(client, q)
}

// learnOnly は、DNS で得たアドレスだけを執行部に頼む egress.Enforcer。端末のグループは CONTROLLER が執行部に渡す。
type learnOnly struct{ learner privsep.Learner }

func (learnOnly) SetMembership(context.Context, egress.Membership) error { return nil }
func (o learnOnly) Learn(ctx context.Context, t egress.Target, ips []netip.Addr, ttl time.Duration) error {
	return o.learner.Learn(ctx, t, ips, ttl)
}

// controller.LAN と privsep.LANServices。
func (l *gwLAN) Addr() netip.Addr      { return l.lan.Addr() }
func (l *gwLAN) Prefix() netip.Prefix  { return l.lan.Prefix() }
func (l *gwLAN) MAC() net.HardwareAddr { return l.lan.MAC() }
func (l *gwLAN) Probe(ctx context.Context, ip netip.Addr) (net.HardwareAddr, bool) {
	return l.lan.Probe(ctx, ip)
}
func (l *gwLAN) Addrs6() []netip.Addr   { return l.addrs6.Get() }
func (l *gwLAN) Gateways() []netip.Addr { return l.gateways }
func (l *gwLAN) WithdrawRA(_ context.Context, src netip.Addr, mac net.HardwareAddr, prefixes []netip.Prefix, rdnss []netip.Addr) error {
	return l.lan.WithdrawRA(src, mac, prefixes, rdnss)
}

// SetMembership は、CONTROLLER から受け取った端末のグループと隔離の状態を、DNS の判断と DHCP に使う。
func (l *gwLAN) SetMembership(ctx context.Context, m egress.Membership) error {
	isolated := make(map[netip.Addr]bool, len(m.Isolated))
	for a := range m.Isolated {
		isolated[a] = true
	}
	l.isolated.Store(&isolated)
	l.members.Store(&m)
	if err := l.engine.Load().SetMembership(ctx, m); err != nil {
		return err
	}
	if l.forward != nil {
		return l.forward.SetMembership(ctx, m)
	}
	return nil
}

// advertise は、GW を LAN の IPv6 のルーターとして知らせる RA を、間をおいて送る。端末のルーター要請には、
// 前の RA から 3 秒（RFC 4861 の MIN_DELAY_BETWEEN_RAS）以上たっていれば、すぐに答える。
func (l *gwLAN) advertise(ctx context.Context, interval time.Duration, prefix netip.Prefix, rdnss []netip.Addr, solicited <-chan struct{}) {
	lifetime := min(max(3*interval, 30*time.Second), 9000*time.Second)
	opts := gw.RAOptions{
		HopLimit: 64, RouterLifetime: uint16(lifetime / time.Second), Prefixes: []netip.Prefix{prefix},
		Valid: 86400, Preferred: 14400, RDNSS: rdnss, RDNSSLifetime: uint32(lifetime / time.Second),
	}
	l.log.Info("LAN に IPv6 のルーター広告を送ります", "ネットワーク", prefix, "間隔", interval, "DNS サーバー", rdnss)
	t := time.NewTicker(interval)
	defer t.Stop()
	var last time.Time
	send := func() {
		if err := l.lan.Advertise(opts); err != nil {
			l.log.Warn("ルーター広告を送れません", "エラー", err)
			return
		}
		last = time.Now()
	}
	send()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			send()
		case <-solicited:
			if time.Since(last) >= 3*time.Second {
				send()
			}
		}
	}
}

// probeIPv6 は、間をおいてルーター要請と DHCPv6 の問い合わせを送り、答える不正なルーターとサーバーを探す。
// リンクローカルのアドレスがない（LAN で IPv6 を止めている）ときは、最初の 1 回だけログに残す。
func (l *gwLAN) probeIPv6(ctx context.Context, interval time.Duration) {
	first := time.NewTimer(5 * time.Second)
	defer first.Stop()
	select {
	case <-ctx.Done():
		return
	case <-first.C:
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	warned := false
	for {
		if err := l.lan.ProbeIPv6(); err != nil && !warned {
			l.log.Warn("不正なルーターと DHCPv6 のサーバーを探す問い合わせを送れません", "エラー", err)
			warned = true
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// quarantined は、隔離中の機器が使っていたアドレスかを返す（DHCP で割り当てない）。
func (l *gwLAN) quarantined(ip netip.Addr) bool { return (*l.isolated.Load())[ip] }

// run は LAN 側の処理を動かし、見つけたことを sink に知らせる。ctx が終わるか、部品が止まるまで返らない。
func (l *gwLAN) run(ctx context.Context, sink privsep.LANObserver) error {
	l.sink.Store(&sink)
	cfg, log := l.cfg, l.log
	upstreams, err := parseUpstreams(cfg.DNS)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	failc := make(chan error, 4)
	// background は部品を動かし、ctx が終わる前に止まったら LAN 側の処理全体を止める。
	background := func(name string, run func(context.Context) error) {
		go func() {
			if err := run(ctx); err != nil && ctx.Err() == nil {
				failc <- fmt.Errorf("%s が止まりました: %w", name, err)
				cancel()
			}
		}()
	}
	l.lan.SetHandler(func(n gw.Neighbor) {
		sink.ObserveNeighbor(n.FrameMAC, n.ARP.SenderIP)
		// 自分のアドレスを知らせる ARP（gratuitous ARP）と、アドレスの重複の確認（送信元が 0.0.0.0）は、探したことにしない。
		if a := n.ARP; a.Op == gw.ARPRequest && a.TargetIP != a.SenderIP && !a.SenderIP.IsUnspecified() {
			sink.ObserveARPRequest(n.FrameMAC, a.TargetIP)
		}
	})
	background("ARP の監視", l.lan.Run)
	solicited := make(chan struct{}, 1) // 端末のルーター要請（GW の RA ですぐに答える）
	if l.lan.HasND() {
		l.lan.SetNDHandler(func(ev gw.NDEvent) {
			switch {
			case ev.ND != nil:
				n := ev.ND
				if n.Type == gw.NDRouterSolicit {
					select {
					case solicited <- struct{}{}:
					default:
					}
				}
				sink.ObserveND(controller.NDObservation{Frame: ev.FrameMAC, Type: int(n.Type), Src: n.Src, Target: n.Target,
					Override: n.Override, RouterLifetime: int(n.RouterLifetime), Prefixes: n.Prefixes, RDNSS: n.RDNSS})
			case ev.DHCPv6 != nil:
				d := ev.DHCPv6
				sink.ObserveDHCPv6(controller.DHCPv6Observation{Frame: ev.FrameMAC, Src: d.Src, DNS: d.DNS, Address: d.Address})
			}
		})
		background("近隣探索の監視", l.lan.RunND)
		go l.probeIPv6(ctx, l.side.ndProbe())
		if cfg.Router != nil && cfg.Router.IPv6 {
			addr6, prefix6, err := lanIPv6(cfg.Router.LAN)
			if err != nil {
				return err
			}
			var rdnss []netip.Addr
			if cfg.DNS != nil {
				rdnss = []netip.Addr{addr6}
			}
			go l.advertise(ctx, cfg.Router.RAInterval.Or(defaultRAInterval), prefix6, rdnss, solicited)
		}
	} else if cfg.Router != nil && cfg.Router.IPv6 {
		return errors.New("router.ipv6 には IPv6 の近隣探索のソケットが必要です")
	}
	if d := cfg.DHCP; d != nil {
		if len(d.DNS) == 0 && cfg.DNS != nil {
			d.DNS = []string{l.lan.Addr().String()} // 端末には GW のリゾルバを知らせる
		}
		srv, err := newDHCP(d, l.lan, filepath.Join(lanDir(l.stateDir), "dhcp-leases.json"), sink, l.quarantined, log)
		if err != nil {
			return err
		}
		pc, err := net.FilePacketConn(l.files.dhcp)
		if err != nil {
			return err
		}
		background("DHCP サーバー", func(ctx context.Context) error { return srv.ServeConn(ctx, pc) })
	}
	if cfg.DNS != nil {
		resolver, err := newResolver(cfg.DNS, upstreams, l.lan, l, sink, log)
		if err != nil {
			return err
		}
		var pcs []net.PacketConn
		var tls []net.Listener
		for _, s := range [][2]*os.File{{l.files.dnsUDP, l.files.dnsTCP}, {l.files.dnsUDP6, l.files.dnsTCP6}} {
			if s[0] == nil || s[1] == nil {
				continue
			}
			pc, err := net.FilePacketConn(s[0])
			if err != nil {
				return err
			}
			tl, err := net.FileListener(s[1])
			if err != nil {
				return err
			}
			pcs, tls = append(pcs, pc), append(tls, tl)
		}
		background("DNS リゾルバ", func(ctx context.Context) error { return resolver.ServeAll(ctx, pcs, tls) })
	}
	if l.files.flowCT != nil {
		fcfg := flow.Config{LAN: l.lan.Prefix(), Gateway: l.lan.Addr(), LogGroup: flow.DefaultLogGroup, BlockGroup: flow.DefaultBlockGroup,
			OnRecord: func(r flow.Record) { sink.RecordFlow(flowRecord(r)) }, Logger: log}
		if cfg.Router != nil && cfg.Router.IPv6 {
			if addr6, prefix6, err := lanIPv6(cfg.Router.LAN); err == nil {
				fcfg.LAN6, fcfg.Gateway6 = prefix6, addr6
			}
		}
		socks := &flow.Sockets{Conntrack: l.files.flowCT, NFLOG: l.files.flowLog}
		background("通信の記録", func(ctx context.Context) error { return flow.RunSockets(ctx, fcfg, socks) })
	}
	select {
	case err := <-failc:
		return err
	case <-ctx.Done():
		return nil
	}
}

// notifyChange は設定ファイルの変更を changes に送る。
func notifyChange(ctx context.Context, changes chan<- string, path string) {
	select {
	case changes <- path:
	case <-ctx.Done():
	}
}

// chownTree は dir とその下のすべての持ち主を uid、gid にする。
func chownTree(dir string, uid, gid int) error {
	return filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
}

// failOpen は、停止するときの通信の扱いをポリシーの障害時の動作（G12）に合わせる。
// fail_open なら外部通信の制御をやめ、LAN の DNS を最初の平文の上流に向け直す。fail_closed なら制御を残す。
// 端末単位の隔離は、どちらでも残す（乗っ取られた端末を通さないため）。
func failOpen(engine *egress.Engine, intels *gwIntel, bridgeOpen func(context.Context) error, mode policy.FailureMode, upstreams []*dns.Upstream, log *slog.Logger) {
	if mode != policy.FailOpen {
		log.Info("停止中も外部通信の制御を続けます（fail_closed）")
		return
	}
	var plain netip.AddrPort
	for _, u := range upstreams {
		if u.TLSName == "" {
			plain = u.Addr
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := engine.FailOpen(ctx, plain); err != nil {
		log.Error("停止中に通信を通す設定にできません", "エラー", err)
		return
	}
	if err := intels.stop(ctx); err != nil {
		log.Error("脅威情報のアドレスの遮断をやめられません", "エラー", err)
	}
	if bridgeOpen != nil {
		if err := bridgeOpen(ctx); err != nil {
			log.Error("ブリッジ方式の DNS の向け直しをやめられません", "エラー", err)
		}
	}
	log.Warn("停止中は外部通信の制御をやめ、通信を通します（fail_open）。端末の隔離は続けます")
}

// startFlowLog は conntrack の通信量と時刻の記録を有効にし、各接続の最初の数パケットを NFLOG で渡すルールを入れる。
// 通信量を数えられないとパケットの数を絞れないので、有効にできなければルールを入れない。
func startFlowLog(ctx context.Context, lanIface string, fam nft.Family, runner nft.Runner) error {
	if err := flow.EnableAccounting(); err != nil {
		return err
	}
	script, err := nft.FlowLog{Family: fam, LAN: lanIface, Group: flow.DefaultLogGroup}.Script()
	if err != nil {
		return err
	}
	return runner.Run(ctx, script)
}

func flowRecord(r flow.Record) controller.FlowRecord {
	return controller.FlowRecord{
		Open: r.Kind == flow.Open, Blocked: r.Kind == flow.Blocked, Time: r.Time, Proto: r.Proto, Src: r.Src, Dst: r.Dst,
		BytesOut: r.BytesOut, BytesIn: r.BytesIn, PacketsOut: r.PacketsOut, PacketsIn: r.PacketsIn,
		Start: r.Start, End: r.End,
		SNI: r.Info.SNI, JA4: r.Info.JA4, TLSVersion: r.Info.TLSVersion, ALPN: r.Info.ALPN,
		HTTPMethod: r.Info.HTTPMethod, HTTPHost: r.Info.HTTPHost,
	}
}

func parseUpstreams(d *dnsConfig) ([]*dns.Upstream, error) {
	if d == nil {
		return nil, nil
	}
	if len(d.Upstreams) == 0 {
		return nil, errors.New("dns.upstreams に上流の DNS サーバーを指定してください")
	}
	var out []*dns.Upstream
	for _, u := range d.Upstreams {
		ap, err := netip.ParseAddrPort(u.Address)
		if err != nil {
			return nil, fmt.Errorf("dns.upstreams の %q はアドレスとポート（例: 192.168.0.1:53）で書いてください", u.Address)
		}
		out = append(out, &dns.Upstream{Addr: ap, TLSName: u.TLSName})
	}
	return out, nil
}

func newResolver(d *dnsConfig, upstreams []*dns.Upstream, lan *gw.LAN, engine dns.Policy, sink privsep.LANObserver, log *slog.Logger) (*dns.Server, error) {
	cfg := dns.Config{Addr: lan.Addr(), Upstreams: upstreams, Policy: engine, Logger: log}
	if d.LogQueries == nil || *d.LogQueries {
		cfg.OnQuery = func(q dns.QueryLog) {
			r := controller.DNSRecord{
				Time: q.Time, Client: q.Client, Name: q.Name, Type: q.Type, Rcode: q.Rcode,
				Action: q.Action.String(), Reason: q.Reason, Group: q.Group,
			}
			for _, a := range q.Answers {
				if a.IP.IsValid() {
					r.Answers = append(r.Answers, a.IP.String())
				} else if a.Target != "" {
					r.Answers = append(r.Answers, a.Target)
				}
			}
			sink.RecordDNS(r)
		}
	}
	return dns.New(cfg)
}

func newDHCP(d *dhcpConfig, lan *gw.LAN, statePath string, sink privsep.LANObserver, avoid func(netip.Addr) bool, log *slog.Logger) (*dhcp.Server, error) {
	start, end, err := dhcp.ParseRange(d.Range)
	if err != nil {
		return nil, err
	}
	var dns []netip.Addr
	for _, s := range d.DNS {
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is4() {
			return nil, fmt.Errorf("dhcp.dns の %q は IPv4 アドレスで書いてください", s)
		}
		dns = append(dns, a)
	}
	return dhcp.New(dhcp.Config{
		ServerIP:   lan.Addr(),
		Prefix:     lan.Prefix(),
		RangeStart: start,
		RangeEnd:   end,
		DNS:        dns,
		LeaseTime:  d.LeaseTime.Or(dhcp.DefaultLeaseTime),
		StatePath:  statePath,
		OnLease: func(l dhcp.Lease, released bool) {
			sink.ObserveLease(l.MAC, l.IP, l.Hostname, l.Expiry, released)
		},
		Avoid:  avoid,
		Logger: log,
	})
}

// watchFiles は files の中身が変わったら onChange を呼ぶ（G12 の設定の改ざん検知）。
// 変更は起動し直すまで反映しないので、変わったことだけを知らせる。
func watchFiles(ctx context.Context, files []string, interval time.Duration, onChange func(string)) {
	sums := make(map[string][sha256.Size]byte, len(files))
	for _, f := range files {
		sums[f] = fileSum(f)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, f := range files {
				if sum := fileSum(f); sum != sums[f] {
					sums[f] = sum
					onChange(f)
				}
			}
		}
	}
}

func fileSum(path string) [sha256.Size]byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return [sha256.Size]byte{}
	}
	return sha256.Sum256(data)
}

// gwPolicies は GW の執行部のポリシーの配布（M2、controller.PolicyManager）。署名と版数を保存先で確かめてから、
// 外部通信の制御と GW の遮断に反映し、LAN 側の処理に知らせる。CONTROLLER は署名の鍵を持たないので、
// CONTROLLER を乗っ取られても、ポリシーの中身は変えられない（署名済みの版の中から選ぶことしかできない）。
type gwPolicies struct {
	store     *policy.Store
	engine    *egress.Engine // nil ならルーター方式でない
	enforcer  *gw.Enforcer   // nil なら GW で遮断しない
	notifyLAN func(controller.PolicyState)
	log       *slog.Logger
	mu        sync.Mutex
}

func (g *gwPolicies) ApplyPolicy(ctx context.Context, env sign.Envelope, canary bool) (controller.PolicyState, error) {
	return g.change(ctx, func() error { _, err := g.store.Apply(env, canary); return err })
}

func (g *gwPolicies) PromotePolicy(ctx context.Context) (controller.PolicyState, error) {
	return g.change(ctx, g.store.Promote)
}

func (g *gwPolicies) AbortPolicy(ctx context.Context) (controller.PolicyState, error) {
	return g.change(ctx, g.store.Abort)
}

// change は保存先を変え、GW で使うポリシーを切り替える。
func (g *gwPolicies) change(ctx context.Context, op func() error) (controller.PolicyState, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := op(); err != nil {
		return controller.PolicyState{}, err
	}
	eff := g.store.Effective()
	if g.engine != nil {
		if err := g.engine.Reconfigure(ctx, eff); err != nil {
			g.log.Error("外部通信の制御にポリシーを反映できません。起動し直すと反映します", "エラー", err)
			return controller.PolicyState{}, fmt.Errorf("外部通信の制御に反映できません: %w", err)
		}
	}
	if g.enforcer != nil {
		g.enforcer.SetUpdates(eff.AllUpdatePrefixes()) // CONTROLLER が遮断の一覧を送り直すときに反映する
	}
	current, canary := g.store.Policies()
	curData, canData, err := policyBytes(current, canary)
	if err != nil {
		return controller.PolicyState{}, err
	}
	st := controller.PolicyState{Current: curData, Canary: canData}
	if g.notifyLAN != nil {
		g.notifyLAN(st)
	}
	attrs := []any{"今の版数", current.Version}
	if canary != nil {
		attrs = append(attrs, "先行適用の版数", canary.Version)
	}
	g.log.Warn("ポリシーを切り替えました", attrs...)
	return st, nil
}

// gwIntel は GW の執行部の、脅威情報の配布の受け付け（controller.IntelManager）。署名と版数を確かめ、
// 遮断の一覧のアドレスを nftables に入れてから保存し、ドメインを LAN 側の処理（DNS）に知らせる。
type gwIntel struct {
	store     *intel.Store
	runner    nft.Runner
	lanIface  string     // 空ならルーター方式でもブリッジ方式でもない（nftables で遮断しない）
	family    nft.Family // テーブルの種類
	group     uint16     // 落としたパケットを渡す NFLOG のグループ（0 なら渡さない）
	notifyLAN func(intel.Blocklist)
	log       *slog.Logger
	mu        sync.Mutex
}

// apply は遮断の一覧のアドレスを nftables に入れる（なければテーブルを消す）。
func (g *gwIntel) apply(ctx context.Context, s *intel.Set) error {
	if g.lanIface == "" {
		return nil
	}
	rules := nft.Intel{Family: g.family, LAN: g.lanIface, Group: g.group, Block: s.BlockedPrefixes()}
	script, err := rules.Script()
	if err != nil {
		return err
	}
	err = g.runner.Run(ctx, script)
	if err != nil && g.family == nft.Bridge && g.group != 0 {
		// bridge のテーブルで NFLOG を使えないカーネルでは、記録せずに落とす。
		g.log.Warn("脅威情報のアドレスに落としたパケットを記録できません。記録せずに遮断します", "エラー", err)
		g.group, rules.Group = 0, 0
		if script, err = rules.Script(); err == nil {
			err = g.runner.Run(ctx, script)
		}
	}
	return err
}

// stop は脅威情報のアドレスの遮断をやめる（停止中に通信を通すとき）。
func (g *gwIntel) stop(ctx context.Context) error {
	if g.lanIface == "" {
		return nil
	}
	return g.runner.Run(ctx, nft.DeleteTableIn(g.family, nft.IntelTable))
}

func (g *gwIntel) ApplyIntel(ctx context.Context, env sign.Envelope) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	s, err := g.store.Check(env)
	if err != nil {
		return err
	}
	if err := g.apply(ctx, s); err != nil {
		return fmt.Errorf("脅威情報のアドレスを nftables に入れられません: %w", err)
	}
	if _, err := g.store.Apply(env); err != nil {
		return err
	}
	if g.notifyLAN != nil {
		g.notifyLAN(s.Blocklist())
	}
	g.log.Warn("脅威情報を切り替えました", "版数", s.Version, "遮断するアドレスの範囲", len(s.BlockedPrefixes()))
	return nil
}

// policyBytes は今の版と先行適用の版（なければ空）を JSON にする。
func policyBytes(current, canary *policy.Policy) ([]byte, []byte, error) {
	cur, err := json.Marshal(current)
	if err != nil || canary == nil {
		return cur, nil, err
	}
	can, err := json.Marshal(canary)
	return cur, can, err
}

// parsePolicies は今の版と先行適用の版（空なら nil）を読む。
func parsePolicies(current, canary []byte) (*policy.Policy, *policy.Policy, error) {
	cur, err := policy.Parse(current)
	if err != nil || len(canary) == 0 {
		return cur, nil, err
	}
	can, err := policy.Parse(canary)
	return cur, can, err
}
