// Package controller は CONTROLLER モードの機能をまとめる。
//
//   - 端末の台帳（M1）：証明書で認証した端末を、最初の接続で台帳に載せる
//   - LAN の機器の台帳（G8）：DHCP と ARP で見えた機器を MAC アドレスで記録し、端末と結び付ける。
//     なりすまし（ゲートウェイのアドレスや、ほかの機器に割り当て中のアドレスを名乗る ARP）を検知する
//   - イベントの集約（M4）：CLIENT と GW のイベントを、端末 ID を付けて保存する
//   - 判定と自動対応（M3、M5、M6）：集めたイベントを検知ルールで評価し、端末ごとの危険度がしきい値を超えたら隔離する。
//     既定のルールでは、おとりへの接触、短時間の大量変更、ハートビートの途絶（G10）、なりすましで隔離する。
//     ハートビートが途絶えても、LAN にいない端末は「不在」として隔離しない
//   - 監査ログ（M10）：隔離と解除、設定の変更を記録する
//
// 端末の隔離は、GW の遮断（Enforcer）と、CLIENT への署名付きの指示（自己隔離）の両方で行う。
// CLIENT のない機器は GW の遮断だけで隔離する。
package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/audit"
	"susanoo/internal/behavior"
	"susanoo/internal/event"
	"susanoo/internal/intel"
	"susanoo/internal/notify"
	"susanoo/internal/policy"
	"susanoo/internal/rules"
	"susanoo/internal/sign"
	"susanoo/internal/store"
)

// Enforcer は GW で端末を遮断する。
type Enforcer interface {
	// Sync は遮断する端末の一覧を、アドレス addrs と MAC アドレス macs に置き換える。
	Sync(ctx context.Context, addrs map[netip.Addr]policy.IsolationLevel, macs map[string]policy.IsolationLevel) error
}

// LAN は GW の LAN 側の情報と、機器が LAN にいるかの確認（CONTROLLER を GW に同居させるとき）。
type LAN interface {
	Addr() netip.Addr      // GW の LAN 側のアドレス
	Prefix() netip.Prefix  // LAN のネットワーク
	MAC() net.HardwareAddr // GW の LAN 側の MAC アドレス
	// Probe は ip のアドレスを持つ機器が LAN にいるかを確かめ、いれば MAC アドレスを返す。
	Probe(ctx context.Context, ip netip.Addr) (net.HardwareAddr, bool)
}

// Config は CONTROLLER の設定。
type Config struct {
	Dir              string            // 台帳、監査ログ、イベントを置くディレクトリ
	CA               *x509.CertPool    // 内部の認証局
	Cert             tls.Certificate   // CONTROLLER のサーバー証明書
	Signer           *sign.Signer      // CLIENT への指示に署名する鍵
	Policy           *policy.Policy    // ポリシー
	Enforcer         Enforcer          // GW の遮断。nil なら GW では遮断しない
	LAN              LAN               // GW の LAN。nil なら在席の確認となりすましの検知をしない
	Issuer           Issuer            // 端末の証明書の更新に使う。nil なら更新しない
	Canary           *policy.Policy    // 先行適用の版（なければ nil）。Policy は今の版
	Policies         PolicyManager     // ポリシーの配布に使う。nil なら配布しない
	Egress           Egress            // 外部通信の制御。nil なら端末のグループを渡さない
	RulesKey         ed25519.PublicKey // 検知ルールの署名を確かめる公開鍵（ポリシーと同じ鍵）。nil なら配布を受け付けない（既定のルールだけ）
	Intel            IntelManager      // 脅威情報の配布に使う。nil なら配布しない
	Notifier         *notify.Notifier  // 管理者への通知（M7）。nil なら通知しない
	IntelSet         *intel.Set        // 執行部が使っている脅威情報（なければ nil）
	HeartbeatTimeout time.Duration     // これより長くハートビートがなければ隔離する
	MaxEventBytes    int64             // 保存するイベントの合計の上限
	Logger           *slog.Logger
	Now              func() time.Time
}

// 既定値。
const (
	DefaultHeartbeatTimeout = 30 * time.Second
	DefaultMaxEventBytes    = 1 << 30
	flushInterval           = 10 * time.Second
	enforceTimeout          = 10 * time.Second
	probeTimeout            = 3 * time.Second
)

// 監査ログに記録する操作。
const (
	ActionRegister           = "device.register"
	ActionIsolate            = "device.isolate"
	ActionIsolatePending     = "device.isolate.pending"
	ActionRelease            = "device.release"
	ActionHostIsolate        = "host.isolate"
	ActionHostIsolatePending = "host.isolate.pending"
	ActionHostRelease        = "host.release"
	ActionConfigChanged      = "config.changed"
)

// 隔離の理由。
const (
	ReasonHoneytoken      = "おとりへの接触"
	ReasonHeartbeatLost   = "ハートビートの途絶"
	ReasonGatewaySpoofing = "ゲートウェイのなりすまし"
	ReasonIPSpoofing      = "アドレスのなりすまし"
	ReasonMassChange      = "短時間の大量変更"
	ReasonAdmin           = "管理者による隔離"
)

// actorSystem は自動対応のときの操作の主体。
const actorSystem = "system"

// Controller は CONTROLLER。
type Controller struct {
	cfg    Config
	log    *slog.Logger
	now    func() time.Time
	audit  *audit.Log
	events *store.JSONL

	mu      sync.Mutex
	devices map[string]*device
	hosts   map[string]*host // MAC アドレス → 機器
	dirty   bool             // 台帳に保存していない変更（最終接続時刻など）がある

	learned learnedLog

	// quarantined は GW で遮断しているアドレス。DHCP がロックを取らずに参照する。
	quarantined atomic.Pointer[map[netip.Addr]bool]

	started   time.Time
	pol       *policy.Policy // 今の版（mu で守る）
	canaryPol *policy.Policy // 先行適用の版。なければ nil（mu で守る）
	canarySel canarySelection

	cert    atomic.Pointer[tls.Certificate] // CONTROLLER の証明書（SetCertificate で切り替える）
	revMu   sync.Mutex
	revoked map[string]time.Time // 失効させた持ち主の URI → 時刻

	engine    atomic.Pointer[rules.Engine] // 検知ルール
	counter   rules.Counter                // しきい値のあるルールの回数
	ruleStore *rules.Store                 // 配布した検知ルールの版。nil なら配布を受け付けない
	risk      riskState                    // 危険度と、ルールに当てはまった回数（mu で守る）
	riskDirty bool
	hitLogs   map[string]*hitLog // 当てはまりのログをまとめるための記録（mu で守る）

	intelM    atomic.Pointer[intel.Matcher] // 脅威情報（G7）
	intelSeen map[string]time.Time          // 脅威情報の検知結果をまとめるための記録（mu で守る）

	detector      *behavior.Detector // 振る舞いの検知（G6）
	behaviorMu    sync.Mutex
	behaviorSaved time.Time

	evidenceMu sync.Mutex
	evidence   []api.EvidenceInfo // 保存した証拠（C11）

	incidents []*incident // インシデント（M9。mu で守る）
}

// New は台帳、監査ログ、イベントの保存先を開いて CONTROLLER を作る。
func New(cfg Config) (*Controller, error) {
	if cfg.Signer == nil || cfg.Policy == nil || cfg.CA == nil {
		return nil, errors.New("controller: 認証局、署名の鍵、ポリシーは必須です")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HeartbeatTimeout <= 0 {
		cfg.HeartbeatTimeout = DefaultHeartbeatTimeout
	}
	if cfg.MaxEventBytes <= 0 {
		cfg.MaxEventBytes = DefaultMaxEventBytes
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	devices, hosts, err := loadRegistry(filepath.Join(cfg.Dir, "devices.json"))
	if err != nil {
		return nil, err
	}
	// 停止していた間はハートビートを受け取れないので、起動時刻から数え直す。
	start := cfg.Now()
	for _, d := range devices {
		if d.LastSeen.Before(start) {
			d.LastSeen = start
		}
	}
	al, err := audit.Open(filepath.Join(cfg.Dir, "audit.log"))
	if err != nil {
		return nil, err
	}
	events, err := store.Open(filepath.Join(cfg.Dir, "events"), "events", cfg.MaxEventBytes)
	if err != nil {
		al.Close()
		return nil, err
	}
	revoked, err := loadRevocations(filepath.Join(cfg.Dir, revocationFile))
	if err != nil {
		events.Close()
		al.Close()
		return nil, err
	}
	c := &Controller{cfg: cfg, log: cfg.Logger, now: cfg.Now, audit: al, events: events, devices: devices, hosts: hosts, revoked: revoked,
		pol: cfg.Policy, canaryPol: cfg.Canary, started: cfg.Now()}
	c.quarantined.Store(&map[netip.Addr]bool{})
	c.cert.Store(&cfg.Cert)
	if err := c.initPolicy(); err != nil {
		events.Close()
		al.Close()
		return nil, err
	}
	if c.learned.entries, err = loadLearned(c.learnedPath()); err != nil {
		events.Close()
		al.Close()
		return nil, err
	}
	if err := c.initRules(); err != nil {
		events.Close()
		al.Close()
		return nil, err
	}
	c.initIntel()
	if err := c.initBehavior(); err != nil {
		events.Close()
		al.Close()
		return nil, err
	}
	if err := c.initEvidence(); err != nil {
		events.Close()
		al.Close()
		return nil, err
	}
	if err := c.initIncidents(); err != nil {
		events.Close()
		al.Close()
		return nil, err
	}
	return c, nil
}

// Serve は ln で管理通信を受け付け、ctx が終わるまで動く。終了時に台帳を保存してファイルを閉じる。
func (c *Controller) Serve(ctx context.Context, ln net.Listener) error {
	defer c.close()

	// 停止前に隔離していた端末を、GW で遮断し直す。
	c.mu.Lock()
	err := c.syncLocked()
	c.mu.Unlock()
	if err != nil {
		return err
	}

	srv := &http.Server{
		Handler:           c.Handler(),
		TLSConfig:         c.tlsConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(c.log.Handler(), slog.LevelDebug),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ServeTLS(ln, "", "") }()
	go c.loop(ctx)
	if c.cfg.Notifier.Enabled() {
		go c.cfg.Notifier.Run(ctx)
	}
	c.log.Info("管理通信の受け付けを始めました", "アドレス", ln.Addr().String())

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(shutdown)
	return nil
}

func (c *Controller) close() {
	c.mu.Lock()
	c.saveLocked()
	c.saveRiskLocked()
	c.mu.Unlock()
	c.saveLearned(false)
	c.saveBehavior(true)
	c.events.Close()
	c.audit.Close()
}

// loop はハートビートの途絶の確認と、台帳の定期的な保存を行う。
func (c *Controller) loop(ctx context.Context) {
	check := time.NewTicker(min(time.Second, c.cfg.HeartbeatTimeout/5))
	defer check.Stop()
	flush := time.NewTicker(flushInterval)
	defer flush.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-check.C:
			c.checkHeartbeats()
		case <-flush.C:
			c.mu.Lock()
			if c.dirty {
				c.saveLocked()
			}
			if c.riskDirty {
				c.saveRiskLocked()
			}
			c.refreshIncidentsLocked()
			c.mu.Unlock()
			c.saveLearned(false)
			c.saveBehavior(false)
			c.checkIncidentDeadlines()
		}
	}
}

// checkHeartbeats はハートビートが途絶えた端末を検知して対応する（G10）。
// GW の LAN があれば、その端末がまだ LAN にいるかを確かめ、いなければ不在として隔離しない。
func (c *Controller) checkHeartbeats() {
	now := c.now()
	var lost []device
	c.mu.Lock()
	for _, d := range c.devices {
		if !d.Lost && d.Isolation == "" && now.Sub(d.LastSeen) > c.cfg.HeartbeatTimeout {
			d.Lost = true
			lost = append(lost, *d)
		}
	}
	c.mu.Unlock()

	for _, d := range lost {
		if !c.present(d) {
			c.markAway(d.ID)
			continue
		}
		msg := fmt.Sprintf("端末 %s のハートビートが %s 以上途絶えています", d.ID, c.cfg.HeartbeatTimeout)
		c.log.Warn("ハートビートが途絶えました", "端末", d.ID, "最終接続", d.LastSeen)
		c.observe(c.finding(event.FindingTypeHeartbeatLost, ReasonHeartbeatLost, msg, event.SeverityHigh, deviceInfo(&d)), subject{device: d.ID})
	}
}

// present は端末が LAN にいるかを返す。確かめる手段がなければ、いるものとみなす。
// 最後にハートビートを受け取ったアドレスに加え、端末に結び付いた機器の今のアドレス（アドレスが
// 変わった場合）にも問い合わせる。応答した機器が、その端末に結び付いた MAC アドレスでなければ、いないとみなす。
func (c *Controller) present(d device) bool {
	lan := c.cfg.LAN
	if lan == nil {
		return true
	}
	c.mu.Lock()
	linked := c.linkedMACsLocked(d.ID)
	var addrs []netip.Addr
	if d.Addr.IsValid() {
		addrs = append(addrs, d.Addr)
	}
	for _, mac := range linked {
		if ip := c.hosts[mac].IP; ip.IsValid() && !slices.Contains(addrs, ip) {
			addrs = append(addrs, ip)
		}
	}
	c.mu.Unlock()
	if len(addrs) == 0 {
		return true
	}
	for _, addr := range addrs {
		ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		mac, ok := lan.Probe(ctx, addr)
		cancel()
		if ok && (len(linked) == 0 || slices.Contains(linked, mac.String())) {
			return true
		}
	}
	return false
}

// markAway はハートビートが途絶えた端末を不在にする。LAN に戻ったら、途絶の確認を再開する。
func (c *Controller) markAway(id string) {
	c.mu.Lock()
	d := c.devices[id]
	if d == nil || !d.Lost || d.Away {
		c.mu.Unlock()
		return
	}
	d.Away = true
	c.saveLocked()
	info := deviceInfo(d)
	c.mu.Unlock()
	msg := fmt.Sprintf("端末 %s のハートビートが途絶えましたが、LAN にいないため隔離しません（不在）", id)
	c.observe(c.finding(event.FindingTypeDeviceAway, "端末の不在", msg, event.SeverityInformational, info), subject{device: id})
	c.log.Info("端末が LAN にいないため、隔離しません（不在）", "端末", id)
}

// record はイベントを保存する。
func (c *Controller) record(e *event.Event) {
	e.Metadata.LoggedTime = c.now().UnixMilli()
	if err := c.events.Append(e); err != nil {
		c.log.Error("イベントを保存できません", "エラー", err)
	}
}

// finding は CONTROLLER が出す検知結果のイベントを作る。
func (c *Controller) finding(typ, title, msg string, sev event.Severity, dev *event.Device) *event.Event {
	e := event.New(event.ClassDetectionFinding, event.FindingCreate, sev, c.now())
	e.Message = msg
	e.FindingInfo = &event.FindingInfo{UID: rand.Text(), Title: title, Desc: msg, Types: []string{typ}}
	e.Device = dev
	return e
}

func deviceInfo(d *device) *event.Device {
	e := &event.Device{UID: d.ID, Hostname: d.Hostname}
	if d.Addr.IsValid() {
		e.IP = d.Addr.String()
	}
	return e
}

// decision はポリシーに従った対応。
type decision int

const (
	decideNone    decision = iota // 隔離しない（監視モード、警告モード）
	decidePending                 // 人の承認を待つ
	decideIsolate                 // 隔離する
)

// decideLocked は隔離が必要な検知への対応を、ポリシーの対応の段階とグループの設定で決める（M6）。
// canary が真なら、グループの設定は先行適用の版から読む。
func (c *Controller) decideLocked(group string, canary bool, target, reason string) (decision, policy.IsolationLevel) {
	switch c.pol.Response {
	case policy.ResponseMonitor:
		c.log.Info("監視モードのため隔離しません", "対象", target, "理由", reason)
		c.notifyAlertLocked(target, reason, c.pol.Response)
		return decideNone, ""
	case policy.ResponseAlert:
		c.log.Warn("隔離が必要な検知がありました（警告モードのため隔離しません）", "対象", target, "理由", reason)
		c.notifyAlertLocked(target, reason, c.pol.Response)
		return decideNone, ""
	}
	g := c.groupLocked(group, canary)
	if g.RequireApproval {
		return decidePending, ""
	}
	return decideIsolate, g.Isolation
}

// trigger は端末への隔離が必要な検知に、ポリシーに従って対応する。
func (c *Controller) trigger(id, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	d := c.devices[id]
	if d == nil || d.Isolation != "" {
		return
	}
	switch dec, level := c.decideLocked(d.Group, c.deviceCanaryLocked(d), id, reason); dec {
	case decidePending:
		if d.Pending == "" {
			d.Pending = reason
			c.saveLocked()
			c.auditLocked(actorSystem, ActionIsolatePending, d.ID, d.Addr, map[string]any{"reason": reason})
			c.log.Warn("隔離の承認を待っています", "端末", id, "理由", reason)
			c.notifyPendingLocked(d.ID, "", cmpOr(d.Group, policy.DefaultGroup), reason)
		}
	case decideIsolate:
		c.isolateLocked(d, level, reason, actorSystem)
	}
}

func (c *Controller) isolateLocked(d *device, level policy.IsolationLevel, reason, actor string) {
	now := c.now()
	d.Isolation, d.Reason, d.Since, d.Pending = level, reason, now, ""
	d.Version = nextVersion(d.Version, now)
	c.saveLocked()
	c.auditLocked(actor, ActionIsolate, d.ID, d.Addr, map[string]any{"level": level, "reason": reason, "macs": c.linkedMACsLocked(d.ID)})
	c.log.Warn("端末を隔離しました", "端末", d.ID, "段階", level, "理由", reason, "操作", actor)
	c.syncLocked()
	inc := c.openIncidentForLocked(d.ID, "端末 "+d.ID, reason, actor)
	c.notifyIsolateLocked(d.ID, "", d.Addr, cmpOr(d.Group, policy.DefaultGroup), level, reason, actor, c.riskLocked("device:"+d.ID), inc)
}

func (c *Controller) releaseLocked(d *device, actor string) {
	now := c.now()
	prev := d.Isolation
	d.Isolation, d.Reason, d.Since, d.Pending, d.Lost, d.Away = "", "", time.Time{}, "", false, false
	c.resetRiskLocked("device:" + d.ID)
	// 隔離中は通信できなかった可能性があるので、ハートビートの途絶は解除の時刻から数え直す。
	d.LastSeen = now
	d.Version = nextVersion(d.Version, now)
	c.saveLocked()
	c.auditLocked(actor, ActionRelease, d.ID, d.Addr, map[string]any{"previous": prev})
	c.log.Info("端末の隔離を解除しました", "端末", d.ID, "操作", actor)
	c.syncLocked()
	c.refreshIncidentsLocked()
	if prev != "" {
		c.notifyReleaseLocked(d.ID, "", prev, actor)
	}
}

// syncLocked は隔離している端末と機器を、アドレスと MAC アドレスで GW で遮断し、
// 隔離の状態を外部通信の制御にも渡す。要求の取り消しに影響されないよう、独立した期限で実行する。
func (c *Controller) syncLocked() error {
	addrs, macs := c.isolationLocked()
	quarantined := make(map[netip.Addr]bool, len(addrs))
	for a := range addrs {
		quarantined[a] = true
	}
	c.quarantined.Store(&quarantined)
	c.pushMembershipLocked(addrs)

	if c.cfg.Enforcer == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), enforceTimeout)
	defer cancel()
	if err := c.cfg.Enforcer.Sync(ctx, addrs, macs); err != nil {
		c.log.Error("GW で遮断できません", "エラー", err)
		return err
	}
	return nil
}

// isolationLocked は隔離している端末と機器の、アドレスと MAC アドレスごとの隔離の段階を返す。
func (c *Controller) isolationLocked() (map[netip.Addr]policy.IsolationLevel, map[string]policy.IsolationLevel) {
	addrs := map[netip.Addr]policy.IsolationLevel{}
	macs := map[string]policy.IsolationLevel{}
	for _, d := range c.devices {
		if d.Isolation == "" {
			continue
		}
		if d.Addr.IsValid() {
			addrs[d.Addr] = d.Isolation
		}
		for _, h := range c.hosts {
			if h.DeviceID == d.ID {
				macs[h.MAC] = d.Isolation
				if h.IP.IsValid() {
					addrs[h.IP] = d.Isolation
				}
			}
		}
	}
	for _, h := range c.hosts {
		if h.Isolation != "" {
			macs[h.MAC] = h.Isolation
			if h.IP.IsValid() {
				addrs[h.IP] = h.Isolation
			}
		}
	}
	return addrs, macs
}

// Quarantined は ip が GW で遮断中のアドレスかを返す。DHCP がこのアドレスをほかの機器に渡さないために使う。
func (c *Controller) Quarantined(ip netip.Addr) bool {
	return (*c.quarantined.Load())[ip]
}

func (c *Controller) saveLocked() {
	if err := saveRegistry(filepath.Join(c.cfg.Dir, "devices.json"), c.devices, c.hosts); err != nil {
		c.log.Error("端末台帳を保存できません", "エラー", err)
		return
	}
	c.dirty = false
}

// auditLocked は監査ログに記録する。
func (c *Controller) auditLocked(actor, action, target string, addr netip.Addr, detail map[string]any) {
	if addr.IsValid() {
		detail["addr"] = addr.String()
	}
	if _, err := c.audit.Append(audit.Entry{Actor: actor, Action: action, Target: target, Detail: detail}); err != nil {
		c.log.Error("監査ログに記録できません", "エラー", err)
	}
}

// ReportChange は設定ファイルの変更を記録する（G12 の設定の改ざん検知）。
func (c *Controller) ReportChange(path string) {
	c.mu.Lock()
	c.auditLocked(actorSystem, ActionConfigChanged, path, netip.Addr{}, map[string]any{})
	c.mu.Unlock()
	msg := fmt.Sprintf("設定ファイル %s が変更されました。意図した変更でなければ、改ざんの恐れがあります", path)
	c.observe(c.finding(event.FindingTypeConfigChanged, "設定の変更", msg, event.SeverityMedium, nil), subject{})
	c.log.Warn("設定ファイルが変更されました。反映するには再起動してください", "ファイル", path)
}

// commandLocked は端末への署名付きの指示を作る。
//
// 端末のグループのプロセス単位の通信の制御（C7）も入れる。ポリシーの配布、先行適用、グループの変更で制御が変わったら、
// 版数を上げて、CLIENT に適用させる。
func (c *Controller) commandLocked(d *device) (sign.Envelope, error) {
	g := c.groupLocked(d.Group, c.deviceCanaryLocked(d))
	if h := appsHash(g.Apps); h != d.AppsHash {
		d.AppsHash = h
		d.Version = nextVersion(d.Version, c.now())
		c.saveLocked()
	}
	cmd := api.Command{DeviceID: d.ID, Version: d.Version, Isolation: d.Isolation, Evidence: d.Evidence, Apps: g.Apps, IssuedAt: c.now().UTC()}
	if d.Isolation == policy.IsolateManagementAndUpdates {
		cmd.Updates = g.UpdatePrefixes()
	}
	payload, err := json.Marshal(cmd)
	if err != nil {
		return sign.Envelope{}, err
	}
	return c.cfg.Signer.Sign(sign.PurposeCommand, payload), nil
}

// appsHash はプロセス単位の通信の制御のハッシュを返す（なければ空）。
func appsHash(a *policy.AppControl) string {
	if a == nil {
		return ""
	}
	data, _ := json.Marshal(a)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ensureLocked は端末を台帳から返す。なければ載せる。
func (c *Controller) ensureLocked(id string, addr netip.Addr) *device {
	d := c.devices[id]
	if d != nil {
		return d
	}
	now := c.now()
	d = &device{ID: id, Addr: addr, FirstSeen: now, LastSeen: now}
	c.devices[id] = d
	c.saveLocked()
	c.auditLocked(actorSystem, ActionRegister, d.ID, d.Addr, map[string]any{})
	c.log.Info("端末を台帳に載せました", "端末", id, "アドレス", addr)
	return d
}

// touchLocked は端末の最終接続時刻とアドレスを更新し、LAN の機器と結び付ける。
// 隔離中の端末のアドレスが変わったら、GW の遮断を新しいアドレスに移す。
func (c *Controller) touchLocked(d *device, addr netip.Addr) {
	d.LastSeen = c.now()
	d.Lost, d.Away = false, false
	c.dirty = true
	if addr.IsValid() && addr != d.Addr {
		c.log.Info("端末のアドレスが変わりました", "端末", d.ID, "旧", d.Addr, "新", addr)
		d.Addr = addr
		c.saveLocked()
		if d.Isolation != "" {
			c.syncLocked()
		}
	}
	c.linkLocked(d, addr)
}
