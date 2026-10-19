// Package client は CLIENT モードの機能をまとめる。
//
// CLIENT は、特権の執行部（Executor）と非特権の解析部（Agent）に分かれる（C10）。
//
//   - Agent：執行部が検知したイベントを CONTROLLER に送り、執行部が作った署名付きのハートビートを送る。
//     応答に含まれる署名付きの指示は、そのまま執行部に渡す
//   - 執行部（Local）：指示の署名を検証して、自己隔離（C6）と解除を行う。適用した指示は状態ファイルに記録し、
//     再起動しても隔離を続ける。隔離中は自己隔離のルールが消されていないかを確かめる
//
// CONTROLLER に接続できない間も、隔離は解除しない。
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/pki"
	"susanoo/internal/transport"
)

// Config は CLIENT の解析部の設定。
type Config struct {
	Controller        netip.AddrPort // CONTROLLER の待ち受けアドレス
	CA                *x509.CertPool // 内部の認証局
	Chain             [][]byte       // 端末の証明書の連なり（DER）。秘密鍵は執行部だけが持つ
	HeartbeatInterval time.Duration
	Executor          Executor
	Logger            *slog.Logger
}

// 既定値と上限。
const (
	DefaultHeartbeatInterval = 5 * time.Second
	maxPending               = 10000            // 送れていないイベントの上限
	maxBatch                 = 100              // 1 回に送るイベントの上限
	requestTimeout           = 15 * time.Second // 要求の時間切れの上限。実際はハートビートの間隔の 2 倍まで
)

// Agent は CLIENT の解析部。
type Agent struct {
	cfg     Config
	log     *slog.Logger
	id      pki.Identity
	cert    tls.Certificate // 秘密鍵の代わりに、執行部に署名を頼む crypto.Signer を持つ
	http    *http.Client
	base    string
	applied []byte // 最後に適用できた指示の署名（同じ指示を執行部に渡し直さない）
	pending []event.Event
	renewAt time.Time // 証明書の更新に失敗したとき、次に試す時刻
	offline bool      // CONTROLLER に送れていない（送れるようになるまで、ハートビートの間隔ごとに試す）
	dropped int       // 送れていないイベントが上限を超えて捨てた数（間隔ごとにまとめてログに残す）
}

// New は証明書から端末 ID を読んで Agent を作る。
func New(cfg Config) (*Agent, error) {
	if cfg.Executor == nil || cfg.CA == nil || !cfg.Controller.IsValid() {
		return nil, errors.New("client: CONTROLLER のアドレス、認証局、執行部は必須です")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = DefaultHeartbeatInterval
	}
	id, leaf, err := identity(cfg.Chain)
	if err != nil {
		return nil, err
	}
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("client: 端末の鍵が ed25519 ではありません")
	}
	a := &Agent{
		cfg:  cfg,
		log:  cfg.Logger.With("端末", id.ID),
		id:   id,
		cert: tls.Certificate{Certificate: cfg.Chain, Leaf: leaf, PrivateKey: executorSigner{pub, cfg.Executor}},
		base: "https://" + cfg.Controller.String(),
	}
	a.http = &http.Client{Timeout: requestTimeout, Transport: a.newTransport()}
	return a, nil
}

// ID は端末 ID を返す。
func (a *Agent) ID() string { return a.id.ID }

// Run は ctx が終わるまで、イベントの送信、ハートビート、指示の受け渡しを続ける。
func (a *Agent) Run(ctx context.Context) error {
	events := make(chan event.Event, 256)
	watchErr := make(chan error, 1)
	go func() { watchErr <- a.cfg.Executor.Watch(ctx, events) }()

	a.heartbeat(ctx)
	tick := time.NewTicker(a.cfg.HeartbeatInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			// 執行部の監視の後始末（固定した ARP の表のエントリを消すなど）を待つ。
			if watchErr != nil {
				select {
				case <-watchErr:
				case <-time.After(5 * time.Second):
				}
			}
			return nil
		case e := <-events:
			a.enqueue(e)
			for drained := false; !drained; {
				select {
				case e := <-events:
					a.enqueue(e)
				default:
					drained = true
				}
			}
			if !a.offline { // 送れない間は、イベントごとに接続し直さない
				a.flush(ctx)
			}
		case <-tick.C:
			if a.dropped > 0 {
				a.log.Warn("送れていないイベントが上限を超えたため、古いものを捨てました", "件数", a.dropped)
				a.dropped = 0
			}
			a.flush(ctx)
			a.heartbeat(ctx)
			a.sendEvidence(ctx)
			a.renewIfDue(ctx)
		case err := <-watchErr:
			if ctx.Err() != nil || errors.Is(err, ErrExecutorStopped) {
				return nil
			}
			a.log.Error("執行部からイベントを受け取れなくなりました。ハートビートは続けます", "エラー", err)
			watchErr = nil
		}
	}
}

// renewIfDue は、証明書の有効期間の残りが 3 分の 1 を切っていたら、CONTROLLER に同じ鍵での更新を求め、
// 執行部に確かめさせて保存してから使い始める（M1）。失敗したら、ハートビートの間隔の 10 倍の後に試し直す。
func (a *Agent) renewIfDue(ctx context.Context) {
	now := time.Now()
	if !pki.RenewalDue(a.cert.Leaf, now) || now.Before(a.renewAt) {
		return
	}
	a.renewAt = now.Add(10 * a.cfg.HeartbeatInterval)
	var resp api.CertificateResponse
	if err := a.post(ctx, api.PathCertificate, nil, &resp); err != nil {
		a.log.Warn("証明書を更新できません", "期限", a.cert.Leaf.NotAfter, "エラー", err)
		return
	}
	chain := append([][]byte{resp.Certificate}, resp.Chain...)
	if err := a.cfg.Executor.RenewCert(ctx, chain); err != nil {
		a.log.Error("更新した証明書を受け入れられません", "エラー", err)
		return
	}
	leaf, err := x509.ParseCertificate(resp.Certificate)
	if err != nil {
		return
	}
	a.cert = tls.Certificate{Certificate: chain, Leaf: leaf, PrivateKey: a.cert.PrivateKey}
	a.resetConnections() // 新しい証明書で接続し直す
}

func (a *Agent) enqueue(e event.Event) {
	if len(a.pending) >= maxPending {
		a.pending = a.pending[1:]
		a.dropped++
	}
	a.pending = append(a.pending, e)
}

// flush は送れていないイベントを送る。失敗したら残りは次の機会に送る。
func (a *Agent) flush(ctx context.Context) {
	for len(a.pending) > 0 {
		n := min(len(a.pending), maxBatch)
		var d api.Desired
		if err := a.post(ctx, api.PathEvents, api.EventBatch{Events: a.pending[:n]}, &d); err != nil {
			a.sent("イベント", err)
			return
		}
		a.sent("イベント", nil)
		a.pending = append([]event.Event(nil), a.pending[n:]...)
		a.apply(ctx, d)
	}
}

func (a *Agent) heartbeat(ctx context.Context) {
	env, err := a.cfg.Executor.Heartbeat(ctx)
	if err != nil {
		a.log.Error("ハートビートを作れません", "エラー", err)
		return
	}
	var d api.Desired
	if err := a.post(ctx, api.PathHeartbeat, env, &d); err != nil {
		a.sent("ハートビート", err)
		return
	}
	a.sent("ハートビート", nil)
	a.apply(ctx, d)
}

// evidencePerTick は、ハートビートの間隔ごとに送る証拠の数の上限（大きいので、ほかの送信を長く待たせない）。
const evidencePerTick = 2

// sendEvidence は、執行部が保存した証拠を CONTROLLER に送り、受け取られたら執行部に知らせる（C11）。
// CONTROLLER が中身を理由に受け付けなかった証拠（4xx）は、送り直しても受け付けられないので、受け取られたものとして先に進む
// （端末には控えが残る）。
func (a *Agent) sendEvidence(ctx context.Context) {
	if a.offline {
		return
	}
	for range evidencePerTick {
		id, env, ok, err := a.cfg.Executor.NextEvidence(ctx)
		if err != nil {
			a.log.Error("執行部から証拠を受け取れません", "エラー", err)
			return
		}
		if !ok {
			return
		}
		var d api.Desired
		err = a.post(ctx, api.PathEvidence, api.EvidenceUpload{Envelope: env}, &d)
		var he *httpError
		switch {
		case errors.As(err, &he) && he.status/100 == 4 && he.status != http.StatusForbidden:
			a.log.Error("CONTROLLER が証拠を受け付けません。端末に控えを残して、次の証拠に進みます", "ID", id, "エラー", err)
		case err != nil:
			a.sent("証拠", err)
			return
		default:
			a.sent("証拠", nil)
			a.log.Info("証拠を CONTROLLER に送りました", "ID", id)
			a.apply(ctx, d)
		}
		if err := a.cfg.Executor.AckEvidence(ctx, id); err != nil {
			a.log.Error("証拠を送ったことを記録できません", "ID", id, "エラー", err)
			return
		}
	}
}

// httpError は CONTROLLER がエラーで応答したこと。
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

// sent は CONTROLLER への送信の成否を記録する。ログは、送れなくなったときと、送れるようになったときだけ残す
// （CONTROLLER に届かない間に、同じ警告を送るたびに出さない）。
func (a *Agent) sent(what string, err error) {
	switch {
	case err != nil && !a.offline:
		a.offline = true
		a.log.Warn("CONTROLLER に送れません。送れるようになるまで、ハートビートの間隔ごとに試し直します", "送るもの", what, "エラー", err)
	case err != nil:
		a.log.Debug("CONTROLLER に送れません", "送るもの", what, "エラー", err)
	case a.offline:
		a.offline = false
		a.log.Info("CONTROLLER に送れるようになりました", "送れていないイベント", len(a.pending))
	}
}

// newTransport は CONTROLLER への接続の仕組みを作る。HTTP/2 の PING で接続の生存を確かめ、
// 応答のない接続は閉じる。
func (a *Agent) newTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig:     transport.ClientConfig(a.cfg.CA, a.cert, pki.RoleController),
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     time.Minute,
		HTTP2: &http.HTTP2Config{
			SendPingTimeout:  a.cfg.HeartbeatInterval,
			PingTimeout:      a.cfg.HeartbeatInterval,
			WriteByteTimeout: 2 * a.cfg.HeartbeatInterval,
		},
	}
}

// resetConnections は接続の仕組みを作り直し、次の要求で必ず接続し直す。
// アドレスが変わった後などは、古い接続が閉じられないまま応答しなくなるため、使い続けない。
// 古い接続は PING の時間切れで閉じられる。
func (a *Agent) resetConnections() {
	old, _ := a.http.Transport.(*http.Transport)
	a.http.Transport = a.newTransport()
	if old != nil {
		old.CloseIdleConnections()
	}
}

// post は要求を送る。切れた接続で待ち続けないよう、時間切れはハートビートの間隔の 2 倍までとし、
// 失敗したら接続し直す。
func (a *Agent) post(ctx context.Context, path string, body, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, min(requestTimeout, 2*a.cfg.HeartbeatInterval))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		a.resetConnections()
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e api.Error
		json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e)
		return &httpError{status: resp.StatusCode, msg: fmt.Sprintf("%s: %s: %s", path, resp.Status, e.Error)}
	}
	return json.NewDecoder(io.LimitReader(resp.Body, api.MaxBodyBytes)).Decode(out)
}

// apply は CONTROLLER の指示を執行部に渡す。検証と適用は執行部が行う。
func (a *Agent) apply(ctx context.Context, d api.Desired) {
	if len(d.Command.Signature) > 0 && bytes.Equal(d.Command.Signature, a.applied) {
		return
	}
	if err := a.cfg.Executor.Apply(ctx, d.Command); err != nil {
		a.log.Error("指示を適用できません。次の応答で再び試します", "エラー", err)
		return
	}
	a.applied = bytes.Clone(d.Command.Signature)
}
