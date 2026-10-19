package privsep

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"time"

	"susanoo/internal/controller"
	"susanoo/internal/egress"
	"susanoo/internal/intel"
	"susanoo/internal/policy"
	"susanoo/internal/sign"
)

// GW の権限の分離（G12）。
//
// GW は root で起動し、ソケット（ARP、DHCP、DNS、通信の記録の netlink、管理通信）を開き、nftables のルールを入れてから、
// 自分自身を 2 つの非特権の利用者で起動し直して、CONTROLLER と LAN 側の処理とする（ソケットは受け継がせる）。
// 執行部は CAP_NET_ADMIN だけを残し、次の要求だけを受け付ける。値はどれも執行部の側で検証してから nftables に反映する。
//
//   - quarantine（CONTROLLER から）：端末単位の遮断（G9）の一覧の置き換え。アドレスと MAC アドレスと隔離の段階は nft の側で検証する
//   - membership（CONTROLLER から）：端末のグループ（外部通信の制御の所属の集合）。ポリシーにないグループは既定のグループとして扱う
//   - learn（LAN 側の処理から）：DNS で得たアドレスの許可への追加。集合の名前ではなく、ポリシーの中の番号（egress.Target）で受け取る
//   - issue_client（CONTROLLER から）：端末の証明書の発行（M1 の更新）。役割は端末に限る。認証局の秘密鍵は執行部だけが持つ
//   - apply_policy、promote_policy、abort_policy（CONTROLLER から）：ポリシーの配布（M2）。署名と版数は執行部が
//     ポリシー専用の公開鍵で確かめる（CONTROLLER は署名の鍵を持たない）
//   - apply_intel（CONTROLLER から）：脅威情報の配布（G7）。署名と版数は執行部がポリシー専用の公開鍵で確かめる
//
// つながりごとに受け付ける要求を決め（GWExecutor）、それ以外の要求が届いたら、乗っ取られた恐れがあるとみなしてつながりを切る。
// 執行部から CONTROLLER には、設定ファイルの変更（G12）と、更新した CONTROLLER の証明書（M1）と、DNS で得たアドレスを
// 許可に加えた結果（2m-2。断ったアドレスを含む）を、
// LAN 側の処理には、切り替えたポリシー（M2）と、DNS で引かせない脅威情報のドメイン（G7）を知らせる。CONTROLLER と LAN 側の処理のつながりは lan.go。

// GW の非特権のプロセスから執行部への要求と、執行部からの知らせ。
const (
	reqQuarantine        = "quarantine"
	reqMembership        = "membership"
	reqLearn             = "learn"
	reqIssueClient       = "issue_client"
	reqApplyPolicy       = "apply_policy"
	reqPromotePolicy     = "promote_policy"
	reqAbortPolicy       = "abort_policy"
	reqApplyIntel        = "apply_intel"
	noticeConfigChanged  = "config_changed"
	noticeControllerCert = "controller_cert"
	noticePolicy         = "policy"
	noticeIntel          = "intel"
	noticeLearnReport    = "learn_report"
)

// MembershipSetter は端末のグループを外部通信の制御に反映する。
type MembershipSetter interface {
	SetMembership(ctx context.Context, m egress.Membership) error
}

// Learner は DNS で得たアドレスを許可に加える。
type Learner interface {
	Learn(ctx context.Context, t egress.Target, ips []netip.Addr, ttl time.Duration) error
}

// GWExecutor は、1 つのつながりで執行部が受け付ける要求と、その働き。nil の要求は受け付けない。
type GWExecutor struct {
	Quarantine controller.Enforcer      // quarantine（CONTROLLER のつながり。enforce: false なら nil）
	Membership MembershipSetter         // membership（CONTROLLER のつながり。ルーター方式でなければ nil）
	Learner    Learner                  // learn（LAN 側の処理のつながり）
	Issuer     controller.Issuer        // issue_client（CONTROLLER のつながり）
	Policies   controller.PolicyManager // apply_policy、promote_policy、abort_policy（CONTROLLER のつながり）
	Intel      controller.IntelManager  // apply_intel（CONTROLLER のつながり）
}

type applyIntelBody struct {
	Envelope sign.Envelope `json:"envelope"`
}

type applyPolicyBody struct {
	Envelope sign.Envelope `json:"envelope"`
	Canary   bool          `json:"canary,omitempty"`
}

// GWNotices は、執行部から非特権のプロセスに知らせること。nil のチャネルは使わない。
type GWNotices struct {
	Changes  <-chan string                 // 設定ファイルの変更
	Certs    <-chan []byte                 // 更新した CONTROLLER の証明書（DER）
	Policies <-chan controller.PolicyState // 切り替えたポリシー
	Intel    <-chan intel.Blocklist        // DNS で引かせない脅威情報のドメイン
	Learns   <-chan egress.LearnReport     // DNS で得たアドレスを許可に加えた結果（2m-2）
}

type issueBody struct {
	ID  string            `json:"id"`
	Pub ed25519.PublicKey `json:"pub"`
}

type quarantineBody struct {
	Addrs map[netip.Addr]policy.IsolationLevel `json:"addrs"`
	MACs  map[string]policy.IsolationLevel     `json:"macs"`
}

type learnBody struct {
	Target egress.Target `json:"target"`
	IPs    []netip.Addr  `json:"ips"`
	TTL    time.Duration `json:"ttl"`
}

// ErrWorkerStopped は、GW の非特権のプロセスとのつながりが切れたことを表す。
var ErrWorkerStopped = errors.New("privsep: GW の非特権のプロセスが止まりました")

// ServeGW は GW の執行部の側。非特権のプロセスに hello を送り、out に届いたことを知らせながら、
// ex で受け付ける要求に応える。ctx が終わると nil を、つながりが切れると
// ErrWorkerStopped を返す。不正なデータや受け付けない要求が届いたら、乗っ取られた恐れがあるので、
// つながりを切ってエラーを返す。rwc は閉じる。
func ServeGW(ctx context.Context, rwc io.ReadWriteCloser, ex GWExecutor, hello any, out GWNotices, log *slog.Logger) error {
	defer rwc.Close()
	c := newConn(rwc)
	if err := sendHello(c, hello); err != nil {
		return fmt.Errorf("privsep: GW の非特権のプロセスに設定を渡せません: %w", err)
	}
	p := newPeer(c, rwc, handlers{
		request: func(ctx context.Context, typ string, body json.RawMessage) (any, error) {
			resp, err := handleGW(ctx, ex, typ, body)
			if err != nil {
				log.Warn("非特権のプロセスの要求を断りました", "要求", typ, "理由", err)
			}
			return resp, err
		},
		// DNS の応答ごとの追加は並行して受け付け、執行部の側で 1 回の nft の実行にまとめる。
		concurrent: func(typ string) bool { return typ == reqLearn },
	}, log, ErrWorkerStopped)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			var err error
			select {
			case path := <-out.Changes:
				err = p.notify(noticeConfigChanged, path)
			case der := <-out.Certs:
				err = p.notify(noticeControllerCert, der)
			case st := <-out.Policies:
				err = p.notify(noticePolicy, st)
			case b := <-out.Intel:
				err = p.notify(noticeIntel, b)
			case r := <-out.Learns:
				err = p.notify(noticeLearnReport, r)
			case <-ctx.Done():
				return
			}
			if err != nil {
				cancel()
				return
			}
		}
	}()
	err := p.run(ctx)
	cancel()
	<-done
	if errors.Is(err, io.EOF) {
		return ErrWorkerStopped
	}
	if err != nil {
		return fmt.Errorf("GW の非特権のプロセスから不正なデータが届きました。つながりを切ります: %w", err)
	}
	return nil
}

func handleGW(ctx context.Context, ex GWExecutor, typ string, body json.RawMessage) (any, error) {
	refuse := protocolError{fmt.Errorf("privsep: このつながりでは要求 %q を受け付けません", typ)}
	switch typ {
	case reqQuarantine:
		if ex.Quarantine == nil {
			return nil, refuse
		}
		var b quarantineBody
		if err := decodeBody(body, &b); err != nil {
			return nil, err
		}
		return nil, ex.Quarantine.Sync(ctx, b.Addrs, b.MACs)
	case reqMembership:
		if ex.Membership == nil {
			return nil, refuse
		}
		var m egress.Membership
		if err := decodeBody(body, &m); err != nil {
			return nil, err
		}
		return nil, ex.Membership.SetMembership(ctx, m)
	case reqLearn:
		if ex.Learner == nil {
			return nil, refuse
		}
		var b learnBody
		if err := decodeBody(body, &b); err != nil {
			return nil, err
		}
		return nil, ex.Learner.Learn(ctx, b.Target, b.IPs, b.TTL)
	case reqIssueClient:
		if ex.Issuer == nil {
			return nil, refuse
		}
		var b issueBody
		if err := decodeBody(body, &b); err != nil {
			return nil, err
		}
		chain, err := ex.Issuer.IssueClient(ctx, b.ID, b.Pub)
		if err != nil {
			return nil, err
		}
		var ders [][]byte
		for _, c := range chain {
			ders = append(ders, c.Raw)
		}
		return ders, nil
	case reqApplyPolicy, reqPromotePolicy, reqAbortPolicy:
		if ex.Policies == nil {
			return nil, refuse
		}
		switch typ {
		case reqApplyPolicy:
			var b applyPolicyBody
			if err := decodeBody(body, &b); err != nil {
				return nil, err
			}
			return ex.Policies.ApplyPolicy(ctx, b.Envelope, b.Canary)
		case reqPromotePolicy:
			return ex.Policies.PromotePolicy(ctx)
		default:
			return ex.Policies.AbortPolicy(ctx)
		}
	case reqApplyIntel:
		if ex.Intel == nil {
			return nil, refuse
		}
		var b applyIntelBody
		if err := decodeBody(body, &b); err != nil {
			return nil, err
		}
		return nil, ex.Intel.ApplyIntel(ctx, b.Envelope)
	}
	return nil, fmt.Errorf("知らない要求 %q です", typ)
}

// GWRemote は GW の非特権のプロセスの側。執行部への要求で、端末単位の遮断（controller.Enforcer）と
// 外部通信の制御の反映（egress.Enforcer）を満たす。執行部は、つながりごとに受け付ける要求を決めている。
type GWRemote struct {
	p        *peer
	rwc      io.Closer
	changes  chan string
	certs    chan []byte
	policies chan controller.PolicyState
	intel    chan intel.Blocklist
	learns   chan egress.LearnReport
}

var (
	_ controller.Enforcer      = (*GWRemote)(nil)
	_ controller.Issuer        = (*GWRemote)(nil)
	_ controller.PolicyManager = (*GWRemote)(nil)
	_ controller.IntelManager  = (*GWRemote)(nil)
	_ egress.Enforcer          = (*GWRemote)(nil)
)

// DialGW は執行部からの hello を受け取って hello に解析し、GWRemote を作る。
func DialGW(rwc io.ReadWriteCloser, hello any, log *slog.Logger) (*GWRemote, error) {
	c := newConn(rwc)
	if err := recvHello(c, hello); err != nil {
		return nil, fmt.Errorf("privsep: 執行部から設定を受け取れません: %w", err)
	}
	r := &GWRemote{rwc: rwc, changes: make(chan string, 16), certs: make(chan []byte, 1), policies: make(chan controller.PolicyState, 1),
		intel: make(chan intel.Blocklist, 1), learns: make(chan egress.LearnReport, learnReportQueue)}
	r.p = newPeer(c, rwc, handlers{notice: r.notice}, log, ErrExecutorStopped)
	go func() {
		if err := r.p.run(context.Background()); err != nil && !errors.Is(err, io.EOF) {
			log.Error("執行部から不正なデータが届きました", "エラー", err)
		}
	}()
	return r, nil
}

func (r *GWRemote) notice(typ string, body json.RawMessage) error {
	switch typ {
	case noticeConfigChanged:
		var path string
		if err := decodeBody(body, &path); err != nil {
			return err
		}
		select {
		case r.changes <- path:
		default: // 受け取り手が遅れているときは捨てる（変更は次の確認でも知らせる）
		}
	case noticeControllerCert:
		var der []byte
		if err := decodeBody(body, &der); err != nil {
			return err
		}
		select {
		case <-r.certs: // 古いものは捨て、新しいものだけを残す
		default:
		}
		r.certs <- der
	case noticePolicy:
		var st controller.PolicyState
		if err := decodeBody(body, &st); err != nil {
			return err
		}
		select {
		case <-r.policies: // 古いものは捨て、新しいものだけを残す
		default:
		}
		r.policies <- st
	case noticeIntel:
		var b intel.Blocklist
		if err := decodeBody(body, &b); err != nil {
			return err
		}
		select {
		case <-r.intel: // 古いものは捨て、新しいものだけを残す
		default:
		}
		r.intel <- b
	case noticeLearnReport:
		var lr egress.LearnReport
		if err := decodeBody(body, &lr); err != nil {
			return err
		}
		select {
		case r.learns <- lr:
		default: // 受け取り手が遅れているときは捨てる（突き合わせは見逃してよい）
		}
	default:
		return fmt.Errorf("privsep: 知らない知らせ %q です", typ)
	}
	return nil
}

// Policies は、執行部が切り替えたポリシーを届けるチャネルを返す。
func (r *GWRemote) Policies() <-chan controller.PolicyState { return r.policies }

// ApplyPolicy は署名付きのポリシーの適用を執行部に頼む（controller.PolicyManager）。
func (r *GWRemote) ApplyPolicy(ctx context.Context, env sign.Envelope, canary bool) (controller.PolicyState, error) {
	var st controller.PolicyState
	err := r.p.call(ctx, reqApplyPolicy, applyPolicyBody{Envelope: env, Canary: canary}, &st)
	return st, err
}

func (r *GWRemote) PromotePolicy(ctx context.Context) (controller.PolicyState, error) {
	var st controller.PolicyState
	err := r.p.call(ctx, reqPromotePolicy, nil, &st)
	return st, err
}

func (r *GWRemote) AbortPolicy(ctx context.Context) (controller.PolicyState, error) {
	var st controller.PolicyState
	err := r.p.call(ctx, reqAbortPolicy, nil, &st)
	return st, err
}

// Intel は、執行部が切り替えた、DNS で引かせない脅威情報のドメインを届けるチャネルを返す。
func (r *GWRemote) Intel() <-chan intel.Blocklist { return r.intel }

// ApplyIntel は署名付きの脅威情報の適用を執行部に頼む（controller.IntelManager）。
func (r *GWRemote) ApplyIntel(ctx context.Context, env sign.Envelope) error {
	return r.p.call(ctx, reqApplyIntel, applyIntelBody{Envelope: env}, nil)
}

// Certs は、執行部が更新した CONTROLLER の証明書（DER）を届けるチャネルを返す。
func (r *GWRemote) Certs() <-chan []byte { return r.certs }

// IssueClient は端末の証明書の発行を執行部に頼む（controller.Issuer）。
func (r *GWRemote) IssueClient(ctx context.Context, id string, pub ed25519.PublicKey) ([]*x509.Certificate, error) {
	var ders [][]byte
	if err := r.p.call(ctx, reqIssueClient, issueBody{ID: id, Pub: pub}, &ders); err != nil {
		return nil, err
	}
	if len(ders) == 0 || len(ders) > 4 {
		return nil, errors.New("privsep: 発行した証明書の連なりが不正です")
	}
	var chain []*x509.Certificate
	for _, der := range ders {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		chain = append(chain, c)
	}
	return chain, nil
}

// Changes は、執行部が見つけた設定ファイルの変更を届けるチャネルを返す。
func (r *GWRemote) Changes() <-chan string { return r.changes }

// learnReportQueue は、CONTROLLER に渡していない許可への追加の結果の上限。
const learnReportQueue = 256

// Learns は、執行部が DNS で得たアドレスを許可に加えた結果を受け取るチャネルを返す（2m-2）。
func (r *GWRemote) Learns() <-chan egress.LearnReport { return r.learns }

// Done は執行部とのつながりが切れたら閉じるチャネルを返す。
func (r *GWRemote) Done() <-chan struct{} { return r.p.done }

// Close はつながりを切る。
func (r *GWRemote) Close() error { return r.rwc.Close() }

func (r *GWRemote) Sync(ctx context.Context, addrs map[netip.Addr]policy.IsolationLevel, macs map[string]policy.IsolationLevel) error {
	return r.p.call(ctx, reqQuarantine, quarantineBody{Addrs: addrs, MACs: macs}, nil)
}

func (r *GWRemote) SetMembership(ctx context.Context, m egress.Membership) error {
	return r.p.call(ctx, reqMembership, m, nil)
}

func (r *GWRemote) Learn(ctx context.Context, t egress.Target, ips []netip.Addr, ttl time.Duration) error {
	return r.p.call(ctx, reqLearn, learnBody{Target: t, IPs: ips, TTL: ttl}, nil)
}
