package privsep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"susanoo/internal/client"
	"susanoo/internal/event"
	"susanoo/internal/sign"
)

// CLIENT の解析部から執行部への要求と、執行部からの知らせ。
const (
	reqHeartbeat = "heartbeat"  // 署名付きのハートビートを作る
	reqApply     = "apply"      // 署名付きの指示を適用する
	reqSignTLS   = "sign_tls"   // TLS 1.3 のクライアント認証の署名を作る
	reqRenewCert = "renew_cert" // 更新した証明書を確かめて保存する
	noticeEvent  = "event"      // 検知したイベント
)

// Serve は CLIENT の執行部の側。解析部に hello を送り、ex が検知したイベントを送りながら、
// 解析部の要求に 1 つずつ応える。ctx が終わると nil を、解析部とのつながりが切れると ErrAnalyzerStopped を返す。
// 解析部から不正なデータが届いたら、乗っ取られた恐れがあるので、つながりを切ってエラーを返す。rwc は閉じる。
func Serve(ctx context.Context, rwc io.ReadWriteCloser, ex client.Executor, hello Hello, log *slog.Logger) error {
	defer rwc.Close()
	c := newConn(rwc)
	if err := sendHello(c, hello); err != nil {
		return fmt.Errorf("privsep: 解析部に設定を渡せません: %w", err)
	}
	p := newPeer(c, rwc, handlers{request: func(ctx context.Context, typ string, body json.RawMessage) (any, error) {
		resp, err := handleClient(ctx, ex, typ, body)
		if err != nil {
			log.Warn("解析部の要求を断りました", "要求", typ, "理由", err)
		}
		return resp, err
	}}, log, ErrAnalyzerStopped)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	events := make(chan event.Event, 256)
	wg.Add(2)
	go func() {
		defer wg.Done()
		ex.Watch(ctx, events)
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case e := <-events:
				if err := p.notify(noticeEvent, e); err != nil {
					cancel()
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	err := p.run(ctx)
	cancel()
	wg.Wait()
	if errors.Is(err, io.EOF) {
		return ErrAnalyzerStopped
	}
	if err != nil {
		return fmt.Errorf("解析部から不正なデータが届きました。つながりを切ります: %w", err)
	}
	return nil
}

// handleClient は解析部の要求に応える。
func handleClient(ctx context.Context, ex client.Executor, typ string, body json.RawMessage) (any, error) {
	switch typ {
	case reqHeartbeat:
		return ex.Heartbeat(ctx)
	case reqApply:
		var env sign.Envelope
		if err := decodeBody(body, &env); err != nil {
			return nil, err
		}
		return nil, ex.Apply(ctx, env)
	case reqSignTLS:
		var msg []byte
		if err := decodeBody(body, &msg); err != nil {
			return nil, err
		}
		return ex.SignTLS(ctx, msg)
	case reqRenewCert:
		var der []byte
		if err := decodeBody(body, &der); err != nil {
			return nil, err
		}
		return nil, ex.RenewCert(ctx, der)
	}
	return nil, fmt.Errorf("知らない要求 %q です", typ)
}

// maxQueue は、解析部が受け取ってまだ渡していないイベントの上限。超えたら古いものを捨てる。
const maxQueue = 10000

// Remote は CLIENT の解析部の側。別のプロセスの執行部に要求を送る client.Executor。
//
// 受け取ったイベントは内部のキューに入れ、読み込みのゴルーチンは決して待たせない。待たせると、
// TLS の署名の応答を待つ Agent とイベントの受け渡しが互いを待ち合って止まるため。
type Remote struct {
	p   *peer
	rwc io.Closer
	log *slog.Logger

	qmu     sync.Mutex
	queue   []event.Event
	dropped int
	ready   chan struct{}
}

var _ client.Executor = (*Remote)(nil)

// Dial は執行部からの hello を受け取り、Remote を作る。
func Dial(rwc io.ReadWriteCloser, log *slog.Logger) (*Remote, Hello, error) {
	c := newConn(rwc)
	var hello Hello
	if err := recvHello(c, &hello); err != nil {
		return nil, Hello{}, fmt.Errorf("privsep: 執行部から設定を受け取れません: %w", err)
	}
	r := &Remote{rwc: rwc, log: log, ready: make(chan struct{}, 1)}
	r.p = newPeer(c, rwc, handlers{notice: r.notice}, log, ErrExecutorStopped)
	go func() {
		if err := r.p.run(context.Background()); err != nil && !errors.Is(err, io.EOF) {
			log.Error("執行部から不正なデータが届きました", "エラー", err)
		}
	}()
	return r, hello, nil
}

// Done は執行部とのつながりが切れたら閉じるチャネルを返す。
func (r *Remote) Done() <-chan struct{} { return r.p.done }

// Close はつながりを切る。
func (r *Remote) Close() error { return r.rwc.Close() }

func (r *Remote) notice(typ string, body json.RawMessage) error {
	if typ != noticeEvent {
		return fmt.Errorf("privsep: 知らない知らせ %q です", typ)
	}
	var e event.Event
	if err := decodeBody(body, &e); err != nil {
		return err
	}
	r.qmu.Lock()
	if len(r.queue) >= maxQueue {
		r.queue = r.queue[1:]
		r.dropped++
	}
	r.queue = append(r.queue, e)
	r.qmu.Unlock()
	select {
	case r.ready <- struct{}{}:
	default:
	}
	return nil
}

func (r *Remote) Heartbeat(ctx context.Context) (sign.Envelope, error) {
	var env sign.Envelope
	err := r.p.call(ctx, reqHeartbeat, nil, &env)
	return env, err
}

func (r *Remote) Apply(ctx context.Context, cmd sign.Envelope) error {
	return r.p.call(ctx, reqApply, cmd, nil)
}

func (r *Remote) SignTLS(ctx context.Context, message []byte) ([]byte, error) {
	var sig []byte
	err := r.p.call(ctx, reqSignTLS, message, &sig)
	return sig, err
}

func (r *Remote) RenewCert(ctx context.Context, der []byte) error {
	return r.p.call(ctx, reqRenewCert, der, nil)
}

// Watch は執行部から届いたイベントを out に送る。
func (r *Remote) Watch(ctx context.Context, out chan<- event.Event) error {
	for {
		r.qmu.Lock()
		q, dropped := r.queue, r.dropped
		r.queue, r.dropped = nil, 0
		r.qmu.Unlock()
		if dropped > 0 {
			r.log.Warn("イベントが多すぎるため、古いものを捨てました", "件数", dropped)
		}
		for _, e := range q {
			select {
			case out <- e:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		select {
		case <-r.ready:
		case <-r.p.done:
			return ErrExecutorStopped
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
