package privsep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
)

// message は 1 つのフレーム。次の 3 種類がある。
//
//   - 要求：ID が 0 でなく、Reply が偽。相手は同じ ID の応答を返す
//   - 応答：Reply が真
//   - 知らせ：ID が 0。応答は返さない
type message struct {
	Type  string          `json:"type"`
	ID    uint64          `json:"id,omitempty"`
	Reply bool            `json:"reply,omitempty"`
	Error string          `json:"error,omitempty"`
	Body  json.RawMessage `json:"body,omitempty"`
}

// handlers は、peer が受け取った要求と知らせの扱い。
type handlers struct {
	// request は要求に応える。届いた順に 1 つずつ呼ぶ（concurrent が真を返す種類だけは並行して呼ぶ）。
	// 応える途中で相手に要求を送ってはならない（互いの応答を待ち合って止まる恐れがある）。
	request    func(ctx context.Context, typ string, body json.RawMessage) (any, error)
	concurrent func(typ string) bool
	// notice は知らせを受け取る。読み込みのゴルーチンから呼ぶので、待たせてはならない。
	// エラーを返すと、不正なデータとみなしてつながりを切る。
	notice func(typ string, body json.RawMessage) error
}

// protocolError は、相手から不正なデータが届いたことを表す。乗っ取られた恐れがあるので、つながりを切る。
type protocolError struct{ err error }

func (e protocolError) Error() string { return e.err.Error() }
func (e protocolError) Unwrap() error { return e.err }

// maxConcurrent は並行して応える要求の上限。
const maxConcurrent = 64

// peer はつながりの片側。要求を送って応答を待ち、相手の要求に応え、知らせをやり取りする。
type peer struct {
	c       *conn
	rwc     io.Closer
	h       handlers
	log     *slog.Logger
	stopped error // つながりが切れた後の要求に返すエラー

	mu      sync.Mutex
	next    uint64
	waiting map[uint64]chan message
	done    chan struct{}
	failed  error // 不正なデータで切ったときの理由
}

func newPeer(c *conn, rwc io.Closer, h handlers, log *slog.Logger, stopped error) *peer {
	return &peer{c: c, rwc: rwc, h: h, log: log, stopped: stopped, waiting: map[uint64]chan message{}, done: make(chan struct{})}
}

// run は、ctx が終わるか、つながりが切れるか、不正なデータが届くまで読み続ける。
// ctx が終わったら nil を、相手が閉じたら io.EOF を、不正なデータならそのエラーを返す。rwc は閉じる。
func (p *peer) run(ctx context.Context) error {
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	context.AfterFunc(ctx, func() { p.rwc.Close() })

	var wg sync.WaitGroup
	reqs := make(chan message, maxConcurrent)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for m := range reqs {
			p.serve(ctx, m)
		}
	}()
	err := p.read(ctx, reqs, &wg)
	close(reqs)
	p.rwc.Close()
	p.mu.Lock()
	close(p.done)
	if p.failed != nil {
		err = p.failed
	}
	p.mu.Unlock()
	cancel()
	wg.Wait()
	switch {
	case parent.Err() != nil:
		return nil
	case errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed):
		return io.EOF
	}
	return err
}

func (p *peer) read(ctx context.Context, reqs chan<- message, wg *sync.WaitGroup) error {
	sem := make(chan struct{}, maxConcurrent)
	for {
		var m message
		if err := p.c.recv(&m); err != nil {
			return err
		}
		switch {
		case m.Reply:
			p.mu.Lock()
			ch := p.waiting[m.ID]
			delete(p.waiting, m.ID)
			p.mu.Unlock()
			if ch != nil {
				ch <- m
			}
		case m.ID == 0:
			if p.h.notice == nil {
				return protocolError{fmt.Errorf("privsep: 知らせ %q は受け付けません", m.Type)}
			}
			if err := p.h.notice(m.Type, m.Body); err != nil {
				return protocolError{err}
			}
		case p.h.concurrent != nil && p.h.concurrent(m.Type):
			sem <- struct{}{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				p.serve(ctx, m)
			}()
		default:
			select {
			case reqs <- m:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

// serve は 1 つの要求に応える。中身が不正なら、つながりを切る。
func (p *peer) serve(ctx context.Context, m message) {
	reply := message{Type: m.Type, ID: m.ID, Reply: true}
	var resp any
	var err error
	if p.h.request == nil {
		err = fmt.Errorf("要求 %q は受け付けません", m.Type)
	} else {
		resp, err = p.h.request(ctx, m.Type, m.Body)
	}
	if pe := (protocolError{}); errors.As(err, &pe) {
		p.fail(pe)
		return
	}
	if err != nil {
		reply.Error = err.Error()
	} else if resp != nil {
		if reply.Body, err = json.Marshal(resp); err != nil {
			reply.Error = err.Error()
		}
	}
	p.c.send(reply)
}

// fail は不正なデータを受け取ったとして、つながりを切る。
func (p *peer) fail(err error) {
	p.mu.Lock()
	if p.failed == nil {
		p.failed = err
	}
	p.mu.Unlock()
	p.rwc.Close()
}

// call は要求を送って応答を待ち、応答の中身を out に解析する。
func (p *peer) call(ctx context.Context, typ string, body, out any) error {
	var data json.RawMessage
	if body != nil {
		var err error
		if data, err = json.Marshal(body); err != nil {
			return err
		}
	}
	ch := make(chan message, 1)
	p.mu.Lock()
	select {
	case <-p.done:
		p.mu.Unlock()
		return p.stopped
	default:
	}
	p.next++
	id := p.next
	p.waiting[id] = ch
	p.mu.Unlock()
	forget := func() {
		p.mu.Lock()
		delete(p.waiting, id)
		p.mu.Unlock()
	}
	if err := p.c.send(message{Type: typ, ID: id, Body: data}); err != nil {
		forget()
		if errors.Is(err, errFrameTooLarge) {
			return err // 送っていないので、つながりは使える
		}
		return p.stopped
	}
	select {
	case m := <-ch:
		if m.Error != "" {
			return fmt.Errorf("%s", m.Error)
		}
		if out != nil {
			return decodeBody(m.Body, out)
		}
		return nil
	case <-p.done:
		return p.stopped
	case <-ctx.Done():
		forget()
		return ctx.Err()
	}
}

// notify は知らせを送る。
func (p *peer) notify(typ string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return p.c.send(message{Type: typ, Body: data})
}

// decodeBody は中身を v に解析する。知らない項目や余分なデータがあれば、不正なデータとする。
func decodeBody(body json.RawMessage, v any) error {
	if err := parseFrame(body, v); err != nil {
		return protocolError{err}
	}
	return nil
}

// sendHello はつながりの最初に、相手が動くのに必要な情報を送る。
func sendHello(c *conn, hello any) error {
	data, err := json.Marshal(hello)
	if err != nil {
		return err
	}
	return c.send(message{Type: noticeHello, Body: data})
}

// recvHello はつながりの最初の知らせを受け取り、hello に解析する。
func recvHello(c *conn, hello any) error {
	var m message
	if err := c.recv(&m); err != nil {
		return err
	}
	if m.Type != noticeHello || m.ID != 0 || m.Reply {
		return fmt.Errorf("privsep: 最初の知らせが設定ではありません（%q）", m.Type)
	}
	return decodeBody(m.Body, hello)
}
