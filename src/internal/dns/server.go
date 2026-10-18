// Package dns は GW の DNS リゾルバ（G3）を実装する。
//
// LAN の端末からの問い合わせを、ポリシー（Policy）の判定に従って上流に転送するか、遮断する。
// 許可リストで運用するグループでは、上流から得たアドレスを応答を返す前に GW の許可に加える
// （Verdict.Learn）。端末が応答を受け取ってすぐに接続しても通るようにするため。
// 問い合わせはすべて OnQuery で知らせ、記録する。キャッシュは持たない。
package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// Action は問い合わせへの対応。
type Action int

const (
	Forward Action = iota // 上流に転送する
	Block                 // 存在しない名前（NXDOMAIN）として返す
	NoData                // 該当するレコードなしとして返す（ECH の設定を含むレコードを返さないときなど）
	Refuse                // 問い合わせを断る（REFUSED）
)

func (a Action) String() string {
	return [...]string{"forward", "block", "nodata", "refuse"}[a]
}

// Verdict はポリシーの判定。
type Verdict struct {
	Action Action
	Reason string // 遮断の理由（記録用）
	Group  string // 端末のグループ（記録用）
	// Learn は、転送して得たアドレスを GW の許可に加える。nil なら加えない。
	Learn func(ctx context.Context, ips []netip.Addr, ttl time.Duration) error
}

// Policy は問い合わせへの対応を決める。
type Policy interface {
	Decide(client netip.Addr, q Question) Verdict
}

// QueryLog は 1 件の問い合わせの記録。
type QueryLog struct {
	Time    time.Time
	Client  netip.Addr
	Name    string
	Type    uint16
	Rcode   int
	Answers []Answer
	Action  Action
	Reason  string
	Group   string
}

// Config はリゾルバの設定。
type Config struct {
	Addr      netip.Addr // 待ち受けるアドレス（GW の LAN 側）
	Port      uint16     // 待ち受けるポート。既定 53
	Upstreams []*Upstream
	Policy    Policy
	OnQuery   func(QueryLog)
	Timeout   time.Duration // 上流への 1 回の問い合わせの時間切れ。既定 DefaultTimeout
	Logger    *slog.Logger
}

// 上限。
const (
	maxConcurrent = 256
	tcpIdle       = 10 * time.Second
	minUDPSize    = 512
)

// Server は DNS リゾルバ。
type Server struct {
	cfg Config
	log *slog.Logger
	sem chan struct{}
}

// New はリゾルバを作る。
func New(cfg Config) (*Server, error) {
	if len(cfg.Upstreams) == 0 || cfg.Policy == nil {
		return nil, errors.New("dns: 上流のサーバーとポリシーは必須です")
	}
	if cfg.Port == 0 {
		cfg.Port = 53
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{cfg: cfg, log: cfg.Logger, sem: make(chan struct{}, maxConcurrent)}, nil
}

// Serve は UDP と TCP で問い合わせを受け付け、ctx が終わるまで応答する（Listen と ServeConns をまとめたもの）。
func (s *Server) Serve(ctx context.Context) error {
	pc, ln, err := Listen(s.cfg.Addr, s.cfg.Port)
	if err != nil {
		return err
	}
	return s.ServeConns(ctx, pc, ln)
}

// Listen は addr のポート port（0 なら 53）で、UDP と TCP の待ち受けを開く。53 番には CAP_NET_BIND_SERVICE が必要。
// 権限を分けるとき（G12）は、執行部が開いて非特権の側に渡す。
func Listen(addr netip.Addr, port uint16) (net.PacketConn, net.Listener, error) {
	if port == 0 {
		port = 53
	}
	hostport := net.JoinHostPort(addr.String(), strconv.Itoa(int(port)))
	pc, err := net.ListenPacket("udp", hostport)
	if err != nil {
		return nil, nil, err
	}
	ln, err := net.Listen("tcp", hostport)
	if err != nil {
		pc.Close()
		return nil, nil, err
	}
	return pc, ln, nil
}

// ServeConns は Listen で開いた待ち受けで問い合わせを受け付け、ctx が終わるまで応答する。pc と ln は閉じる。
func (s *Server) ServeConns(ctx context.Context, pc net.PacketConn, ln net.Listener) error {
	addr := pc.LocalAddr().String()
	go func() { <-ctx.Done(); pc.Close(); ln.Close() }()
	defer func() {
		for _, u := range s.cfg.Upstreams {
			u.Close()
		}
	}()
	s.log.Info("DNS リゾルバを起動しました", "アドレス", addr, "上流", len(s.cfg.Upstreams))

	errc := make(chan error, 2)
	go func() { errc <- s.serveUDP(ctx, pc) }()
	go func() { errc <- s.serveTCP(ctx, ln) }()
	err := <-errc
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (s *Server) serveUDP(ctx context.Context, pc net.PacketConn) error {
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		client := addrOf(from)
		query := append([]byte(nil), buf[:n]...)
		select {
		case s.sem <- struct{}{}:
		default:
			continue // 同時に処理できる数を超えたら捨てる
		}
		go func() {
			defer func() { <-s.sem }()
			if resp := s.handle(ctx, client, query, true); resp != nil {
				pc.WriteTo(resp, from)
			}
		}()
	}
}

func (s *Server) serveTCP(ctx context.Context, ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			client := addrOf(c.RemoteAddr())
			for {
				c.SetDeadline(time.Now().Add(tcpIdle))
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, query); err != nil {
					return
				}
				resp := s.handle(ctx, client, query, false)
				if resp == nil {
					return
				}
				out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
				if _, err := c.Write(append(out, resp...)); err != nil {
					return
				}
			}
		}()
	}
}

func addrOf(a net.Addr) netip.Addr {
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// handle は 1 件の問い合わせに応答する。応答しない（解析できない）場合は nil。
func (s *Server) handle(ctx context.Context, client netip.Addr, raw []byte, udp bool) []byte {
	q, err := Parse(raw)
	if err != nil || q.Response() {
		return nil
	}
	if q.Opcode() != 0 {
		return Reply(raw, q, RcodeNotImp, false)
	}
	v := s.cfg.Policy.Decide(client, q.Question)
	entry := QueryLog{Time: time.Now(), Client: client, Name: q.Question.Name, Type: q.Question.Type, Action: v.Action, Reason: v.Reason, Group: v.Group}

	var resp []byte
	switch v.Action {
	case Block:
		resp, entry.Rcode = Reply(raw, q, RcodeNXDomain, false), RcodeNXDomain
	case NoData:
		resp = Reply(raw, q, RcodeSuccess, false)
	case Refuse:
		resp, entry.Rcode = Reply(raw, q, RcodeRefused, false), RcodeRefused
	default:
		resp = s.forward(ctx, raw, q)
		r, err := Parse(resp)
		if err != nil {
			resp, entry.Rcode = Reply(raw, q, RcodeServFail, false), RcodeServFail
			break
		}
		entry.Rcode, entry.Answers = r.Rcode(), r.Answers
		if v.Learn != nil && r.Rcode() == RcodeSuccess {
			if ips, ttl := addresses(r.Answers); len(ips) > 0 {
				if err := v.Learn(ctx, ips, ttl); err != nil {
					// 許可に加えられなければ、端末は接続できない。応答は返して、記録に残す。
					s.log.Error("DNS で得たアドレスを許可に加えられません", "名前", q.Question.Name, "エラー", err)
				}
			}
		}
	}
	if udp && len(resp) > max(minUDPSize, q.UDPSize) {
		resp = Reply(raw, q, entry.Rcode, true)
	}
	if s.cfg.OnQuery != nil {
		s.cfg.OnQuery(entry)
	}
	return resp
}

// forward は上流に順に問い合わせ、最初に得た応答を返す。すべて失敗したら SERVFAIL を返す。
func (s *Server) forward(ctx context.Context, raw []byte, q *Message) []byte {
	for _, u := range s.cfg.Upstreams {
		qctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
		resp, err := u.Exchange(qctx, raw)
		cancel()
		if err == nil {
			return resp
		}
		s.log.Warn("上流の DNS サーバーに問い合わせられません", "上流", u.String(), "エラー", err)
	}
	return Reply(raw, q, RcodeServFail, false)
}

// addresses は応答のアドレスと、最も短い TTL を返す。
func addresses(answers []Answer) ([]netip.Addr, time.Duration) {
	var ips []netip.Addr
	var ttl uint32
	first := true
	for _, a := range answers {
		if a.IP.IsValid() {
			ips = append(ips, a.IP)
			if first || a.TTL < ttl {
				ttl, first = a.TTL, false
			}
		}
	}
	return ips, time.Duration(ttl) * time.Second
}
