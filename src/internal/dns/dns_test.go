package dns

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 試験の通信はループバック（127.0.0.1）だけで行う。

// answer は試験用の応答を作る。records は名前ごとの A レコード（なければ NXDOMAIN）。
func answer(query []byte, records map[string]string, ttl uint32, pad int) []byte {
	q, err := Parse(query)
	if err != nil {
		return nil
	}
	ip, ok := records[q.Question.Name]
	if !ok {
		return Reply(query, q, RcodeNXDomain, false)
	}
	resp := Reply(query, q, RcodeSuccess, false)
	n := 1 + pad
	binary.BigEndian.PutUint16(resp[6:], uint16(n))
	for i := range n {
		a := netip.MustParseAddr(ip)
		if i > 0 {
			a = netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
		}
		resp = append(resp, 0xc0, 12) // 問い合わせの名前への圧縮
		resp = binary.BigEndian.AppendUint16(resp, TypeA)
		resp = binary.BigEndian.AppendUint16(resp, 1)
		resp = binary.BigEndian.AppendUint32(resp, ttl)
		resp = binary.BigEndian.AppendUint16(resp, 4)
		resp = append(resp, a.AsSlice()...)
	}
	return resp
}

// fakeUpstream は試験用の上流の DNS サーバー（UDP と TCP）。
type fakeUpstream struct {
	addr    netip.AddrPort
	records map[string]string
	pad     atomic.Int32 // 応答に足すレコードの数（大きな応答の試験用）
	spoof   atomic.Bool  // 偽の応答を先に送る
	udp     atomic.Int32
	tcp     atomic.Int32
}

func startUpstream(t *testing.T, records map[string]string) *fakeUpstream {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close(); ln.Close() })
	u := &fakeUpstream{addr: netip.MustParseAddrPort(pc.LocalAddr().String()), records: records}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			u.udp.Add(1)
			resp := answer(buf[:n], u.records, 300, int(u.pad.Load()))
			if u.spoof.Load() {
				// 偽の応答（ID が違う）を先に送る。
				bad := append([]byte(nil), resp...)
				bad[0] ^= 0xff
				pc.WriteTo(bad, from)
			}
			if len(resp) > 512 {
				q, _ := Parse(buf[:n])
				resp = Reply(buf[:n], q, RcodeSuccess, true)
			}
			pc.WriteTo(resp, from)
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(l[:]))
				io.ReadFull(c, q)
				u.tcp.Add(1)
				resp := answer(q, u.records, 300, int(u.pad.Load()))
				c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(resp))), resp...))
			}()
		}
	}()
	return u
}

type staticPolicy struct {
	mu      sync.Mutex
	verdict func(Question) Verdict
}

func (p *staticPolicy) Decide(_ netip.Addr, q Question) Verdict { return p.verdict(q) }

func newServer(t *testing.T, policy Policy, upstreams ...*Upstream) (*Server, *[]QueryLog) {
	t.Helper()
	var mu sync.Mutex
	var logs []QueryLog
	s, err := New(Config{
		Addr: netip.MustParseAddr("127.0.0.1"), Upstreams: upstreams, Policy: policy,
		OnQuery: func(l QueryLog) { mu.Lock(); logs = append(logs, l); mu.Unlock() },
		Timeout: time.Second,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, &logs
}

func query(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	q, err := NewQuery(0x4242, name, qtype)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

var client = netip.MustParseAddr("10.77.0.100")

func TestParse(t *testing.T) {
	resp := answer(query(t, "WWW.Example.JP", TypeA), map[string]string{"www.example.jp": "192.0.2.1"}, 60, 0)
	m, err := Parse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != 0x4242 || !m.Response() || m.Question.Name != "www.example.jp" || m.Question.Type != TypeA {
		t.Errorf("メッセージ = %+v", m)
	}
	if len(m.Answers) != 1 || m.Answers[0].IP != netip.MustParseAddr("192.0.2.1") || m.Answers[0].TTL != 60 || m.Answers[0].Name != "www.example.jp" {
		t.Errorf("応答 = %+v", m.Answers)
	}
}

func TestParseEscapesAndRejects(t *testing.T) {
	// ラベルの中の「.」や制御文字はエスケープし、ほかの名前と取り違えないようにする。
	q := []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', '.', 'm', 'p', 0x01, 'X', 2, 'j', 'p', 0, 0, 1, 0, 1}
	m, err := Parse(q)
	if err != nil {
		t.Fatal(err)
	}
	if want := `ex\046mp\001x.jp`; m.Question.Name != want {
		t.Errorf("名前 = %q, 期待値 %q", m.Question.Name, want)
	}

	loop := []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1}
	long := []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for range 5 {
		long = append(long, 63)
		long = append(long, strings.Repeat("a", 63)...)
	}
	long = append(long, 0, 0, 1, 0, 1)
	for name, b := range map[string][]byte{
		"短い":        {0, 1, 0},
		"問い合わせ 2 件": {0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0},
		"圧縮の循環":     loop,
		"長すぎる名前":    long,
		"ラベルが切れる":   {0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5, 'a', 'b'},
		"種類が切れる":    {0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0},
	} {
		if _, err := Parse(b); err == nil {
			t.Errorf("%s: エラーにならない", name)
		}
	}
}

func TestHandleVerdicts(t *testing.T) {
	up := startUpstream(t, map[string]string{"ok.test": "192.0.2.1"})
	policy := &staticPolicy{verdict: func(q Question) Verdict {
		switch q.Name {
		case "blocked.test":
			return Verdict{Action: Block, Reason: "拒否リスト"}
		case "refused.test":
			return Verdict{Action: Refuse}
		}
		if q.Type == TypeHTTPS {
			return Verdict{Action: NoData, Reason: "ECH"}
		}
		return Verdict{Action: Forward}
	}}
	s, logs := newServer(t, policy, &Upstream{Addr: up.addr})

	tests := []struct {
		name    string
		qtype   uint16
		rcode   int
		answers int
	}{
		{"ok.test", TypeA, RcodeSuccess, 1},
		{"missing.test", TypeA, RcodeNXDomain, 0},
		{"blocked.test", TypeA, RcodeNXDomain, 0},
		{"refused.test", TypeA, RcodeRefused, 0},
		{"ok.test", TypeHTTPS, RcodeSuccess, 0},
	}
	for _, tt := range tests {
		resp := s.handle(context.Background(), client, query(t, tt.name, tt.qtype), true)
		m, err := Parse(resp)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if m.ID != 0x4242 || m.Rcode() != tt.rcode || len(m.Answers) != tt.answers || m.Question.Name != tt.name {
			t.Errorf("%s（%d）: 応答 = %+v", tt.name, tt.qtype, m)
		}
	}
	if len(*logs) != len(tests) || (*logs)[2].Action != Block || (*logs)[2].Reason != "拒否リスト" || (*logs)[0].Client != client {
		t.Errorf("記録 = %+v", *logs)
	}
	if up.udp.Load() != 2 {
		t.Errorf("上流への問い合わせ = %d 回（転送は 2 回のはず）", up.udp.Load())
	}
}

func TestLearn(t *testing.T) {
	up := startUpstream(t, map[string]string{"ok.test": "192.0.2.1"})
	var learned []netip.Addr
	var ttl time.Duration
	policy := &staticPolicy{verdict: func(Question) Verdict {
		return Verdict{Action: Forward, Learn: func(_ context.Context, ips []netip.Addr, d time.Duration) error {
			learned, ttl = ips, d
			return nil
		}}
	}}
	s, _ := newServer(t, policy, &Upstream{Addr: up.addr})
	s.handle(context.Background(), client, query(t, "ok.test", TypeA), true)
	if len(learned) != 1 || learned[0] != netip.MustParseAddr("192.0.2.1") || ttl != 300*time.Second {
		t.Errorf("許可に加えたアドレス = %v（TTL %v）", learned, ttl)
	}
	learned = nil
	s.handle(context.Background(), client, query(t, "missing.test", TypeA), true)
	if learned != nil {
		t.Errorf("存在しない名前で許可に加えた: %v", learned)
	}
}

func TestTruncationAndTCP(t *testing.T) {
	up := startUpstream(t, map[string]string{"big.test": "192.0.2.1"})
	up.pad.Store(60) // UDP の 512 バイトを超える応答
	s, _ := newServer(t, &staticPolicy{verdict: func(Question) Verdict { return Verdict{Action: Forward} }}, &Upstream{Addr: up.addr})

	// 上流が切り詰めた応答を返したら、上流には TCP で問い合わせ直す。
	resp := s.handle(context.Background(), client, query(t, "big.test", TypeA), false)
	m, err := Parse(resp)
	if err != nil || len(m.Answers) != 61 || up.tcp.Load() != 1 {
		t.Fatalf("TCP の応答 = %+v, %v（TCP %d 回）", m, err, up.tcp.Load())
	}
	// UDP の端末には大きすぎるので、切り詰めて TCP での問い合わせ直しを促す。
	resp = s.handle(context.Background(), client, query(t, "big.test", TypeA), true)
	if m, err := Parse(resp); err != nil || !m.Truncated() || len(m.Answers) != 0 {
		t.Errorf("UDP の応答 = %+v, %v", m, err)
	}
}

func TestUpstreamIgnoresSpoofedAndFailsOver(t *testing.T) {
	up := startUpstream(t, map[string]string{"ok.test": "192.0.2.1"})
	up.spoof.Store(true)
	// 1 つ目の上流は応答しない。2 つ目に切り替える。
	dead, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dead.Close()
	s, _ := newServer(t, &staticPolicy{verdict: func(Question) Verdict { return Verdict{Action: Forward} }},
		&Upstream{Addr: netip.MustParseAddrPort(dead.LocalAddr().String())}, &Upstream{Addr: up.addr})
	resp := s.handle(context.Background(), client, query(t, "ok.test", TypeA), true)
	if m, err := Parse(resp); err != nil || len(m.Answers) != 1 || m.ID != 0x4242 {
		t.Errorf("応答 = %+v, %v", m, err)
	}
}

func TestAllUpstreamsFail(t *testing.T) {
	dead, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dead.Close()
	s, _ := newServer(t, &staticPolicy{verdict: func(Question) Verdict { return Verdict{Action: Forward} }},
		&Upstream{Addr: netip.MustParseAddrPort(dead.LocalAddr().String())})
	resp := s.handle(context.Background(), client, query(t, "ok.test", TypeA), true)
	if m, err := Parse(resp); err != nil || m.Rcode() != RcodeServFail {
		t.Errorf("応答 = %+v, %v", m, err)
	}
}

// selfSigned は DoT の試験用の証明書を作る。
func selfSigned(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: cert}, pool
}

func TestDoT(t *testing.T) {
	cert, pool := selfSigned(t, "dns.test")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var conns atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer c.Close()
				for {
					var l [2]byte
					if _, err := io.ReadFull(c, l[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(l[:]))
					io.ReadFull(c, q)
					resp := answer(q, map[string]string{"ok.test": "192.0.2.1"}, 300, 0)
					c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(resp))), resp...))
				}
			}()
		}
	}()

	u := &Upstream{Addr: netip.MustParseAddrPort(ln.Addr().String()), TLSName: "dns.test", Roots: pool}
	defer u.Close()
	for range 3 {
		resp, err := u.Exchange(context.Background(), query(t, "ok.test", TypeA))
		if err != nil {
			t.Fatal(err)
		}
		if m, _ := Parse(resp); len(m.Answers) != 1 || m.ID != 0x4242 {
			t.Errorf("応答 = %+v", m)
		}
	}
	if conns.Load() != 1 {
		t.Errorf("接続を使い回していない（%d 回接続した）", conns.Load())
	}

	wrong := &Upstream{Addr: u.Addr, TLSName: "other.test", Roots: pool}
	if _, err := wrong.Exchange(context.Background(), query(t, "ok.test", TypeA)); err == nil {
		t.Error("証明書の名前が違うサーバーに問い合わせた")
	}
}

func TestServeUDPAndTCP(t *testing.T) {
	up := startUpstream(t, map[string]string{"ok.test": "192.0.2.1"})
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := netip.MustParseAddrPort(ln.LocalAddr().String()).Port()
	ln.Close()
	s, _ := newServer(t, &staticPolicy{verdict: func(Question) Verdict { return Verdict{Action: Forward} }}, &Upstream{Addr: up.addr})
	s.cfg.Port = port
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	defer func() { cancel(); <-done }()

	target := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
	var resp []byte
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = (&Upstream{Addr: target}).Exchange(context.Background(), query(t, "ok.test", TypeA))
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if m, err := Parse(resp); err != nil || len(m.Answers) != 1 {
		t.Fatalf("UDP の応答 = %+v, %v", m, err)
	}
	c, err := net.Dial("tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err = roundTrip(context.Background(), c, query(t, "ok.test", TypeA))
	if m, err2 := Parse(resp); err != nil || err2 != nil || len(m.Answers) != 1 {
		t.Errorf("TCP の応答 = %+v, %v %v", m, err, err2)
	}
}

func FuzzParse(f *testing.F) {
	q, _ := NewQuery(1, "www.example.jp", TypeA)
	f.Add(q)
	f.Add(answer(q, map[string]string{"www.example.jp": "192.0.2.1"}, 60, 2))
	f.Add([]byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Parse(b)
		if err != nil {
			return
		}
		// 解析できた問い合わせには、問い合わせの部分を含む応答を作れる。
		r, err := Parse(Reply(b, m, RcodeRefused, false))
		if err != nil || r.Question != m.Question || r.Rcode() != RcodeRefused || r.ID != m.ID {
			t.Fatalf("応答を作れない: %+v, %v", r, err)
		}
		if len(m.Question.Name) > 4*maxNameLen {
			t.Fatalf("名前が長すぎる: %d", len(m.Question.Name))
		}
	})
}
