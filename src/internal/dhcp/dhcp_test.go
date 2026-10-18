package dhcp

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newServer(t *testing.T, statePath string, c *clock) (*Server, *[]Lease) {
	t.Helper()
	var events []Lease
	s, err := New(Config{
		ServerIP:   netip.MustParseAddr("10.77.0.1"),
		Prefix:     netip.MustParsePrefix("10.77.0.0/24"),
		RangeStart: netip.MustParseAddr("10.77.0.100"),
		RangeEnd:   netip.MustParseAddr("10.77.0.102"),
		DNS:        []netip.Addr{netip.MustParseAddr("10.77.0.1")},
		LeaseTime:  time.Hour,
		StatePath:  statePath,
		OnLease:    func(l Lease, _ bool) { events = append(events, l) },
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:        c.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, &events
}

func mac(last byte) net.HardwareAddr { return net.HardwareAddr{2, 0, 0, 0, 0, last} }

func request(t MessageType, hw net.HardwareAddr, opts map[byte][]byte) *Message {
	m := &Message{Op: opRequest, HType: htypeEthernet, HLen: 6, XID: 0x1234, CHAddr: hw, Options: map[byte][]byte{OptMessageType: {byte(t)}}}
	for k, v := range opts {
		m.Options[k] = v
	}
	return m
}

func addr(s string) []byte { return netip.MustParseAddr(s).AsSlice() }

// roundTrip は送受信と同じく、バイト列を経由してメッセージを処理する。
func roundTrip(t *testing.T, s *Server, req *Message) *Message {
	t.Helper()
	parsed, err := Parse(req.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	reply := s.Handle(parsed)
	if reply == nil {
		return nil
	}
	parsed, err = Parse(reply.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// lease は DISCOVER と REQUEST でアドレスを得る。
func lease(t *testing.T, s *Server, hw net.HardwareAddr) netip.Addr {
	t.Helper()
	offer := roundTrip(t, s, request(Discover, hw, map[byte][]byte{OptHostname: []byte("pc")}))
	if offer == nil || offer.Type() != Offer {
		t.Fatalf("OFFER がない: %+v", offer)
	}
	ack := roundTrip(t, s, request(Request, hw, map[byte][]byte{
		OptRequestedIP: offer.YIAddr.AsSlice(),
		OptServerID:    addr("10.77.0.1"),
	}))
	if ack == nil || ack.Type() != Ack || ack.YIAddr != offer.YIAddr {
		t.Fatalf("ACK がない: %+v", ack)
	}
	return ack.YIAddr
}

func TestDiscoverRequest(t *testing.T) {
	c := &clock{time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	s, events := newServer(t, "", c)

	offer := roundTrip(t, s, request(Discover, mac(1), nil))
	if offer.YIAddr != netip.MustParseAddr("10.77.0.100") || offer.XID != 0x1234 || !bytes.Equal(offer.CHAddr, mac(1)) {
		t.Errorf("OFFER = %+v", offer)
	}
	if offer.AddrOption(OptServerID) != netip.MustParseAddr("10.77.0.1") || offer.AddrOption(OptRouter) != netip.MustParseAddr("10.77.0.1") {
		t.Errorf("サーバーとルーターのオプション = %v", offer.Options)
	}
	if !bytes.Equal(offer.Options[OptSubnetMask], []byte{255, 255, 255, 0}) || !bytes.Equal(offer.Options[OptLeaseTime], []byte{0, 0, 0x0e, 0x10}) {
		t.Errorf("マスクとリース時間のオプション = %v", offer.Options)
	}

	ip := lease(t, s, mac(1))
	if len(*events) != 1 || (*events)[0].IP != ip || (*events)[0].Hostname != "pc" || (*events)[0].MAC != mac(1).String() {
		t.Errorf("通知 = %+v", *events)
	}
	// 2 台目は別のアドレス。
	if ip2 := lease(t, s, mac(2)); ip2 == ip {
		t.Errorf("同じアドレスを 2 台に渡した: %s", ip2)
	}
}

func TestStickyAddress(t *testing.T) {
	c := &clock{time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	s, _ := newServer(t, "", c)
	first := lease(t, s, mac(1))
	lease(t, s, mac(2))

	// 期限が切れても、ほかの機器に渡していなければ同じアドレスを渡す。
	c.t = c.t.Add(3 * time.Hour)
	if again := lease(t, s, mac(1)); again != first {
		t.Errorf("再接続で別のアドレスになった: %s, 前回 %s", again, first)
	}
}

func TestRequestRejects(t *testing.T) {
	c := &clock{time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	s, _ := newServer(t, "", c)
	ip1 := lease(t, s, mac(1))

	tests := []struct {
		name string
		req  *Message
		want MessageType // 0 なら応答しない
	}{
		{"ほかの機器のアドレス", request(Request, mac(2), map[byte][]byte{OptRequestedIP: ip1.AsSlice()}), Nak},
		{"範囲の外", request(Request, mac(2), map[byte][]byte{OptRequestedIP: addr("10.77.0.50")}), Nak},
		{"別のネットワーク", request(Request, mac(2), map[byte][]byte{OptRequestedIP: addr("192.168.10.10")}), Nak},
		{"サーバー自身", request(Request, mac(2), map[byte][]byte{OptRequestedIP: addr("10.77.0.1")}), Nak},
		{"別のサーバーを選んだ", request(Request, mac(2), map[byte][]byte{OptRequestedIP: addr("10.77.0.101"), OptServerID: addr("10.77.0.254")}), 0},
		{"記録がなくても空いていれば渡す", request(Request, mac(3), map[byte][]byte{OptRequestedIP: addr("10.77.0.102")}), Ack},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reply := roundTrip(t, s, tt.req)
			var got MessageType
			if reply != nil {
				got = reply.Type()
			}
			if got != tt.want {
				t.Errorf("応答 = %v, 期待値 %v", got, tt.want)
			}
		})
	}
}

func TestIgnoresInvalid(t *testing.T) {
	c := &clock{time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	s, _ := newServer(t, "", c)
	relay := request(Discover, mac(1), nil)
	relay.GIAddr = netip.MustParseAddr("10.0.0.1")
	reply := request(Discover, mac(1), nil)
	reply.Op = opReply
	noType := request(Discover, mac(1), nil)
	delete(noType.Options, OptMessageType)
	for name, m := range map[string]*Message{"リレー経由": relay, "応答のメッセージ": reply, "種類なし": noType} {
		if r := s.Handle(m); r != nil {
			t.Errorf("%s に応答した: %+v", name, r)
		}
	}
}

func TestExhaustion(t *testing.T) {
	c := &clock{time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	s, _ := newServer(t, "", c)
	for i := byte(1); i <= 3; i++ {
		lease(t, s, mac(i))
	}
	if r := roundTrip(t, s, request(Discover, mac(4), nil)); r != nil {
		t.Errorf("範囲が尽きているのに OFFER した: %s", r.YIAddr)
	}
	// 期限が切れたアドレスは再利用する。
	c.t = c.t.Add(2 * time.Hour)
	if ip := lease(t, s, mac(4)); !ip.IsValid() {
		t.Error("期限切れのアドレスを再利用できない")
	}
}

func TestReleaseAndDecline(t *testing.T) {
	c := &clock{time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	s, events := newServer(t, "", c)
	ip := lease(t, s, mac(1))
	rel := request(Release, mac(1), nil)
	rel.CIAddr = ip
	roundTrip(t, s, rel)
	if len(*events) != 2 {
		t.Errorf("解放の通知がない: %+v", *events)
	}
	// 解放したアドレスはほかの機器に渡せる。
	if got := roundTrip(t, s, request(Request, mac(2), map[byte][]byte{OptRequestedIP: ip.AsSlice()})); got.Type() != Ack {
		t.Errorf("解放したアドレスを渡せない: %v", got.Type())
	}

	// DECLINE されたアドレスはしばらく使わない。
	ip3 := lease(t, s, mac(3))
	roundTrip(t, s, request(Decline, mac(3), map[byte][]byte{OptRequestedIP: ip3.AsSlice()}))
	if offer := roundTrip(t, s, request(Discover, mac(4), nil)); offer != nil && offer.YIAddr == ip3 {
		t.Errorf("DECLINE されたアドレスを渡した: %s", ip3)
	}
}

func TestAvoid(t *testing.T) {
	c := &clock{time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	s, _ := newServer(t, "", c)
	ip := lease(t, s, mac(1))
	s.cfg.Avoid = func(a netip.Addr) bool { return a == ip }

	// 隔離中の機器のアドレスは、期限が切れてもほかの機器に渡さない。
	c.t = c.t.Add(2 * time.Hour)
	if got := lease(t, s, mac(2)); got == ip {
		t.Errorf("隔離中の機器のアドレスを渡した: %s", got)
	}
	// 本人の更新は受け付ける。
	if got := lease(t, s, mac(1)); got != ip {
		t.Errorf("隔離中の機器が自分のアドレスを更新できない: %s", got)
	}
}

func TestPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.json")
	c := &clock{time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	s, _ := newServer(t, path, c)
	ip := lease(t, s, mac(1))

	s2, _ := newServer(t, path, c)
	if got := s2.Leases(); len(got) != 1 || got[0].IP != ip {
		t.Fatalf("読み直した割り当て = %+v", got)
	}
	if offer := roundTrip(t, s2, request(Discover, mac(2), nil)); offer.YIAddr == ip {
		t.Errorf("再起動後に使用中のアドレスを渡した: %s", ip)
	}
}

func TestInform(t *testing.T) {
	c := &clock{time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	s, _ := newServer(t, "", c)
	req := request(Inform, mac(1), nil)
	req.CIAddr = netip.MustParseAddr("10.77.0.50")
	r := roundTrip(t, s, req)
	if r == nil || r.Type() != Ack || r.CIAddr != req.CIAddr || r.Options[OptLeaseTime] != nil || r.AddrOption(OptDNS) != netip.MustParseAddr("10.77.0.1") {
		t.Errorf("INFORM の応答 = %+v", r)
	}
}

func TestConfigValidation(t *testing.T) {
	base := Config{
		ServerIP:   netip.MustParseAddr("10.77.0.1"),
		Prefix:     netip.MustParsePrefix("10.77.0.0/24"),
		RangeStart: netip.MustParseAddr("10.77.0.100"),
		RangeEnd:   netip.MustParseAddr("10.77.0.199"),
	}
	if _, err := New(base); err != nil {
		t.Fatal(err)
	}
	bad := []func(*Config){
		func(c *Config) { c.RangeEnd = netip.MustParseAddr("10.78.0.1") },
		func(c *Config) { c.RangeStart, c.RangeEnd = c.RangeEnd, c.RangeStart },
		func(c *Config) { c.ServerIP = netip.MustParseAddr("192.168.0.1") },
		func(c *Config) {
			c.Prefix = netip.MustParsePrefix("10.0.0.0/8")
			c.RangeEnd = netip.MustParseAddr("10.255.255.254")
		},
	}
	for i, f := range bad {
		c := base
		f(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%d: 不正な設定を受け付けた", i)
		}
	}
	if s, e, err := ParseRange("10.0.0.100 - 10.0.0.200"); err != nil || s != netip.MustParseAddr("10.0.0.100") || e != netip.MustParseAddr("10.0.0.200") {
		t.Errorf("範囲の解析 = %v %v %v", s, e, err)
	}
	if _, _, err := ParseRange("10.0.0.100"); err == nil {
		t.Error("不正な範囲を受け付けた")
	}
}

func TestParseErrors(t *testing.T) {
	valid := request(Discover, mac(1), nil).Marshal()
	cases := map[string][]byte{
		"短い":        valid[:100],
		"クッキーが違う":   append(append([]byte{}, valid[:236]...), 1, 2, 3, 4, OptEnd),
		"オプションが切れる": append(append([]byte{}, valid[:240]...), OptHostname, 10, 'a'),
		"終わりがない":    append(append([]byte{}, valid[:240]...), OptHostname, 1, 'a'),
	}
	bad := append([]byte{}, valid...)
	bad[2] = 17
	cases["ハードウェアアドレスが長い"] = bad
	for name, b := range cases {
		if _, err := Parse(b); err == nil {
			t.Errorf("%s: エラーにならない", name)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(request(Discover, mac(1), map[byte][]byte{OptHostname: []byte("pc"), OptRequestedIP: addr("10.77.0.100")}).Marshal())
	f.Add(request(Request, mac(1), map[byte][]byte{OptServerID: addr("10.77.0.1")}).Marshal())
	c := &clock{time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	s, err := New(Config{
		ServerIP: netip.MustParseAddr("10.77.0.1"), Prefix: netip.MustParsePrefix("10.77.0.0/24"),
		RangeStart: netip.MustParseAddr("10.77.0.100"), RangeEnd: netip.MustParseAddr("10.77.0.199"),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: c.now,
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Parse(b)
		if err != nil {
			return
		}
		// 解析できたメッセージは、書き出して読み直せる。
		if _, err := Parse(m.Marshal()); err != nil {
			t.Fatalf("書き出したメッセージを読み直せない: %v", err)
		}
		// どんなメッセージでも、応答は範囲の中のアドレスだけを渡す。
		if r := s.Handle(m); r != nil && r.YIAddr.IsValid() && !r.YIAddr.IsUnspecified() {
			if r.YIAddr.Less(s.cfg.RangeStart) || s.cfg.RangeEnd.Less(r.YIAddr) {
				t.Fatalf("範囲の外のアドレス %s を渡した", r.YIAddr)
			}
		}
	})
}
