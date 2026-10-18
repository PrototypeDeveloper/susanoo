package flow

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"
)

// goClientHello は Go の TLS クライアントが送る ClientHello のレコードを、パイプで受け取って返す（通信はしない）。
func goClientHello(t testing.TB, sni string, alpn []string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c2.Close()
	go func() {
		tls.Client(c1, &tls.Config{ServerName: sni, NextProtos: alpn, InsecureSkipVerify: true}).Handshake()
		c1.Close()
	}()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c2, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:5]))
	if _, err := io.ReadFull(c2, body); err != nil {
		t.Fatal(err)
	}
	return append(hdr, body...)
}

var ja4Pattern = regexp.MustCompile(`^t13d\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)

func TestParseGoClientHello(t *testing.T) {
	rec := goClientHello(t, "Secure.Example.JP", []string{"h2", "http/1.1"})
	ch, err := parseClientHello(rec)
	if err != nil {
		t.Fatal(err)
	}
	if ch.SNI != "secure.example.jp" || ch.Version != 0x0304 || len(ch.ALPN) != 2 || ch.ALPN[0] != "h2" {
		t.Errorf("ClientHello = %+v", ch)
	}
	if !ja4Pattern.MatchString(ch.JA4) || !strings.HasSuffix(strings.Split(ch.JA4, "_")[0], "h2") {
		t.Errorf("JA4 = %q", ch.JA4)
	}
	// ランダムな値は毎回変わるが、指紋は同じ。
	again, err := parseClientHello(goClientHello(t, "other.example.jp", []string{"h2", "http/1.1"}))
	if err != nil || again.JA4 != ch.JA4 {
		t.Errorf("JA4 が変わった: %q, %q（%v）", ch.JA4, again.JA4, err)
	}
	if len(rec) <= 1460 {
		t.Logf("ClientHello は %d バイト（1 パケットに収まる）", len(rec))
	}
}

// helloBuilder は試験用の ClientHello を組み立てる。
func buildHello(ciphers []uint16, exts [][2]any) []byte {
	var body []byte
	body = binary.BigEndian.AppendUint16(body, 0x0303)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session_id
	body = binary.BigEndian.AppendUint16(body, uint16(2*len(ciphers)))
	for _, c := range ciphers {
		body = binary.BigEndian.AppendUint16(body, c)
	}
	body = append(body, 1, 0) // compression_methods
	var ext []byte
	for _, e := range exts {
		data := e[1].([]byte)
		ext = binary.BigEndian.AppendUint16(ext, e[0].(uint16))
		ext = binary.BigEndian.AppendUint16(ext, uint16(len(data)))
		ext = append(ext, data...)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func sniExt(name string) []byte {
	entry := append([]byte{0}, binary.BigEndian.AppendUint16(nil, uint16(len(name)))...)
	entry = append(entry, name...)
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(entry))), entry...)
}

func alpnExt(protos ...string) []byte {
	var list []byte
	for _, p := range protos {
		list = append(list, byte(len(p)))
		list = append(list, p...)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(list))), list...)
}

func sha12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func TestJA4ExcludesGREASE(t *testing.T) {
	rec := buildHello([]uint16{0x0a0a, 0x1302, 0x1301}, [][2]any{
		{uint16(0x2a2a), []byte{}}, // GREASE
		{uint16(0x0000), sniExt("www.example.jp")},
		{uint16(0x0010), alpnExt("h2")},
		{uint16(0x002b), []byte{4, 0x1a, 0x1a, 0x03, 0x04}},    // supported_versions（GREASE と TLS 1.3）
		{uint16(0x000d), []byte{0, 4, 0x04, 0x03, 0x08, 0x04}}, // signature_algorithms（この順）
	})
	ch, err := parseClientHello(rec)
	if err != nil {
		t.Fatal(err)
	}
	want := "t13d0204h2_" + sha12("1301,1302") + "_" + sha12("000d,002b_0403,0804")
	if ch.JA4 != want {
		t.Errorf("JA4 = %s, 期待値 %s", ch.JA4, want)
	}

	// SNI も ALPN もない TLS 1.2 の ClientHello。
	plain, err := parseClientHello(buildHello([]uint16{0xc02f}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if want := "t12i010000_" + sha12("c02f") + "_000000000000"; plain.JA4 != want {
		t.Errorf("JA4 = %s, 期待値 %s", plain.JA4, want)
	}
}

func TestParseClientHelloRejects(t *testing.T) {
	good := goClientHello(t, "a.example.jp", nil)
	for name, b := range map[string][]byte{
		"短い":             good[:4],
		"途中で切れる":         good[:len(good)-10],
		"TLS ではない":       []byte("GET / HTTP/1.1\r\n\r\n"),
		"ClientHello 以外": {0x16, 0x03, 0x03, 0, 4, 2, 0, 0, 0},
	} {
		if _, err := parseClientHello(b); err == nil {
			t.Errorf("%s: エラーにならない", name)
		}
	}
}

func TestParseHTTPRequest(t *testing.T) {
	tests := []struct {
		in           string
		method, host string
		ok, more     bool
	}{
		{"GET /index.html HTTP/1.1\r\nUser-Agent: x\r\nHost: Plain.Example.JP:8080\r\n\r\n", "GET", "plain.example.jp", true, false},
		{"POST / HTTP/1.1\r\nhost: a.example.jp\r\n\r\nbody", "POST", "a.example.jp", true, false},
		{"GET / HTTP/1.1\r\nHost: a.exa", "GET", "", true, true},
		{"GE", "", "", false, true},
		{"SSH-2.0-OpenSSH\r\n", "", "", false, false},
		{"\x16\x03\x01", "", "", false, false},
	}
	for _, tt := range tests {
		m, h, ok, more := parseHTTPRequest([]byte(tt.in))
		if m != tt.method || h != tt.host || ok != tt.ok || more != tt.more {
			t.Errorf("%q: %q %q %v %v", tt.in, m, h, ok, more)
		}
	}
}

// ipv4TCP は試験用の IPv4 と TCP のパケットを作る。
func ipv4TCP(src, dst netip.AddrPort, seq uint32, syn bool, payload []byte) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], src.Port())
	binary.BigEndian.PutUint16(tcp[2:], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:], seq)
	tcp[12] = 5 << 4
	if syn {
		tcp[13] = 0x02
	} else {
		tcp[13] = 0x18
	}
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)+len(payload)))
	ip[8], ip[9] = 64, 6
	copy(ip[12:16], src.Addr().AsSlice())
	copy(ip[16:20], dst.Addr().AsSlice())
	return append(append(ip, tcp...), payload...)
}

var (
	client = netip.MustParseAddrPort("10.77.0.100:50000")
	server = netip.MustParseAddrPort("203.0.113.2:443")
)

func TestParseTCP(t *testing.T) {
	s, ok := parseTCP(ipv4TCP(client, server, 1000, false, []byte("abc")))
	if !ok || s.src != client || s.dst != server || s.seq != 1000 || string(s.payload) != "abc" || s.syn {
		t.Errorf("セグメント = %+v", s)
	}
	v6 := make([]byte, 40+20)
	v6[0], v6[6] = 0x60, 6
	binary.BigEndian.PutUint16(v6[4:], 20)
	copy(v6[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())
	copy(v6[24:40], netip.MustParseAddr("2001:db8::2").AsSlice())
	binary.BigEndian.PutUint16(v6[42:], 80)
	v6[52] = 5 << 4
	if s, ok := parseTCP(v6); !ok || s.dst != netip.MustParseAddrPort("[2001:db8::2]:80") {
		t.Errorf("IPv6 = %+v %v", s, ok)
	}
	// 先頭の一部だけを受け取ったパケットは、受け取った分だけを使う。
	big := ipv4TCP(client, server, 7, false, make([]byte, 3000))
	if s, ok := parseTCP(big[:1000]); !ok || len(s.payload) != 1000-40 || s.seq != 7 {
		t.Errorf("一部だけのパケット = %v（ペイロード %d バイト）", ok, len(s.payload))
	}
	frag := ipv4TCP(client, server, 1, false, nil)
	frag[6] = 0x20 // 断片化
	udp := ipv4TCP(client, server, 1, false, nil)
	udp[9] = 17
	for name, b := range map[string][]byte{"断片化": frag, "UDP": udp, "短い": frag[:10]} {
		if _, ok := parseTCP(b); ok {
			t.Errorf("%s を受け付けた", name)
		}
	}
}

func TestTrackerReassembles(t *testing.T) {
	tr := newTracker()
	now := time.Now()
	rec := goClientHello(t, "split.example.jp", []string{"h2"})
	parts := [][]byte{rec[:3], rec[3:200], rec[200:]}
	seq := uint32(5000)
	tr.add(segment{src: client, dst: server, seq: seq - 1, syn: true}, now)
	var info Info
	var ok bool
	for i, p := range parts {
		info, ok = tr.add(segment{src: client, dst: server, seq: seq, payload: p}, now)
		seq += uint32(len(p))
		if ok != (i == len(parts)-1) {
			t.Fatalf("%d 番目のセグメントで ok = %v", i, ok)
		}
	}
	if info.SNI != "split.example.jp" || info.ALPN != "h2" || info.TLSVersion != "TLS 1.3" || !ja4Pattern.MatchString(info.JA4) {
		t.Errorf("情報 = %+v", info)
	}
	// 同じ接続の後続のデータは無視し、接続の終わりに情報を返す。
	if _, ok := tr.add(segment{src: client, dst: server, seq: seq, payload: []byte("x")}, now); ok {
		t.Error("取り出した後の接続で、もう一度情報を返した")
	}
	if got, ok := tr.take(client, server); !ok || got != info {
		t.Errorf("接続の終わりの情報 = %+v, %v", got, ok)
	}
}

func TestTrackerOutOfOrderAndExpiry(t *testing.T) {
	tr := newTracker()
	now := time.Now()
	rec := goClientHello(t, "x.example.jp", nil)
	tr.add(segment{src: client, dst: server, seq: 100, payload: rec[:10]}, now)
	if _, ok := tr.add(segment{src: client, dst: server, seq: 999, payload: rec[10:]}, now); ok {
		t.Error("順序が乱れたセグメントをつないだ")
	}
	if len(tr.streams) != 0 {
		t.Error("順序が乱れた組み立てを捨てていない")
	}
	// TLS でも HTTP でもない通信は捨てる。
	if _, ok := tr.add(segment{src: client, dst: server, seq: 1, payload: []byte("SSH-2.0-x\r\n")}, now); ok || len(tr.streams) != 0 {
		t.Error("TLS でも HTTP でもない通信を組み立てている")
	}
	tr.add(segment{src: client, dst: server, seq: 1, payload: rec[:10]}, now)
	tr.expire(now.Add(time.Minute))
	if len(tr.streams) != 0 {
		t.Error("古い組み立てを捨てていない")
	}
}

// ctMessage は試験用の conntrack の接続の終わりのメッセージを作る。
func ctMessage(orig, reply [2]netip.AddrPort, proto uint8) []byte {
	tup := func(t [2]netip.AddrPort) []byte {
		ip := append(nlAttr(ctaIPv4Src, t[0].Addr().AsSlice()), nlAttr(ctaIPv4Dst, t[1].Addr().AsSlice())...)
		p := nlAttr(ctaProtoNum, []byte{proto})
		p = append(p, nlAttr(ctaProtoSrcPort, binary.BigEndian.AppendUint16(nil, t[0].Port()))...)
		p = append(p, nlAttr(ctaProtoDstPort, binary.BigEndian.AppendUint16(nil, t[1].Port()))...)
		return append(nlAttr(ctaTupleIP|0x8000, ip), nlAttr(ctaTupleProto|0x8000, p)...)
	}
	counters := func(pkts, bytes uint64) []byte {
		return append(nlAttr(ctaCountPackets, binary.BigEndian.AppendUint64(nil, pkts)), nlAttr(ctaCountBytes, binary.BigEndian.AppendUint64(nil, bytes))...)
	}
	start := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	ts := append(nlAttr(ctaTSStart, binary.BigEndian.AppendUint64(nil, uint64(start.UnixNano()))),
		nlAttr(ctaTSStop, binary.BigEndian.AppendUint64(nil, uint64(start.Add(3*time.Second).UnixNano())))...)
	body := []byte{2, 0, 0, 0} // nfgenmsg
	body = append(body, nlAttr(ctaTupleOrig|0x8000, tup(orig))...)
	body = append(body, nlAttr(ctaTupleReply|0x8000, tup(reply))...)
	body = append(body, nlAttr(ctaCountersOrig|0x8000, counters(5, 500))...)
	body = append(body, nlAttr(ctaCountersReply|0x8000, counters(7, 9000))...)
	body = append(body, nlAttr(ctaTimestamp|0x8000, ts)...)
	hdr := make([]byte, nlmsgHdrLen)
	binary.NativeEndian.PutUint32(hdr[0:], uint32(nlmsgHdrLen+len(body)))
	binary.NativeEndian.PutUint16(hdr[4:], msgCTDelete)
	return append(hdr, body...)
}

var (
	gwWAN = netip.MustParseAddrPort("203.0.113.1:50000")
	lan   = netip.MustParsePrefix("10.77.0.0/24")
	gwLAN = netip.MustParseAddr("10.77.0.1")
)

func TestParseConntrack(t *testing.T) {
	msgs, err := parseMessages(ctMessage([2]netip.AddrPort{client, server}, [2]netip.AddrPort{server, gwWAN}, 6))
	if err != nil || len(msgs) != 1 || msgs[0].typ != msgCTDelete {
		t.Fatalf("メッセージ = %+v, %v", msgs, err)
	}
	ct, err := parseConntrack(msgs[0].data)
	if err != nil {
		t.Fatal(err)
	}
	if ct.proto != 6 || ct.orig.src != client || ct.orig.dst != server || ct.reply.dst != gwWAN ||
		ct.pktsOrig != 5 || ct.bytesOrig != 500 || ct.pktsReply != 7 || ct.bytesReply != 9000 || ct.stop.Sub(ct.start) != 3*time.Second {
		t.Errorf("接続 = %+v", ct)
	}
	if _, err := parseConntrack([]byte{2, 0}); err == nil {
		t.Error("短いメッセージを受け付けた")
	}
}

func TestNFLog(t *testing.T) {
	pkt := ipv4TCP(client, server, 1, false, []byte("x"))
	body := append([]byte{2, 0, 0, 100}, nlAttr(nfulaPayload, pkt)...)
	group, got, err := parseNFLog(body)
	if err != nil || string(got) != string(pkt) || group != 100 {
		t.Errorf("パケット = %d %x, %v", group, got, err)
	}
	if _, _, err := parseNFLog([]byte{2, 0, 0, 100}); err == nil {
		t.Error("パケットのないメッセージを受け付けた")
	}
	msgs := nflogBindMessages(100, 4096)
	if len(msgs) != 3 {
		t.Fatalf("設定のメッセージ = %d 件", len(msgs))
	}
	m, _ := parseMessages(msgs[0])
	if len(m) != 1 || m[0].typ != msgULogCfg || m[0].flags != nlmFRequest|nlmFAck || binary.BigEndian.Uint16(m[0].data[2:4]) != 100 {
		t.Errorf("結び付けのメッセージ = %+v", m)
	}
	ack := make([]byte, 4)
	binary.NativeEndian.PutUint32(ack, uint32(0xffffffff)) // -1（EPERM）
	if code := ackError(nlMsg{typ: nlmsgError, data: ack}); code != -1 {
		t.Errorf("応答のエラー = %d", code)
	}
}

func TestProcessor(t *testing.T) {
	var got []Record
	p := newProcessor(lan, gwLAN, func(r Record) { got = append(got, r) })
	now := time.Now()

	// TLS の始まりを記録し、接続の終わりの記録にも SNI を付ける。
	rec := goClientHello(t, "secure.example.jp", nil)
	p.packet(ipv4TCP(client, server, 1, false, rec), now)
	m, _ := parseMessages(ctMessage([2]netip.AddrPort{client, server}, [2]netip.AddrPort{server, gwWAN}, 6))
	ct, _ := parseConntrack(m[0].data)
	p.destroyed(ct, now)
	if len(got) != 2 || got[0].Kind != Open || got[0].Info.SNI != "secure.example.jp" ||
		got[1].Kind != Close || got[1].Info.SNI != "secure.example.jp" || got[1].BytesIn != 9000 || got[1].Start.IsZero() {
		t.Fatalf("記録 = %+v", got)
	}

	// GW のリゾルバに向け直した DNS、GW 自身の通信、LAN の中の通信は記録しない。
	dns := netip.MustParseAddrPort("203.0.113.2:53")
	for _, c := range [][2][2]netip.AddrPort{
		{{client, dns}, {netip.AddrPortFrom(gwLAN, 53), client}},
		{{gwWAN, dns}, {dns, gwWAN}},
		{{client, netip.MustParseAddrPort("10.77.0.101:22")}, {netip.MustParseAddrPort("10.77.0.101:22"), client}},
	} {
		m, _ := parseMessages(ctMessage(c[0], c[1], 17))
		ct, _ := parseConntrack(m[0].data)
		p.destroyed(ct, now)
	}
	if len(got) != 2 {
		t.Errorf("記録しない通信を記録した: %+v", got[2:])
	}
}

// GW が落としたパケットは、LAN から外への接続の試みとして記録する。
func TestProcessorBlocked(t *testing.T) {
	var got []Record
	p := newProcessor(lan, gwLAN, func(r Record) { got = append(got, r) })
	now := time.Now()
	p.blocked(ipv4TCP(client, server, 1, true, nil), now)
	p.blocked(ipv4TCP(server, client, 1, true, nil), now) // 外から LAN
	p.blocked([]byte{0x45}, now)
	if len(got) != 1 || got[0].Kind != Blocked || got[0].Src != client || got[0].Dst != server || got[0].Proto != 6 {
		t.Fatalf("記録 = %+v", got)
	}
	// UDP と ICMP（ポートなし）。
	udp := ipv4TCP(client, netip.MustParseAddrPort("203.0.113.9:53"), 1, false, nil)
	udp[9] = 17
	icmp := ipv4TCP(client, netip.MustParseAddrPort("203.0.113.9:0"), 1, false, nil)
	icmp[9] = 1
	for _, b := range [][]byte{udp, icmp} {
		if src, dst, proto, ok := parseIP(b); !ok || src.Addr() != client.Addr() || dst.Addr() != netip.MustParseAddr("203.0.113.9") || (proto == 1 && dst.Port() != 0) || (proto == 17 && dst.Port() != 53) {
			t.Errorf("parseIP = %v %v %d %v", src, dst, proto, ok)
		}
	}
}

func FuzzParseClientHello(f *testing.F) {
	f.Add(goClientHello(f, "a.example.jp", []string{"h2"}))
	f.Add(buildHello([]uint16{0x1301}, [][2]any{{uint16(0), sniExt("x")}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		ch, err := parseClientHello(b)
		if err == nil && !regexp.MustCompile(`^t`).MatchString(ch.JA4) {
			t.Fatalf("JA4 = %q", ch.JA4)
		}
	})
}

func FuzzParseHTTPRequest(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) { parseHTTPRequest(b) })
}

func FuzzParseTCP(f *testing.F) {
	f.Add(ipv4TCP(client, server, 1, false, []byte("abc")))
	f.Fuzz(func(t *testing.T, b []byte) {
		parseIP(b)
		if s, ok := parseTCP(b); ok && len(s.payload) > len(b) {
			t.Fatal("入力より長いデータを返した")
		}
	})
}

func FuzzParseNetlink(f *testing.F) {
	f.Add(ctMessage([2]netip.AddrPort{client, server}, [2]netip.AddrPort{server, gwWAN}, 6))
	f.Fuzz(func(t *testing.T, b []byte) {
		msgs, _ := parseMessages(b)
		for _, m := range msgs {
			parseConntrack(m.data)
			parseNFLog(m.data)
		}
	})
}

func FuzzTracker(f *testing.F) {
	f.Add(goClientHello(f, "a.example.jp", nil), uint16(100))
	f.Fuzz(func(t *testing.T, b []byte, cut uint16) {
		tr := newTracker()
		n := min(int(cut), len(b))
		tr.add(segment{src: client, dst: server, seq: 1, payload: b[:n]}, time.Now())
		tr.add(segment{src: client, dst: server, seq: 1 + uint32(n), payload: b[n:]}, time.Now())
	})
}
