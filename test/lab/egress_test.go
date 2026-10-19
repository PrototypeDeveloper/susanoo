//go:build lab

package lab

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// extraHelpers は外部通信の制御の試験で使う補助のプログラム。
//
//	dnsserve:アドレス              試験用の上流の DNS サーバー
//	dig:サーバー:名前:種類          DNS で問い合わせ、「rcode=N answers=A,B」を出力する
//	udpecho:アドレス               受けた UDP をそのまま返すサーバー
//	udp:アドレス                   UDP を送り、返ってくれば 0 で終了する
//	tls:アドレス:ポート:SNI         TLS の ClientHello を送る（ハンドシェイクの成否は問わない）
//	http:アドレス:ポート:Host       平文の HTTP の要求を送る
//	sink:アドレス                  接続を受け付け、相手が閉じるまで保つサーバー
//	hold:アドレス:ポート:秒         接続し、その秒数だけ保つ
//	ctflush                       この名前空間の conntrack の表（IPv4。「ctflush:6」なら IPv6）を消す
//	beacon:アドレス:ポート:回数:ミリ秒  決まった間隔で接続と切断を繰り返す（周期的な通信の再現）
//	upload:アドレス:ポート:バイト数    接続して、その量を送る
//	arpscan:インターフェース:送信元:最初のアドレス:数  続いたアドレスを ARP で探す（LAN 内のスキャンの再現）
var extraHelpers = map[string]func(string) int{
	"beacon":   beacon,
	"upload":   upload,
	"arpscan":  arpScan,
	"dnsserve": dnsServe,
	"dig":      dig,
	"dig6":     dig6,
	"udpecho":  udpEcho,
	"udp":      udpProbe,
	"tls":      tlsHello,
	"http":     httpRequest,
	"sink":     sink,
	"hold":     hold,
	"ctflush":  ctFlush,
}

// ctFlush は、この名前空間の conntrack の表（IPv4。arg が「6」なら IPv6）を消す。消した接続の終わりのイベントはすぐに出る
// （消さないと、期限の切れた接続はカーネルが間をおいて回収するときにイベントになるので、いつ出るか分からない）。
func ctFlush(arg string) int {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_NETFILTER)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer syscall.Close(fd)
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 2})
	// nlmsghdr（16 バイト）と nfgenmsg（4 バイト）。型は NFNL_SUBSYS_CTNETLINK(1) << 8 | IPCTNL_MSG_CT_DELETE(2)。
	// 接続を指定しない削除は、指定したアドレスファミリーの表を消す。
	msg := make([]byte, 20)
	binary.NativeEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:6], 1<<8|2)
	binary.NativeEndian.PutUint16(msg[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	binary.NativeEndian.PutUint32(msg[8:12], 1)
	msg[16] = syscall.AF_INET
	if arg == "6" {
		msg[16] = syscall.AF_INET6
	}
	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	buf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	// 応答は NLMSG_ERROR で、エラー番号が 0 なら成功。
	if n < 20 || binary.NativeEndian.Uint16(buf[4:6]) != syscall.NLMSG_ERROR {
		fmt.Fprintln(os.Stderr, "conntrack: 応答が不正です")
		return 1
	}
	if errno := int32(binary.NativeEndian.Uint32(buf[16:20])); errno != 0 {
		fmt.Fprintln(os.Stderr, "conntrack:", syscall.Errno(-errno))
		return 1
	}
	return 0
}

// beacon は「アドレス:ポート:回数:ミリ秒」に、その間隔で接続と切断を繰り返す。
func beacon(arg string) int {
	parts := strings.Split(arg, ":")
	if len(parts) != 4 {
		return 2
	}
	count, err1 := strconv.Atoi(parts[2])
	ms, err2 := strconv.Atoi(parts[3])
	if err1 != nil || err2 != nil {
		return 2
	}
	next := time.Now()
	for range count {
		if c, err := net.DialTimeout("tcp", net.JoinHostPort(parts[0], parts[1]), 2*time.Second); err == nil {
			c.Close()
		}
		next = next.Add(time.Duration(ms) * time.Millisecond)
		time.Sleep(time.Until(next))
	}
	return 0
}

// upload は「アドレス:ポート:バイト数」に接続して、その量を送る。
func upload(arg string) int {
	i := strings.LastIndexByte(arg, ':')
	n, err := strconv.Atoi(arg[i+1:])
	if i < 0 || err != nil {
		return 2
	}
	c, err := net.DialTimeout("tcp", arg[:i], 2*time.Second)
	if err != nil {
		return 1
	}
	defer c.Close()
	buf := make([]byte, 64<<10)
	for n > 0 {
		w, err := c.Write(buf[:min(n, len(buf))])
		if err != nil {
			return 1
		}
		n -= w
	}
	return 0
}

// arpScan は「インターフェース:送信元:最初のアドレス:数」で、続いたアドレスを ARP で探す。
func arpScan(arg string) int {
	parts := strings.Split(arg, ":")
	if len(parts) != 4 {
		return 2
	}
	n, err := strconv.Atoi(parts[3])
	from, first := net.ParseIP(parts[1]).To4(), net.ParseIP(parts[2]).To4()
	if err != nil || from == nil || first == nil {
		return 2
	}
	var targets []net.IP
	for i := range n {
		ip := slices.Clone(first)
		ip[3] += byte(i)
		targets = append(targets, ip)
	}
	if err := sendARPRequests(parts[0], from, targets); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// sink は接続を受け付け、相手が閉じるまで保つサーバー。
func sink(addr string) int {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return 1
		}
		go func() { io.Copy(io.Discard, c); c.Close() }()
	}
}

// hold は「アドレス:ポート:秒」に接続し、その秒数だけ保つ。
func hold(arg string) int {
	i := strings.LastIndexByte(arg, ':')
	secs, err := strconv.Atoi(arg[i+1:])
	if i < 0 || err != nil {
		return 2
	}
	c, err := net.DialTimeout("tcp", arg[:i], 2*time.Second)
	if err != nil {
		return 1
	}
	defer c.Close()
	time.Sleep(time.Duration(secs) * time.Second)
	return 0
}

func tlsHello(arg string) int {
	parts := strings.Split(arg, ":")
	if len(parts) != 3 {
		return 2
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(parts[0], parts[1]), 2*time.Second)
	if err != nil {
		return 1
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	tls.Client(c, &tls.Config{ServerName: parts[2], NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true}).Handshake()
	return 0
}

func httpRequest(arg string) int {
	parts := strings.Split(arg, ":")
	if len(parts) != 3 {
		return 2
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(parts[0], parts[1]), 2*time.Second)
	if err != nil {
		return 1
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(c, "GET /index.html HTTP/1.1\r\nHost: %s\r\nUser-Agent: lab\r\n\r\n", parts[2])
	io.ReadAll(c)
	return 0
}

// upstreamRecords は試験用の上流の DNS サーバーが返す A レコード。
var upstreamRecords = map[string]string{
	"allowed.test":   "203.0.113.2",
	"other.test":     "203.0.113.4",
	"x.blocked.test": "203.0.113.2",
	"a.canary.test":  "203.0.113.2", // ポリシーの配布の試験で、新しい版だけが拒否する名前
}

// upstreamRecords6 は試験用の上流の DNS サーバーが返す AAAA レコード。
var upstreamRecords6 = map[string]string{
	"v6.test":      "2001:db8:113::2",
	"v6other.test": "2001:db8:113::4",
}

// dnsName は問い合わせの名前を読む（圧縮なし）。名前の後ろの位置も返す。
func dnsName(b []byte, off int) (string, int) {
	var labels []string
	for off < len(b) && b[off] != 0 {
		l := int(b[off])
		if l&0xc0 == 0xc0 {
			return strings.Join(labels, "."), off + 2
		}
		if off+1+l > len(b) {
			return "", len(b)
		}
		labels = append(labels, strings.ToLower(string(b[off+1:off+1+l])))
		off += 1 + l
	}
	return strings.Join(labels, "."), off + 1
}

func dnsServe(addr string) int {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	buf := make([]byte, 4096)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil || n < 12 {
			continue
		}
		q := buf[:n]
		name, end := dnsName(q, 12)
		if end+4 > n {
			continue
		}
		qtype := binary.BigEndian.Uint16(q[end:])
		resp := append([]byte(nil), q[:end+4]...)
		binary.BigEndian.PutUint16(resp[2:], 0x8180) // 応答、再帰あり
		binary.BigEndian.PutUint16(resp[6:], 0)
		binary.BigEndian.PutUint16(resp[8:], 0)
		binary.BigEndian.PutUint16(resp[10:], 0)
		ip, ok := upstreamRecords[name]
		ip6, ok6 := upstreamRecords6[name]
		switch {
		case ok6 && qtype == 28:
			binary.BigEndian.PutUint16(resp[6:], 1)
			resp = append(resp, 0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16)
			resp = append(resp, net.ParseIP(ip6).To16()...)
		case ok6:
			// AAAA だけの名前（A は答えない）
		case ok && qtype == 1:
			binary.BigEndian.PutUint16(resp[6:], 1)
			resp = append(resp, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
			resp = append(resp, net.ParseIP(ip).To4()...)
		case ok && qtype == 65:
			// HTTPS レコード（優先度 1、対象は同じ名前）。GW は返さないはず。
			binary.BigEndian.PutUint16(resp[6:], 1)
			resp = append(resp, 0xc0, 12, 0, 65, 0, 1, 0, 0, 0, 60, 0, 3, 0, 1, 0)
		case !ok:
			resp[3] |= 3 // NXDOMAIN
		}
		pc.WriteTo(resp, from)
	}
}

func dig(arg string) int {
	sep := ":"
	if strings.Contains(arg, "\x00") { // dig6 から（IPv6 のアドレスはコロンを含む）
		sep = "\x00"
	}
	parts := strings.Split(arg, sep)
	if len(parts) != 4 {
		return 2
	}
	server, name := net.JoinHostPort(parts[0], parts[1]), parts[2]
	qtype, _ := strconv.Atoi(parts[3])
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0)
	q = binary.BigEndian.AppendUint16(q, uint16(qtype))
	q = binary.BigEndian.AppendUint16(q, 1)

	c, err := net.Dial("udp", server)
	if err != nil {
		fmt.Println("error", err)
		return 1
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write(q)
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil || n < 12 {
		fmt.Println("error", err)
		return 1
	}
	b := buf[:n]
	rcode := int(b[3] & 0xf)
	an := int(binary.BigEndian.Uint16(b[6:]))
	_, off := dnsName(b, 12)
	off += 4
	var answers []string
	for range an {
		_, off = dnsName(b, off)
		if off+10 > n {
			break
		}
		typ, rdlen := binary.BigEndian.Uint16(b[off:]), int(binary.BigEndian.Uint16(b[off+8:]))
		off += 10
		if typ == 1 && rdlen == 4 && off+4 <= n {
			answers = append(answers, net.IP(b[off:off+4]).String())
		} else if typ == 28 && rdlen == 16 && off+16 <= n {
			answers = append(answers, net.IP(b[off:off+16]).String())
		} else {
			answers = append(answers, fmt.Sprintf("type%d", typ))
		}
		off += rdlen
	}
	fmt.Printf("rcode=%d answers=%s\n", rcode, strings.Join(answers, ","))
	return 0
}

// dig6 は「サーバー,名前,種類」（サーバーは IPv6 のアドレス）で問い合わせる。出力は dig と同じ。
func dig6(arg string) int {
	parts := strings.Split(arg, ",")
	if len(parts) != 3 {
		return 2
	}
	return dig(strings.Join([]string{parts[0], "53", parts[1], parts[2]}, "\x00"))
}

func udpEcho(addr string) int {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return 1
		}
		pc.WriteTo(buf[:n], from)
	}
}

func udpProbe(addr string) int {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return 1
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte("ping"))
	buf := make([]byte, 16)
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "ping" {
		return 1
	}
	return 0
}

// runHelper は名前空間 ns で補助のプログラムを動かし、終了コードと出力を返す。
func runHelper(t *testing.T, ns, spec string) (bool, string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := inNS(ns, self)
	cmd.Env = append(os.Environ(), helperEnv+"="+spec)
	out, err := cmd.Output()
	return err == nil, strings.TrimSpace(string(out))
}

// lookup は名前空間 ns から DNS で問い合わせ、応答コードと応答を返す。
func lookup(t *testing.T, ns, server, name string, qtype int) (int, string) {
	t.Helper()
	ok, out := runHelper(t, ns, fmt.Sprintf("dig:%s:53:%s:%d", server, name, qtype))
	m := regexp.MustCompile(`^rcode=(\d+) answers=(.*)$`).FindStringSubmatch(out)
	if !ok || m == nil {
		t.Fatalf("%s から %s に問い合わせられません: %s", ns, name, out)
	}
	rcode, _ := strconv.Atoi(m[1])
	return rcode, m[2]
}

func dialFrom(t *testing.T, ns, addr string) bool {
	t.Helper()
	ok, _ := runHelper(t, ns, "dial:"+addr)
	return ok
}

type learnedEntry struct {
	Group   string `json:"group"`
	Domain  string `json:"domain"`
	Blocked bool   `json:"blocked"`
}

// TestEgress は DNS の制御（G3）、外部通信の制御（G2）、抜け道の遮断（G4）、障害時の動作（G12）を確かめる。
func TestEgress(t *testing.T) {
	if *susanooBin == "" {
		t.Fatal("-susanoo で susanoo の実行ファイルを指定してください")
	}
	pc1 := &machine{ns: "sus-c1", id: "pc-001", port: "p-c1"} // 既定のグループ（学習モード）
	pc2 := &machine{ns: "sus-c2", id: "pc-002", port: "p-c2"} // strict グループ（許可リスト）
	machines := []*machine{pc1, pc2}

	l := &lab{t: t, dir: t.TempDir()}
	buildTopology(t, machines, "203.0.113.4/24")
	l.init()
	l.writeGW([]map[string]any{
		{"name": "default", "isolation": "management", "egress": map[string]any{
			"default": "learn", "deny": []map[string]any{{"domain": "*.blocked.test"}},
		}},
		{"name": "strict", "isolation": "management", "egress": map[string]any{
			"default": "deny", "allow": []map[string]any{{"domain": "allowed.test", "ports": []int{8080}, "protocol": "tcp"}},
		}},
	}, map[string]any{"dns": map[string]any{"upstreams": []map[string]any{{"address": "203.0.113.2:53"}}}})

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range []string{"serve:203.0.113.2:8080", "serve:203.0.113.4:8080", "serve:203.0.113.2:853", "serve:203.0.113.2:443",
		"serve:203.0.113.2:80", "udpecho:203.0.113.2:443", "dnsserve:203.0.113.2:53"} {
		start(t, spec, nsInet, []string{helperEnv + "=" + spec}, self)
	}
	gwProc := start(t, "GW", nsGW, nil, *susanooBin, "gw", "-config", filepath.Join(l.dir, "gw.json"))
	waitFor(t, "GW の起動", 10*time.Second, func() bool { return l.devices() != nil })
	// 閉じた接続の終わりのイベントがすぐ届くよう、検証環境では conntrack の待ち時間を短くする。
	for _, k := range []string{"time_wait", "close", "close_wait", "last_ack", "fin_wait"} {
		sh(t, "ip", "netns", "exec", nsGW, "sysctl", "-qw", "net.netfilter.nf_conntrack_tcp_timeout_"+k+"=1")
	}
	for _, m := range machines {
		l.dhcp(m)
	}
	waitFor(t, "機器の台帳", 10*time.Second, func() bool { _, ok := l.hosts()[pc2.mac]; return ok })
	sh(t, "ip", "netns", "exec", nsGW, *susanooBin, "ctl", "group", pc2.mac, "strict", "-dir", l.ctrlDir, "-server", controllerAddr)

	t.Log("段階1: 既定のグループ（学習モード）では、拒否した名前を引けず、抜け道は遮断され、それ以外は通る")
	if rcode, ans := lookup(t, pc1.ns, gwLAN, "allowed.test", 1); rcode != 0 || ans != "203.0.113.2" {
		t.Errorf("allowed.test の応答 = %d %s", rcode, ans)
	}
	if rcode, _ := lookup(t, pc1.ns, gwLAN, "x.blocked.test", 1); rcode != 3 {
		t.Errorf("拒否した名前の応答コード = %d（NXDOMAIN のはず）", rcode)
	}
	if rcode, _ := lookup(t, pc1.ns, "203.0.113.2", "x.blocked.test", 1); rcode != 3 {
		t.Errorf("外部の DNS サーバーへの直接の問い合わせが GW に向け直されていません（応答コード %d）", rcode)
	}
	if rcode, ans := lookup(t, pc1.ns, gwLAN, "allowed.test", 65); rcode != 0 || ans != "" {
		t.Errorf("ECH の設定を含む HTTPS レコードを返しました: %d %s", rcode, ans)
	}
	if rcode, _ := lookup(t, pc1.ns, gwLAN, "use-application-dns.net", 1); rcode != 3 {
		t.Errorf("DoH の合図の名前を引けました（応答コード %d）", rcode)
	}
	if !dialFrom(t, pc1.ns, "203.0.113.4:8080") {
		t.Error("学習モードのグループで外部に接続できません")
	}
	if ok, _ := runHelper(t, pc1.ns, "udp:203.0.113.2:443"); ok {
		t.Error("QUIC（UDP 443）が遮断されていません")
	}
	if dialFrom(t, pc1.ns, "203.0.113.2:853") {
		t.Error("DNS over TLS（853）が遮断されていません")
	}

	t.Log("段階2: strict グループ（許可リスト）では、許可した名前を引いた後だけ、そのアドレスに接続できる")
	if dialFrom(t, pc2.ns, "203.0.113.2:8080") {
		t.Error("名前を引く前に、許可リストのグループから接続できました")
	}
	if rcode, ans := lookup(t, pc2.ns, gwLAN, "allowed.test", 1); rcode != 0 || ans != "203.0.113.2" {
		t.Errorf("許可した名前の応答 = %d %s", rcode, ans)
	}
	if !dialFrom(t, pc2.ns, "203.0.113.2:8080") {
		t.Error("許可した名前を引いた後に接続できません")
	}
	if set := sh(t, "ip", "netns", "exec", nsGW, "nft", "list", "set", "inet", "susanoo_egress", "g1_a0_d4"); !strings.Contains(set, "203.0.113.2") {
		t.Errorf("DNS で得たアドレスが許可の集合にありません\n%s", set)
	}
	if dialFrom(t, pc2.ns, "203.0.113.4:8080") {
		t.Error("許可していないアドレスに接続できました")
	}
	if rcode, _ := lookup(t, pc2.ns, gwLAN, "other.test", 1); rcode != 3 {
		t.Errorf("許可リストにない名前の応答コード = %d", rcode)
	}

	t.Log("段階3: 通信が記録される（接続の終わりの通信量、TLS の SNI と JA4、平文の HTTP の Host）")
	runHelper(t, pc1.ns, "tls:203.0.113.2:443:secure.test")
	runHelper(t, pc1.ns, "http:203.0.113.2:80:plain.test")
	// 期限の切れた conntrack を消して接続の終わりのイベントを出すのは、カーネルの周期的な片付け（間隔は最大 60 秒）なので、
	// 検証環境では GW の conntrack の表を消して、すぐに出させる。
	if ok, out := runHelper(t, nsGW, "ctflush"); !ok {
		t.Fatalf("GW の conntrack の表を消せません: %s", out)
	}
	checks := []struct {
		name string
		ok   func(string) bool
	}{
		{"TLS の SNI", func(ev string) bool { return strings.Contains(ev, `"sni":"secure.test"`) }},
		{"HTTP の Host", func(ev string) bool { return strings.Contains(ev, `"url":{"hostname":"plain.test"}`) }},
		{"接続の終わり（ポート 8080）", func(ev string) bool { return closedFlow(ev, 8080) }},
	}
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		ev := l.events()
		var missing []string
		for _, c := range checks {
			if !c.ok(ev) {
				missing = append(missing, c.name)
			}
		}
		if len(missing) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("通信の記録を待ちきれません（届いていないもの: %s）", strings.Join(missing, "、"))
		}
	}
	if ev := l.events(); !regexp.MustCompile(`"ja4":"t13d\d{4}h2_[0-9a-f]{12}_[0-9a-f]{12}"`).MatchString(ev) {
		t.Error("TLS の JA4 が記録されていません")
	}

	t.Log("段階4: 学習モードで通した名前と遮断した名前、DNS の問い合わせが記録されている")
	var learned []learnedEntry
	if !l.ctlJSON(&learned, "learned") {
		t.Fatal("ctl learned に失敗しました")
	}
	for _, want := range []learnedEntry{{"default", "allowed.test", false}, {"default", "x.blocked.test", true}, {"strict", "other.test", true}} {
		if !slices.Contains(learned, want) {
			t.Errorf("学習の記録に %+v がありません: %+v", want, learned)
		}
	}
	if ev := l.events(); !strings.Contains(ev, `"class_uid":4003`) || !strings.Contains(ev, `"hostname":"x.blocked.test"`) {
		t.Error("DNS の問い合わせが記録されていません")
	}

	t.Log("段階5: ポリシーを署名して配布すると、先行適用の機器だけが新しい版に従い、全体に広げると全員が従う。過去の版にも戻せる")
	ctlPolicy := func(args ...string) string {
		t.Helper()
		return sh(t, "ip", append(append([]string{"netns", "exec", nsGW, *susanooBin, "ctl", "policy"}, args...), "-dir", l.ctrlDir, "-server", controllerAddr)...)
	}
	// 新しい版：既定のグループで *.canary.test を拒否し、strict で other.test を許可する。
	writeJSON(t, filepath.Join(l.dir, "policy-v2.json"), map[string]any{
		"version": 1, "name": "検証環境 v2", "issued_at": time.Now().UTC(), "response": "enforce", "on_failure": "fail_open",
		"groups": []map[string]any{
			{"name": "default", "isolation": "management", "egress": map[string]any{
				"default": "learn", "deny": []map[string]any{{"domain": "*.blocked.test"}, {"domain": "*.canary.test"}},
			}},
			{"name": "strict", "isolation": "management", "egress": map[string]any{
				"default": "deny", "allow": []map[string]any{
					{"domain": "allowed.test", "ports": []int{8080}, "protocol": "tcp"},
					{"domain": "other.test", "ports": []int{8080}, "protocol": "tcp"},
				},
			}},
		},
	})
	// 配布の前は、pc-001 は a.canary.test を引ける（引けなくなったら GW の拒否による）。
	if rcode, ans := lookup(t, pc1.ns, gwLAN, "a.canary.test", 1); rcode != 0 || ans != "203.0.113.2" {
		t.Fatalf("配布の前に a.canary.test を引けません: %d %s", rcode, ans)
	}
	ctlPolicy("push", filepath.Join(l.dir, "policy-v2.json"), "-canary", pc1.mac)
	if rcode, _ := lookup(t, pc1.ns, gwLAN, "a.canary.test", 1); rcode != 3 {
		t.Errorf("先行適用の機器が新しい版の拒否に従いません（応答コード %d）", rcode)
	}
	if rcode, _ := lookup(t, pc2.ns, gwLAN, "other.test", 1); rcode != 3 {
		t.Errorf("先行適用でない機器が新しい版の許可に従いました（応答コード %d）", rcode)
	}
	ctlPolicy("promote")
	// strict の allowed.test の許可（同じポートの指定）で DNS から得たアドレスは、新しい版に引き継ぐ。
	if set := sh(t, "ip", "netns", "exec", nsGW, "nft", "list", "set", "inet", "susanoo_egress", "g1_a0_d4"); !strings.Contains(set, "203.0.113.2") {
		t.Errorf("DNS で得たアドレスを新しい版に引き継いでいません\n%s", set)
	}
	if rcode, ans := lookup(t, pc2.ns, gwLAN, "other.test", 1); rcode != 0 || ans != "203.0.113.4" {
		t.Errorf("全体に広げた後に、新しい版の許可の名前を引けません: %d %s", rcode, ans)
	}
	if rcode, _ := lookup(t, pc1.ns, gwLAN, "a.canary.test", 1); rcode != 3 {
		t.Errorf("全体に広げた後に、新しい版の拒否が効いていません（応答コード %d）", rcode)
	}
	ctlPolicy("rollback", "1")
	if rcode, ans := lookup(t, pc1.ns, gwLAN, "a.canary.test", 1); rcode != 0 || ans != "203.0.113.2" {
		t.Errorf("版 1 に戻した後も、新しい版の拒否が効いています: %d %s", rcode, ans)
	}
	var info struct {
		Current struct {
			Version int `json:"version"`
		} `json:"current"`
		Versions []struct {
			Version int `json:"version"`
		} `json:"versions"`
	}
	if out := ctlPolicy("list", "-json"); json.Unmarshal([]byte(out), &info) != nil || info.Current.Version != 3 || len(info.Versions) != 3 {
		t.Errorf("版の一覧 = %s", out)
	}

	t.Log("段階6: 検知ルールを署名して配布すると、当てはまる DNS の問い合わせで危険度が上がり、しきい値を超えた機器を隔離する。例外のグループと試験運用のルールでは隔離しない")
	ctlRules := func(args ...string) string {
		t.Helper()
		return sh(t, "ip", append(append([]string{"netns", "exec", nsGW, *susanooBin, "ctl", "rules"}, args...), "-dir", l.ctrlDir, "-server", controllerAddr)...)
	}
	writeJSON(t, filepath.Join(l.dir, "rules.json"), map[string]any{
		"name": "検証環境のルール",
		"rules": []map[string]any{
			{"id": "lab-bad-dns", "name": "悪い名前の問い合わせ", "class": "dns", "mode": "enforce", "score": 60,
				"match": map[string]any{"field": "query.hostname", "op": "suffix", "value": ".evil.test"}},
			{"id": "lab-watch", "name": "見張る名前", "class": "dns", "mode": "monitor", "score": 100,
				"match": map[string]any{"field": "query.hostname", "op": "eq", "value": "watch.test"}},
		},
		"exceptions": []map[string]any{{"rules": []string{"lab-bad-dns"}, "groups": []string{"strict"}, "reason": "検証のため"}},
	})
	ctlRules("push", filepath.Join(l.dir, "rules.json"))
	type ruleStat struct {
		ID        string `json:"id"`
		Hits      int    `json:"hits"`
		Monitored int    `json:"monitored"`
		Excepted  int    `json:"excepted"`
	}
	stats := func() map[string]ruleStat {
		var info struct {
			Rules []ruleStat `json:"rules"`
		}
		m := map[string]ruleStat{}
		if !l.ctlJSON(&info, "rules", "stats") {
			return m
		}
		for _, r := range info.Rules {
			m[r.ID] = r
		}
		return m
	}
	// strict グループの pc-002 は例外。pc-001 の見張る名前は試験運用。どちらも隔離しない。
	lookup(t, pc2.ns, gwLAN, "a.evil.test", 1)
	lookup(t, pc2.ns, gwLAN, "b.evil.test", 1)
	lookup(t, pc1.ns, gwLAN, "watch.test", 1)
	lookup(t, pc1.ns, gwLAN, "a.evil.test", 1)
	waitFor(t, "検知ルールの評価", 10*time.Second, func() bool {
		s := stats()
		return s["lab-bad-dns"].Excepted == 2 && s["lab-watch"].Monitored == 1 && s["lab-bad-dns"].Hits == 1
	})
	hs := l.hosts()
	if h := hs[pc1.mac]; h.Risk != 60 || h.Isolation != "" {
		t.Errorf("1 回当てはまった pc-001 = %+v", h)
	}
	if h := hs[pc2.mac]; h.Risk != 0 || h.Isolation != "" {
		t.Errorf("例外の pc-002 = %+v", h)
	}
	// 2 回目で 120 点になり、しきい値（100）を超えて隔離する。
	lookup(t, pc1.ns, gwLAN, "b.evil.test", 1)
	waitFor(t, "危険度による pc-001 の隔離", 10*time.Second, func() bool {
		h := l.hosts()[pc1.mac]
		return h.Isolation == "management" && strings.HasPrefix(h.Reason, "危険度 120")
	})
	if dialFrom(t, pc1.ns, "203.0.113.4:8080") {
		t.Error("危険度で隔離した pc-001 が外部に接続できます")
	}
	if ev := l.events(); !strings.Contains(ev, `"analytic":{"uid":"lab-bad-dns"`) || !strings.Contains(ev, "見張る名前（試験運用）") {
		t.Error("検知ルールの検知結果が記録されていません")
	}
	sh(t, "ip", "netns", "exec", nsGW, *susanooBin, "ctl", "release", pc1.mac, "-dir", l.ctrlDir, "-server", controllerAddr)
	waitFor(t, "pc-001 の解除", 10*time.Second, func() bool { h := l.hosts()[pc1.mac]; return h.Isolation == "" && h.Risk == 0 })
	waitFor(t, "pc-001 の外部への接続", 10*time.Second, func() bool { return dialFrom(t, pc1.ns, "203.0.113.4:8080") })
	if actions := l.auditActions(); !slices.Contains(actions, "rules.apply:1") || !slices.Contains(actions, "host.isolate:"+pc1.mac) {
		t.Errorf("監査ログ = %v", actions)
	}

	t.Log("段階7: 振る舞いの検知：周期的な通信、大量の送信、新しい宛先の急増、時間外の通信は記録だけし（既定の試験運用）、加点にした LAN 内のスキャンでは隔離する")
	start(t, "sink:203.0.113.2:9000", nsInet, []string{helperEnv + "=sink:203.0.113.2:9000"}, self)
	writeJSON(t, filepath.Join(l.dir, "rules2.json"), map[string]any{
		"name": "検証環境の振る舞い",
		"behavior": map[string]any{
			"beacon":           map[string]any{"min_count": 5, "min_interval": "500ms", "max_jitter": 0.3},
			"large_upload":     map[string]any{"bytes": 1 << 20, "window": "1m"},
			"internal_scan":    map[string]any{"targets": 10, "window": "1m"},
			"new_destinations": map[string]any{"count": 3, "window": "1m", "baseline": "1s"},
			"off_hours":        map[string]any{"groups": []string{"default"}, "days": []string{}, "min_bytes": 1024},
		},
		"rules": []map[string]any{{"id": "internal-scan", "name": "LAN 内のスキャン", "finding": "internal_scan", "mode": "enforce", "score": 100}},
	})
	ctlRules("push", filepath.Join(l.dir, "rules2.json"))
	if ok, out := runHelper(t, pc1.ns, "beacon:203.0.113.2:80:6:1000"); !ok {
		t.Fatalf("周期的な接続を作れません: %s", out)
	}
	if ok, out := runHelper(t, pc1.ns, "upload:203.0.113.2:9000:2097152"); !ok {
		t.Fatalf("大量の送信を作れません: %s", out)
	}
	for _, name := range []string{"a.n1.test", "b.n2.test", "c.n3.test"} {
		lookup(t, pc1.ns, gwLAN, name, 1)
	}
	if ok, out := runHelper(t, nsGW, "ctflush"); !ok {
		t.Fatalf("GW の conntrack の表を消せません: %s", out)
	}
	if ok, out := runHelper(t, pc2.ns, "arpscan:eth0:"+pc2.ip+":10.77.0.20:12"); !ok {
		t.Fatalf("ARP で探せません: %s", out)
	}
	behaviors := []string{"beacon", "large_upload", "new_destinations", "off_hours", "internal_scan"}
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		ev := l.events()
		var missing []string
		for _, k := range behaviors {
			if !strings.Contains(ev, `"types":["`+k+`"]`) {
				missing = append(missing, k)
			}
		}
		if len(missing) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("振る舞いの検知結果を待ちきれません（届いていないもの: %s）", strings.Join(missing, "、"))
		}
	}
	if ev := l.events(); !strings.Contains(ev, "203.0.113.2:80（tcp）") {
		t.Errorf("周期的な通信の宛先が記録されていません")
	}
	waitFor(t, "スキャンした pc-002 の隔離", 10*time.Second, func() bool {
		h := l.hosts()[pc2.mac]
		return h.Isolation == "management" && h.Reason == "LAN 内のスキャン"
	})
	if h := l.hosts()[pc1.mac]; h.Isolation != "" {
		t.Errorf("試験運用の検知だけの pc-001 を隔離しました: %+v", h)
	}
	s := stats()
	if s["internal-scan"].Hits != 1 || s["beacon"].Monitored < 1 || s["large-upload"].Monitored < 1 || s["new-destinations"].Monitored < 1 || s["off-hours"].Monitored < 1 {
		t.Errorf("振る舞いのルールの回数 = %+v", s)
	}
	sh(t, "ip", "netns", "exec", nsGW, *susanooBin, "ctl", "release", pc2.mac, "-dir", l.ctrlDir, "-server", controllerAddr)
	waitFor(t, "pc-002 の解除", 10*time.Second, func() bool { return l.hosts()[pc2.mac].Isolation == "" })

	t.Log("段階8: 脅威情報：遮断の一覧のドメインは引けず、アドレスへの接続は落とされて記録され、検知だけの一覧は通して記録する。一覧を消すと元に戻る")
	ctlIntel := func(args ...string) string {
		t.Helper()
		return sh(t, "ip", append(append([]string{"netns", "exec", nsGW, *susanooBin, "ctl", "intel"}, args...), "-dir", l.ctrlDir, "-server", controllerAddr)...)
	}
	if !dialFrom(t, pc1.ns, "203.0.113.4:8080") {
		t.Fatal("脅威情報の配布の前に 203.0.113.4:8080 に接続できません")
	}
	blockFile, alertFile := filepath.Join(l.dir, "intel-block.txt"), filepath.Join(l.dir, "intel-alert.txt")
	os.WriteFile(blockFile, []byte("# 検証環境の遮断の一覧\n0.0.0.0 canary.test\n203.0.113.4\n"), 0o644)
	os.WriteFile(alertFile, []byte("allowed.test\n"), 0o644)
	ctlIntel("push", "-name", "lab-block", "-action", "block", blockFile)
	ctlIntel("push", "-name", "lab-alert", alertFile)
	if set := sh(t, "ip", "netns", "exec", nsGW, "nft", "list", "set", "inet", "susanoo_intel", "block4"); !strings.Contains(set, "203.0.113.4") {
		t.Errorf("脅威情報のアドレスが遮断の集合にありません\n%s", set)
	}
	if rcode, _ := lookup(t, pc1.ns, gwLAN, "a.canary.test", 1); rcode != 3 {
		t.Errorf("遮断の一覧のドメインの下の名前を引けました（応答コード %d）", rcode)
	}
	if dialFrom(t, pc1.ns, "203.0.113.4:8080") {
		t.Error("遮断の一覧のアドレスに接続できました")
	}
	if rcode, ans := lookup(t, pc1.ns, gwLAN, "allowed.test", 1); rcode != 0 || ans != "203.0.113.2" {
		t.Errorf("検知だけの一覧の名前を引けません: %d %s", rcode, ans)
	}
	intelChecks := []struct{ name, want, and string }{
		{"遮断したドメインの問い合わせ", `"indicator":"canary.test"`, `"blocked":true`},
		{"落とした接続", `"indicator":"203.0.113.4/32"`, `"blocked":true`},
		{"検知だけの一覧", `"list":"lab-alert"`, `"blocked":false`},
		{"DNS の遮断の理由", "脅威情報（lab-block）", ""},
	}
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		lines := strings.Split(l.events(), "\n")
		var missing []string
		for _, c := range intelChecks {
			if !slices.ContainsFunc(lines, func(line string) bool { return strings.Contains(line, c.want) && strings.Contains(line, c.and) }) {
				missing = append(missing, c.name)
			}
		}
		if len(missing) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("脅威情報の検知結果を待ちきれません（届いていないもの: %s）", strings.Join(missing, "、"))
		}
	}
	if out := ctlIntel("check", "a.canary.test"); !strings.Contains(out, "lab-block") {
		t.Errorf("照合の結果 = %s", out)
	}
	if h := l.hosts()[pc1.mac]; h.Isolation != "" {
		t.Errorf("試験運用の脅威情報の検知で隔離しました: %+v", h)
	}
	ctlIntel("remove", "-name", "lab-block")
	waitFor(t, "一覧を消した後の 203.0.113.4:8080 への接続", 10*time.Second, func() bool { return dialFrom(t, pc1.ns, "203.0.113.4:8080") })
	if rcode, ans := lookup(t, pc1.ns, gwLAN, "a.canary.test", 1); rcode != 0 || ans != "203.0.113.2" {
		t.Errorf("一覧を消した後に引けません: %d %s", rcode, ans)
	}

	t.Log("段階9: 学習モードの期間を数え、学習した名前から原則拒否のポリシーの案を作る（脅威情報の名前は入れない）。期間を短くすると、終わったと分かる")
	type learningGroup struct {
		Group   string
		Due     bool
		Learned int
	}
	learning := func() map[string]learningGroup {
		var st struct {
			Learning []learningGroup `json:"learning"`
		}
		l.ctlJSON(&st, "status")
		m := map[string]learningGroup{}
		for _, g := range st.Learning {
			m[g.Group] = g
		}
		return m
	}
	if lg, ok := learning()["default"]; !ok || lg.Due || lg.Learned == 0 {
		t.Errorf("学習モードのグループ = %+v", learning())
	}
	if _, ok := learning()["strict"]; ok {
		t.Error("原則拒否のグループを学習モードとして数えています")
	}
	suggested := filepath.Join(l.dir, "policy-suggested.json")
	out := sh(t, "ip", "netns", "exec", nsGW, *susanooBin, "ctl", "learned", "suggest", "-group", "default", "-min", "1", "-out", suggested, "-dir", l.ctrlDir, "-server", controllerAddr)
	var proposal struct {
		Groups []struct {
			Name   string
			Egress struct {
				Default string
				Allow   []struct{ Domain string }
			}
		}
	}
	data, _ := os.ReadFile(suggested)
	if err := json.Unmarshal(data, &proposal); err != nil {
		t.Fatalf("ポリシーの案を読めません: %v\n%s", err, out)
	}
	for _, g := range proposal.Groups {
		if g.Name != "default" {
			continue
		}
		domains := map[string]bool{}
		for _, a := range g.Egress.Allow {
			domains[a.Domain] = true
		}
		if g.Egress.Default != "deny" || !domains["a.canary.test"] || domains["allowed.test"] {
			t.Errorf("default の案 = %+v", g.Egress)
		}
	}
	if !strings.Contains(out, "入れなかった名前: allowed.test（脅威情報（lab-alert））") {
		t.Errorf("案の説明に、脅威情報の名前を入れなかったことがありません:\n%s", out)
	}
	// 今のポリシーの default の学習モードの期間を 1 秒にして配布すると、期間が終わったと分かる。
	var current map[string]any
	if err := json.Unmarshal([]byte(ctlPolicy("show")), &current); err != nil {
		t.Fatal(err)
	}
	for _, g := range current["groups"].([]any) {
		if g := g.(map[string]any); g["name"] == "default" {
			g["egress"].(map[string]any)["learn_period"] = "1s"
		}
	}
	shortened := filepath.Join(l.dir, "policy-short-learning.json")
	writeJSON(t, shortened, current)
	ctlPolicy("push", shortened)
	waitFor(t, "学習モードの期間の終わり", 10*time.Second, func() bool { return learning()["default"].Due })

	t.Log("段階10: GW を停止すると（fail_open）、外部通信の制御をやめ、DNS は上流に向け直される")
	gwProc.stop(syscall.SIGTERM)
	if !dialFrom(t, pc2.ns, "203.0.113.4:8080") {
		t.Error("停止後も許可リストのグループの通信を遮断しています")
	}
	if rcode, ans := lookup(t, pc1.ns, gwLAN, "x.blocked.test", 1); rcode != 0 || ans != "203.0.113.2" {
		t.Errorf("停止後の DNS が上流に向け直されていません: %d %s", rcode, ans)
	}
}

// events は GW が保存したイベントをすべて返す。
func (l *lab) events() string {
	files, _ := filepath.Glob(filepath.Join(l.dir, "gw-state", "controller", "events", "events-*.jsonl"))
	var b strings.Builder
	for _, f := range files {
		data, _ := os.ReadFile(f)
		b.Write(data)
	}
	return b.String()
}

// closedFlow は、宛先のポートが port の接続の終わりの記録（通信量つき）があるかを返す。
func closedFlow(events string, port int) bool {
	for _, line := range strings.Split(events, "\n") {
		if strings.Contains(line, `"type_uid":400102`) && strings.Contains(line, fmt.Sprintf(`"port":%d}`, port)) &&
			strings.Contains(line, `"bytes_in":`) && strings.Contains(line, `"start_time":`) {
			return true
		}
	}
	return false
}
