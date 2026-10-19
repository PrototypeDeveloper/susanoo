//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"susanoo/internal/event"
	"susanoo/internal/nft"
	"susanoo/internal/policy"
)

// ipv4TCP は IPv4 と TCP のヘッダーだけのパケットを作る。
func ipv4TCP(src, dst netip.AddrPort, proto byte) []byte {
	b := make([]byte, 40)
	b[0] = 0x45
	b[9] = proto
	copy(b[12:16], src.Addr().AsSlice())
	copy(b[16:20], dst.Addr().AsSlice())
	binary.BigEndian.PutUint16(b[20:22], src.Port())
	binary.BigEndian.PutUint16(b[22:24], dst.Port())
	return b
}

func ipv6UDP(src, dst netip.AddrPort) []byte {
	b := make([]byte, 48)
	b[0] = 0x60
	b[6] = syscall.IPPROTO_UDP
	copy(b[8:24], src.Addr().AsSlice())
	copy(b[24:40], dst.Addr().AsSlice())
	binary.BigEndian.PutUint16(b[40:42], src.Port())
	binary.BigEndian.PutUint16(b[42:44], dst.Port())
	return b
}

func TestParseIPPacket(t *testing.T) {
	src, dst := netip.MustParseAddrPort("192.0.2.10:40000"), netip.MustParseAddrPort("203.0.113.5:443")
	k, ok := parseIPPacket(ipv4TCP(src, dst, syscall.IPPROTO_TCP))
	if !ok || k.proto != "tcp" || k.src != src || k.dst != dst {
		t.Errorf("IPv4 = %+v %v", k, ok)
	}
	s6, d6 := netip.MustParseAddrPort("[2001:db8::10]:5353"), netip.MustParseAddrPort("[2001:db8::53]:53")
	if k, ok := parseIPPacket(ipv6UDP(s6, d6)); !ok || k.proto != "udp" || k.src != s6 || k.dst != d6 {
		t.Errorf("IPv6 = %+v %v", k, ok)
	}
	frag := ipv4TCP(src, dst, syscall.IPPROTO_TCP)
	binary.BigEndian.PutUint16(frag[6:8], 10) // 2 番目以降の断片
	for name, b := range map[string][]byte{"ICMP": ipv4TCP(src, dst, syscall.IPPROTO_ICMP), "断片": frag, "短い": {0x45, 0}, "空": nil, "版が不正": {0x75}} {
		if _, ok := parseIPPacket(b); ok {
			t.Errorf("%s を読んだ", name)
		}
	}
}

// キューの設定、パケット、判断のメッセージの形。
func TestNFQueueMessages(t *testing.T) {
	msgs := nfqBindMessages(4242)
	if len(msgs) != 4 {
		t.Fatalf("設定のメッセージ = %d 個", len(msgs))
	}
	for i, m := range msgs {
		if typ := binary.NativeEndian.Uint16(m[4:6]); typ != nfnlSubsysQueue<<8|nfqnlMsgConfig {
			t.Errorf("%d 番目の種類 = %x", i, typ)
		}
		if q := binary.BigEndian.Uint16(m[nlmsgHdrLen+2:]); q != 4242 {
			t.Errorf("%d 番目のキュー = %d", i, q)
		}
	}
	v := nfqVerdictMessage(4242, 7, nfRepeat, nft.AppsDenyMark)
	parsed, err := nlMessages(v)
	if err != nil || len(parsed) != 1 {
		t.Fatal(err)
	}
	a, _ := nlAttributes(parsed[0].data[nfgenmsgLen:])
	if hdr := a[nfqaVerdictHdr]; binary.BigEndian.Uint32(hdr[0:4]) != nfRepeat || binary.BigEndian.Uint32(hdr[4:8]) != 7 ||
		binary.BigEndian.Uint32(a[nfqaMark]) != nft.AppsDenyMark {
		t.Errorf("判断の属性 = %v", a)
	}
	pkt := packetMessage(9, 1000, []byte{1, 2, 3})
	parsed, _ = nlMessages(pkt)
	p, err := parseNFQPacket(parsed[0].data)
	if err != nil || p.id != 9 || !p.hasUID || p.uid != 1000 || string(p.payload) != "\x01\x02\x03" {
		t.Errorf("パケット = %+v, %v", p, err)
	}
	if _, err := parseNFQPacket([]byte{0, 0}); err == nil {
		t.Error("短いメッセージを読んだ")
	}
}

// packetMessage はカーネルが送るキューのパケットのメッセージを作る。
func packetMessage(id, uid uint32, payload []byte) []byte {
	hdr := binary.BigEndian.AppendUint32(nil, id)
	hdr = append(hdr, 0x08, 0x00, 3) // hw_protocol、hook
	return nfqMessage(nfqnlMsgPacket, 0, 0, 4242,
		nlAttribute(nfqaPacketHdr, hdr), nlAttribute(nfqaPayload, payload), nlAttribute(nfqaUID, binary.BigEndian.AppendUint32(nil, uid)))
}

func FuzzParseNFQueue(f *testing.F) {
	f.Add(packetMessage(1, 0, ipv4TCP(netip.MustParseAddrPort("192.0.2.1:1"), netip.MustParseAddrPort("192.0.2.2:2"), syscall.IPPROTO_TCP)))
	f.Fuzz(func(t *testing.T, b []byte) {
		msgs, _ := nlMessages(b)
		for _, m := range msgs {
			if p, err := parseNFQPacket(m.data); err == nil {
				parseIPPacket(p.payload)
			}
		}
	})
}

type nftRecorder struct {
	mu      sync.Mutex
	scripts []string
}

func (r *nftRecorder) Run(_ context.Context, s string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scripts = append(r.scripts, s)
	return nil
}

func (r *nftRecorder) last() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.scripts[len(r.scripts)-1]
}

// キューに入ったパケットを、接続したプロセスと宛先でルールに照らして判断する。カーネルの代わりに socketpair でメッセージを
// やり取りするので、root は要らない。
func TestAppFirewallVerdicts(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	ours, kernel := os.NewFile(uintptr(fds[0]), "queue"), os.NewFile(uintptr(fds[1]), "kernel")
	defer kernel.Close()

	// 接続の持ち主の役のプロセス。agent は名前を試験用のエージェントの名前にして起動した（AI エージェントの役）。
	// 既定のエージェントの名前は使わない（試験を AI エージェントの中で動かすと、祖先にそのエージェントがいて、すべてが帰属するため）。
	plain := exec.Command("/bin/sleep", "5")
	agent := exec.Command("/bin/sleep", "5")
	agent.Args[0] = "susanoo-test-agent"
	for _, c := range []*exec.Cmd{plain, agent} {
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { c.Process.Kill(); c.Wait() }()
	}
	time.Sleep(50 * time.Millisecond)
	owners := map[uint16]int{1001: plain.Process.Pid, 1002: agent.Process.Pid, 1003: 0}

	rec := &nftRecorder{}
	out := make(chan *event.Event, 16)
	f := newAppFirewall(rec, newProcCache(), newAgentMatcher([]AgentSpec{{Name: "test-agent", Match: []string{"susanoo-test-agent"}}}), out, quiet)
	f.self = -1 // 持ち主の役のプロセスは試験のプロセスの子なので、CLIENT 自身として扱わない
	f.open = func(q uint16) (*nfqueue, error) { return &nfqueue{f: ours, queue: q}, nil }
	f.owner = func(k flowKey) int { return owners[k.src.Port()] }
	f.resolve = func(_ context.Context, name string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("198.51.100.7")}, nil
	}
	ac := &policy.AppControl{Mode: policy.AppEnforce, Default: policy.AppAllow, Rules: []policy.AppRule{
		{Name: "エージェントは API だけ", Agents: []string{"*"}, Dst: []policy.Destination{{Domain: "api.example.jp"}}, Action: policy.AppAllow},
		{Name: "エージェントのほか", Agents: []string{"*"}, Action: policy.AppDeny},
		{Name: "sleep は 203.0.113.0/24 に出さない", Names: []string{"sleep"}, Dst: []policy.Destination{{CIDR: "203.0.113.0/24"}}, Action: policy.AppDeny},
	}}
	ctx := context.Background()
	exempt := []netip.Addr{netip.MustParseAddr("10.77.0.1")}
	if err := f.set(ctx, ac, exempt); err != nil {
		t.Fatal(err)
	}
	if s := rec.last(); !strings.Contains(s, "queue num 4242 bypass") || !strings.Contains(s, "ip daddr { 10.77.0.1 } accept") {
		t.Errorf("nft のスクリプト = %s", s)
	}
	// ドメインを引き終わるのを待つ。
	deadline := time.Now().Add(2 * time.Second)
	for len(f.domains.lookup("api.example.jp")) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	verdict := func(id uint32, srcPort uint16, dst string) (uint32, uint32) {
		t.Helper()
		pkt := ipv4TCP(netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), srcPort), netip.MustParseAddrPort(dst), syscall.IPPROTO_TCP)
		if _, err := kernel.Write(packetMessage(id, 1000, pkt)); err != nil {
			t.Fatal(err)
		}
		kernel.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4096)
		n, err := kernel.Read(buf)
		if err != nil {
			t.Fatalf("判断が返らない: %v", err)
		}
		msgs, _ := nlMessages(buf[:n])
		a, _ := nlAttributes(msgs[0].data[nfgenmsgLen:])
		hdr := a[nfqaVerdictHdr]
		if got := binary.BigEndian.Uint32(hdr[4:8]); got != id {
			t.Fatalf("判断の ID = %d, 期待値 %d", got, id)
		}
		mark := uint32(0)
		if m, ok := a[nfqaMark]; ok {
			mark = binary.BigEndian.Uint32(m)
		}
		return binary.BigEndian.Uint32(hdr[0:4]), mark
	}
	for _, tc := range []struct {
		name    string
		port    uint16
		dst     string
		verdict uint32
	}{
		{"sleep から許可する宛先", 1001, "198.51.100.20:443", nfAccept},
		{"sleep から拒否する宛先", 1001, "203.0.113.5:443", nfRepeat},
		{"エージェントから API", 1002, "198.51.100.7:443", nfAccept},
		{"エージェントからほか", 1002, "198.51.100.20:443", nfRepeat},
		{"持ち主が分からない", 1003, "203.0.113.5:443", nfAccept},
	} {
		v, mark := verdict(uint32(tc.port), tc.port, tc.dst)
		if v != tc.verdict || (v == nfRepeat) != (mark == nft.AppsDenyMark) {
			t.Errorf("%s = 判断 %d、印 %x", tc.name, v, mark)
		}
	}
	// 拒否は検知結果になり、エージェントの帰属が付く。
	var findings []*event.Event
	for len(out) > 0 {
		findings = append(findings, <-out)
	}
	if len(findings) != 2 {
		t.Fatalf("検知結果 = %d 件", len(findings))
	}
	for _, e := range findings {
		ac := e.Unmapped["app_control"].(map[string]any)
		if !e.FindingInfo.HasType(event.FindingTypeAppControl) || ac["action"] != "deny" || e.DstEndpoint == nil {
			t.Errorf("検知結果 = %+v", e)
		}
	}
	if _, ok := findings[1].Unmapped["agent"]; !ok {
		t.Errorf("エージェントの帰属がない: %v", findings[1].Unmapped)
	}

	// 試験運用では通して、拒否に当たったことだけを記録する。
	monitor := *ac
	monitor.Mode = policy.AppMonitor
	f.set(ctx, &monitor, exempt)
	if v, _ := verdict(11, 1001, "203.0.113.6:443"); v != nfAccept {
		t.Errorf("試験運用の判断 = %d", v)
	}
	if e := <-out; e.Unmapped["app_control"].(map[string]any)["action"] != "would_deny" {
		t.Errorf("試験運用の検知結果 = %+v", e.Unmapped)
	}
	// ルールを外すと、キューを閉じてテーブルを消す。
	if err := f.set(ctx, nil, nil); err != nil || !strings.Contains(rec.last(), "delete table inet susanoo_apps") || f.q != nil {
		t.Errorf("止めた後 = %v %q", err, rec.last())
	}
}
