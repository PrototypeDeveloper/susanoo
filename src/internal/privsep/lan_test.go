//go:build linux

package privsep

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"susanoo/internal/controller"
	"susanoo/internal/egress"
	"susanoo/internal/policy"
)

// fakeObserver は CONTROLLER の代わりに、LAN 側の処理からの知らせを記録する。
type fakeObserver struct {
	mu    sync.Mutex
	calls []string
	block chan struct{} // nil でなければ、最初の知らせで閉じるまで待つ
}

func (o *fakeObserver) add(s string) {
	if o.block != nil {
		<-o.block
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, s)
}

func (o *fakeObserver) all() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.calls...)
}

func (o *fakeObserver) ObserveNeighbor(frame net.HardwareAddr, ip netip.Addr) {
	o.add("neighbor " + frame.String() + " " + ip.String())
}
func (o *fakeObserver) ObserveARPRequest(frame net.HardwareAddr, target netip.Addr) {
	o.add("arp " + frame.String() + " " + target.String())
}
func (o *fakeObserver) ObserveLease(mac string, ip netip.Addr, hostname string, _ time.Time, released bool) {
	o.add("lease " + mac + " " + ip.String() + " " + hostname)
}
func (o *fakeObserver) RecordDNS(r controller.DNSRecord)   { o.add("dns " + r.Name) }
func (o *fakeObserver) RecordFlow(r controller.FlowRecord) { o.add("flow " + r.SNI) }
func (o *fakeObserver) RecordLearned(group, domain string, blocked bool) {
	o.add("learned " + group + " " + domain)
}
func (o *fakeObserver) ObserveND(n controller.NDObservation) {
	o.add(fmt.Sprintf("nd %d %s %s %v", n.Type, n.Frame, n.Src, n.Prefixes))
}
func (o *fakeObserver) ObserveDHCPv6(d controller.DHCPv6Observation) {
	o.add(fmt.Sprintf("dhcp6 %s %s %v", d.Frame, d.Src, d.DNS))
}

// fakeServices は LAN 側の処理の代わりに、CONTROLLER の要求に応える。
type fakeServices struct {
	mu        sync.Mutex
	members   []egress.Membership
	withdrawn []string
}

func (s *fakeServices) Probe(_ context.Context, ip netip.Addr) (net.HardwareAddr, bool) {
	if ip == netip.MustParseAddr("10.77.0.100") {
		hw, _ := net.ParseMAC("02:00:00:00:00:64")
		return hw, true
	}
	return nil, false
}

func (s *fakeServices) WithdrawRA(_ context.Context, src netip.Addr, mac net.HardwareAddr, prefixes []netip.Prefix, _ []netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.withdrawn = append(s.withdrawn, fmt.Sprintf("%s %s %v", src, mac, prefixes))
	return nil
}

func (s *fakeServices) SetMembership(_ context.Context, m egress.Membership) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.members = append(s.members, m)
	return nil
}

func lanPair(t *testing.T) (*LANLink, *ControllerLink) {
	t.Helper()
	a, b := socketpair(t)
	ctrlSide := ConnectLAN(a, quiet)
	lanSide := ConnectController(b, quiet)
	t.Cleanup(func() { ctrlSide.Close(); lanSide.Close() })
	return ctrlSide, lanSide
}

func waitCalls(t *testing.T, o *fakeObserver, n int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(o.all()) < n {
		if time.Now().After(deadline) {
			t.Fatalf("知らせが %d 件しか届かない: %v", len(o.all()), o.all())
		}
		time.Sleep(10 * time.Millisecond)
	}
	return o.all()
}

// LAN 側の処理は見つけたことを知らせ、CONTROLLER は在席の確認とグループの受け渡しを頼む。
// 渡し先を決める前に届いた知らせは、たまってから渡される。CONTROLLER の要求は、LAN 側の処理の準備ができるまで待つ。
func TestLANLink(t *testing.T) {
	ctrlSide, lanSide := lanPair(t)
	mac, _ := net.ParseMAC("02:00:00:00:00:65")
	lanSide.ObserveNeighbor(mac, netip.MustParseAddr("10.77.0.101"))
	lanSide.ObserveLease("02:00:00:00:00:65", netip.MustParseAddr("10.77.0.101"), "pc-002", time.Now().Add(time.Hour), false)
	lanSide.RecordDNS(controller.DNSRecord{Name: "example.test", Client: netip.MustParseAddr("10.77.0.101")})
	lanSide.RecordFlow(controller.FlowRecord{SNI: "secure.test", Src: netip.MustParseAddrPort("10.77.0.101:40000")})
	lanSide.RecordLearned("default", "new.test", false)
	lanSide.ObserveARPRequest(mac, netip.MustParseAddr("10.77.0.150"))
	lanSide.ObserveND(controller.NDObservation{Frame: mac, Type: 134, Src: netip.MustParseAddr("fe80::bad"), RouterLifetime: 1800,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8:bad::/64")}})
	lanSide.ObserveDHCPv6(controller.DHCPv6Observation{Frame: mac, Src: netip.MustParseAddr("fe80::bad"), DNS: []netip.Addr{netip.MustParseAddr("fe80::bad")}})

	obs := &fakeObserver{}
	time.Sleep(50 * time.Millisecond)
	ctrlSide.SetObserver(obs)
	got := strings.Join(waitCalls(t, obs, 8), "\n")
	for _, want := range []string{"neighbor 02:00:00:00:00:65 10.77.0.101", "arp 02:00:00:00:00:65 10.77.0.150", "lease 02:00:00:00:00:65 10.77.0.101 pc-002", "dns example.test", "flow secure.test", "learned default new.test",
		"nd 134 02:00:00:00:00:65 fe80::bad [2001:db8:bad::/64]", "dhcp6 02:00:00:00:00:65 fe80::bad [fe80::bad]"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q が届かない\n%s", want, got)
		}
	}

	svc := &fakeServices{}
	probed := make(chan bool, 1)
	go func() {
		_, ok := ctrlSide.Probe(context.Background(), netip.MustParseAddr("10.77.0.100"))
		probed <- ok
	}()
	time.Sleep(50 * time.Millisecond)
	lanSide.Serve(svc) // それまで要求は待たされる
	if !<-probed {
		t.Error("LAN にいる機器を見つけられない")
	}
	if _, ok := ctrlSide.Probe(context.Background(), netip.MustParseAddr("10.77.0.200")); ok {
		t.Error("いない機器を見つけた")
	}
	m := egress.Membership{
		MACs:     map[string]string{"02:00:00:00:00:65": "strict"},
		Isolated: map[netip.Addr]policy.IsolationLevel{netip.MustParseAddr("10.77.0.102"): policy.IsolateFull},
	}
	if err := ctrlSide.SetMembership(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if err := ctrlSide.WithdrawRA(context.Background(), netip.MustParseAddr("fe80::bad"), mac, []netip.Prefix{netip.MustParsePrefix("2001:db8:bad::/64")}, nil); err != nil {
		t.Fatal(err)
	}
	// リンクローカルでない送信元の取り消しは、LAN 側の処理が断る。
	if err := ctrlSide.WithdrawRA(context.Background(), netip.MustParseAddr("2001:db8::1"), mac, nil, nil); err == nil {
		t.Error("リンクローカルでない送信元の広告の取り消しを受け付けた")
	}
	svc.mu.Lock()
	if len(svc.withdrawn) != 1 || svc.withdrawn[0] != "fe80::bad 02:00:00:00:00:65 [2001:db8:bad::/64]" {
		t.Errorf("取り消し = %v", svc.withdrawn)
	}
	defer svc.mu.Unlock()
	if len(svc.members) != 1 || svc.members[0].MACs["02:00:00:00:00:65"] != "strict" || svc.members[0].Isolated[netip.MustParseAddr("10.77.0.102")] != policy.IsolateFull {
		t.Errorf("渡したグループ = %+v", svc.members)
	}
}

// LAN 側の処理から形の不正な知らせが届いたら、CONTROLLER は乗っ取られた恐れがあるとみなしてつながりを切る。
func TestLANLinkRejectsMalformedNotices(t *testing.T) {
	for name, send := range map[string]func(*ControllerLink){
		"不正な MAC アドレス": func(l *ControllerLink) {
			l.send(noticeNeighbor, neighborBody{MAC: "; flush ruleset", IP: netip.MustParseAddr("10.77.0.1")})
		},
		"長すぎるホスト名": func(l *ControllerLink) {
			l.send(noticeLease, leaseBody{MAC: "02:00:00:00:00:01", Hostname: strings.Repeat("a", 300)})
		},
		"IPv6 の ARP の宛先": func(l *ControllerLink) {
			l.send(noticeARPReq, arpReqBody{MAC: "02:00:00:00:00:01", Target: netip.MustParseAddr("fe80::1")})
		},
		"IPv4 の近隣探索": func(l *ControllerLink) {
			l.send(noticeND, ndBody{MAC: "02:00:00:00:00:01", Type: 134, Src: netip.MustParseAddr("10.0.0.1")})
		},
		"近隣探索でない種類": func(l *ControllerLink) {
			l.send(noticeND, ndBody{MAC: "02:00:00:00:00:01", Type: 128, Src: netip.MustParseAddr("fe80::1")})
		},
		"多すぎるネットワーク": func(l *ControllerLink) {
			ps := make([]netip.Prefix, 17)
			for i := range ps {
				ps[i] = netip.MustParsePrefix("2001:db8::/64")
			}
			l.send(noticeND, ndBody{MAC: "02:00:00:00:00:01", Type: 134, Src: netip.MustParseAddr("fe80::1"), Prefixes: ps})
		},
		"IPv4 の DHCPv6 の DNS": func(l *ControllerLink) {
			l.send(noticeDHCPv6, dhcp6Body{MAC: "02:00:00:00:00:01", Src: netip.MustParseAddr("fe80::1"), DNS: []netip.Addr{netip.MustParseAddr("10.0.0.1")}})
		},
		"知らない知らせ": func(l *ControllerLink) { l.send("isolate", map[string]string{"id": "pc-001"}) },
		"知らない項目を含む知らせ": func(l *ControllerLink) {
			l.send(noticeLearned, map[string]any{"group": "g", "domain": "d", "release": true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctrlSide, lanSide := lanPair(t)
			obs := &fakeObserver{}
			ctrlSide.SetObserver(obs)
			send(lanSide)
			select {
			case <-ctrlSide.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("不正な知らせでつながりを切らない")
			}
			if len(obs.all()) != 0 {
				t.Errorf("不正な知らせを渡した: %v", obs.all())
			}
		})
	}
}

// CONTROLLER の処理が詰まっても、知らせの受け取りは止まらない（あふれた分は捨てる）。在席の確認も応答を受け取れる。
func TestLANLinkDoesNotBlockReader(t *testing.T) {
	ctrlSide, lanSide := lanPair(t)
	obs := &fakeObserver{block: make(chan struct{})}
	ctrlSide.SetObserver(obs)
	lanSide.Serve(&fakeServices{})
	for range maxLANQueue + 100 {
		lanSide.RecordLearned("default", "flood.test", false)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, ok := ctrlSide.Probe(ctx, netip.MustParseAddr("10.77.0.100")); !ok {
		t.Fatal("知らせがあふれている間に在席の確認の応答を受け取れない")
	}
	if ctrlSide.dropped.Load() == 0 {
		t.Error("あふれた知らせを数えていない")
	}
	close(obs.block)
}
