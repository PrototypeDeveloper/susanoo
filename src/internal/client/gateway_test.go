package client

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/platform/platformtest"
	"susanoo/internal/sign"
)

// neighborPlatform は ARP の表を試験から決められる Platform。
type neighborPlatform struct {
	*platformtest.Fake
	mu      sync.Mutex
	table   map[netip.Addr]net.HardwareAddr
	pins    []string
	unpins  int
	pinFail error
}

func (p *neighborPlatform) Neighbor(ip netip.Addr) (net.HardwareAddr, string, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	mac, ok := p.table[ip]
	return mac, "eth0", ok, nil
}

func (p *neighborPlatform) PinNeighbor(ip netip.Addr, iface string, mac net.HardwareAddr) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pinFail != nil {
		return p.pinFail
	}
	p.pins = append(p.pins, ip.String()+"@"+iface+"="+mac.String())
	p.table[ip] = mac
	return nil
}

func (p *neighborPlatform) UnpinNeighbors() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.unpins++
	return nil
}

func (p *neighborPlatform) set(ip netip.Addr, mac string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	hw, _ := net.ParseMAC(mac)
	p.table[ip] = hw
}

func (p *neighborPlatform) state() ([]string, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.pins), p.unpins
}

// 指示で知らせた GW の MAC アドレスと ARP の表のエントリが違えば、正しい MAC アドレスに固定して検知結果を送る。
func TestGatewayGuard(t *testing.T) {
	env := pkitest.New(t)
	gwIP := netip.MustParseAddr("192.0.2.1")
	p := &neighborPlatform{Fake: platformtest.New(caps), table: map[netip.Addr]net.HardwareAddr{}}
	l := newLocal(t, env, netip.MustParseAddrPort("192.0.2.1:8443"), t.TempDir(), p)
	ctx := context.Background()
	// 知らされる前は確かめない。
	p.set(gwIP, "02:00:00:00:00:bd")
	if e := l.checkGateway(); e != nil {
		t.Fatalf("知らされる前に検知結果: %+v", e)
	}
	gw := &api.GatewayInfo{IP: gwIP, MAC: "02:00:00:00:00:fe"}
	if err := l.Apply(ctx, command(t, env.Signer, sign.PurposeCommand, api.Command{DeviceID: "pc-001", Version: 5, Gateway: gw})); err != nil {
		t.Fatal(err)
	}
	// 版数を上げずに知らせ始めても受け取る。古い版数の指示の情報は使わない。
	if err := l.Apply(ctx, command(t, env.Signer, sign.PurposeCommand, api.Command{DeviceID: "pc-001", Version: 3, Gateway: &api.GatewayInfo{IP: gwIP, MAC: "02:00:00:00:00:aa"}})); err != nil {
		t.Fatal(err)
	}
	if !sameGateway(l.state.Gateway, gw) {
		t.Fatalf("記録した GW の情報 = %+v", l.state.Gateway)
	}
	e := l.checkGateway()
	if e == nil || !e.FindingInfo.HasType(event.FindingTypeARPPoisoning) {
		t.Fatalf("なりすましの検知結果 = %+v", e)
	}
	arp := e.Unmapped["arp"].(map[string]any)
	if arp["observed_mac"] != "02:00:00:00:00:bd" || arp["expected_mac"] != "02:00:00:00:00:fe" || arp["pinned"] != true {
		t.Errorf("検知結果の中身 = %+v", arp)
	}
	if err := e.Validate(); err != nil {
		t.Error(err)
	}
	if pins, _ := p.state(); !slices.Equal(pins, []string{"192.0.2.1@eth0=02:00:00:00:00:fe"}) {
		t.Errorf("固定 = %v", pins)
	}
	// 固定した後は正しいので、検知結果を重ねない。
	if e := l.checkGateway(); e != nil {
		t.Errorf("固定した後の検知結果: %+v", e)
	}
	// GW の MAC アドレスが変わったら（指示で知らされる）、自分で固定した前の MAC アドレスは知らせずに固定し直す。
	if err := l.Apply(ctx, command(t, env.Signer, sign.PurposeCommand, api.Command{DeviceID: "pc-001", Version: 6, Gateway: &api.GatewayInfo{IP: gwIP, MAC: "02:00:00:00:00:fd"}})); err != nil {
		t.Fatal(err)
	}
	if e := l.checkGateway(); e != nil {
		t.Errorf("GW の MAC アドレスが変わったときの検知結果: %+v", e)
	}
	if pins, _ := p.state(); len(pins) != 2 || pins[1] != "192.0.2.1@eth0=02:00:00:00:00:fd" {
		t.Errorf("固定し直し = %v", pins)
	}
	// 固定できないときも 1 回だけ知らせる。
	p.mu.Lock()
	p.pinFail = net.UnknownNetworkError("権限がありません")
	p.mu.Unlock()
	p.set(gwIP, "02:00:00:00:00:cc")
	if e := l.checkGateway(); e == nil || e.Unmapped["arp"].(map[string]any)["pinned"] != false {
		t.Errorf("固定できないときの検知結果 = %+v", e)
	}
	if e := l.checkGateway(); e != nil {
		t.Errorf("同じなりすましを重ねて知らせました: %+v", e)
	}
	// 止めるときは固定を消す。
	wctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { l.Watch(wctx, make(chan event.Event, 16)); close(done) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	if _, unpins := p.state(); unpins != 1 {
		t.Errorf("固定を消した回数 = %d", unpins)
	}
}
