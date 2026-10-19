package client

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/platform"
)

// GW の MAC アドレスの監視（2m-1）。端末だけに宛てた（ユニキャストの）ARP のなりすましは、スイッチが GW に転送しないので
// GW では検知できない。CLIENT は、CONTROLLER が署名付きの指示で知らせた GW の MAC アドレスと、自分の ARP の表の GW の
// エントリを比べ、違えばエントリを正しい MAC アドレスに固定して（管理通信を GW に届くようにして）、検知結果を送る。
// CONTROLLER は、エントリが指していた機器をゲートウェイのなりすましとして扱う。

// gatewayGuard は ARP の表の確認の状態。
type gatewayGuard struct {
	bad    string // 知らせた、なりすましの MAC アドレス（同じものを何度も知らせない）
	pinned string // 固定した MAC アドレス
}

// sameGateway は 2 つの GW の情報が同じかを返す。
func sameGateway(a, b *api.GatewayInfo) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// checkGateway は、ARP の表の GW のエントリが、CONTROLLER が知らせた MAC アドレスを指しているかを確かめる。
// 違えばエントリを正しい MAC アドレスに固定し、検知結果を返す。
func (l *Local) checkGateway() *event.Event {
	nb, ok := l.cfg.Platform.(platform.Neighbors)
	if !ok {
		return nil
	}
	l.mu.Lock()
	gw := l.state.Gateway
	l.mu.Unlock()
	if gw == nil || !gw.IP.Is4() {
		return nil
	}
	want, err := net.ParseMAC(gw.MAC)
	if err != nil {
		return nil
	}
	got, iface, found, err := nb.Neighbor(gw.IP)
	if err != nil || !found {
		return nil
	}
	l.gwMu.Lock()
	defer l.gwMu.Unlock()
	if bytes.Equal(got, want) {
		l.gw.bad = ""
		return nil
	}
	prevPinned := l.gw.pinned
	pinErr := nb.PinNeighbor(gw.IP, iface, want)
	if pinErr == nil {
		l.gw.pinned = want.String()
	}
	// 自分で固定した前の MAC アドレス（GW の MAC アドレスが変わった）なら、固定し直すだけにする。
	if got.String() == prevPinned || got.String() == l.gw.bad {
		return nil
	}
	l.gw.bad = got.String()
	result := "正しい MAC アドレスに固定しました"
	if pinErr != nil {
		result = "正しい MAC アドレスに固定できませんでした（" + pinErr.Error() + "）"
		l.log.Error("ARP の表の GW のエントリを固定できません", "エラー", pinErr)
	}
	msg := fmt.Sprintf("端末の ARP の表で、GW のアドレス %s が別の MAC アドレス %s を指していました（正しくは %s）。"+
		"端末だけに宛てた ARP のなりすましで、通信を横取りされた恐れがあります。%s", gw.IP, got, want, result)
	l.log.Warn("ARP の表の GW のエントリがなりすまされていました", "アドレス", gw.IP, "なりすまし", got.String(), "正しい MAC", want.String(), "固定", pinErr == nil)
	e := event.New(event.ClassDetectionFinding, event.FindingCreate, event.SeverityHigh, l.cfg.Now())
	e.Message = msg
	e.FindingInfo = &event.FindingInfo{UID: rand.Text(), Title: "端末の ARP の表のなりすまし", Desc: msg, Types: []string{event.FindingTypeARPPoisoning}}
	e.Device = &event.Device{Hostname: l.hostname}
	e.Unmapped = map[string]any{"arp": map[string]any{
		"ip": gw.IP.String(), "expected_mac": want.String(), "observed_mac": got.String(), "interface": iface, "pinned": pinErr == nil,
	}}
	return e
}

// unpinGateway は、固定した ARP の表のエントリを消す（CLIENT を止めるとき。固定したままにすると、GW を入れ替えたときに通信できなくなるため）。
func (l *Local) unpinGateway() {
	nb, ok := l.cfg.Platform.(platform.Neighbors)
	if !ok {
		return
	}
	l.gwMu.Lock()
	defer l.gwMu.Unlock()
	if l.gw.pinned == "" {
		return
	}
	if err := nb.UnpinNeighbors(); err != nil {
		l.log.Warn("固定した ARP の表のエントリを消せません", "エラー", err)
	}
	l.gw.pinned = ""
}
