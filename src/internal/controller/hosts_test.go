package controller

import (
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/policy"
)

var (
	macPC  = net.HardwareAddr{2, 0, 0, 0, 0, 1}
	macPC2 = net.HardwareAddr{2, 0, 0, 0, 0, 2}
	macBad = net.HardwareAddr{2, 0, 0, 0, 0, 0xbd}
)

func (f *fixture) hosts(admin *peer) map[string]api.Host {
	f.t.Helper()
	status, body := admin.do(http.MethodGet, api.PathHosts, nil)
	if status != http.StatusOK {
		f.t.Fatalf("機器の一覧を取得できない: %d %s", status, body)
	}
	var list []api.Host
	if err := json.Unmarshal(body, &list); err != nil {
		f.t.Fatal(err)
	}
	out := map[string]api.Host{}
	for _, h := range list {
		out[h.MAC] = h
	}
	return out
}

func eventsText(t *testing.T, dir string) string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "events", "*.jsonl"))
	var b strings.Builder
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(data)
	}
	return b.String()
}

func TestHostLedgerLinksDevice(t *testing.T) {
	f := startWith(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false), &fakeLAN{})
	admin := f.peer(pki.RoleAdmin, "admin")
	f.ctrl.ObserveLease(macPC.String(), loopback, "pc-001", f.clock.now().Add(time.Hour), false)

	h := f.hosts(admin)[macPC.String()]
	if h.IP != "127.0.0.1" || h.Hostname != "pc-001" || h.DeviceID != "" || h.Lease.IsZero() {
		t.Errorf("機器 = %+v", h)
	}
	if ev := eventsText(t, f.dir); !strings.Contains(ev, `"new_device"`) || !strings.Contains(ev, `"class_uid":4004`) {
		t.Errorf("新しい機器と DHCP のイベントがない: %s", ev)
	}

	// ハートビートの送信元のアドレスで、端末と機器が結び付く。
	pc := f.peer(pki.RoleClient, "pc-001")
	pc.heartbeat()
	if h := f.hosts(admin)[macPC.String()]; h.DeviceID != "pc-001" {
		t.Errorf("端末と結び付いていない: %+v", h)
	}
	if d := f.devices(admin)["pc-001"]; !slices.Equal(d.MACs, []string{macPC.String()}) {
		t.Errorf("端末の MAC アドレス = %v", d.MACs)
	}

	// 隔離すると、MAC アドレスでも遮断する。
	pc.touchHoneytoken()
	if got := f.enf.last(); got.macs[macPC.String()] != policy.IsolateManagementAndUpdates || got.addrs[loopback] == "" {
		t.Errorf("GW の遮断 = %+v", got)
	}
	if !f.ctrl.Quarantined(loopback) {
		t.Error("隔離中のアドレスを DHCP に知らせていない")
	}
	admin.do(http.MethodPost, api.PathDevices+"/pc-001/release", nil)
	if f.ctrl.Quarantined(loopback) || len(f.enf.last().macs) != 0 {
		t.Error("解除後も遮断している")
	}
}

func TestGatewaySpoofing(t *testing.T) {
	f := startWith(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false), &fakeLAN{})
	admin := f.peer(pki.RoleAdmin, "admin")

	// GW 自身の ARP は無視する。
	f.ctrl.ObserveNeighbor(gwMAC, f.lan.Addr())
	if len(f.hosts(admin)) != 0 {
		t.Error("GW 自身を機器として台帳に載せた")
	}

	// CLIENT のない機器が GW のアドレスを名乗ると、GW で遮断する。
	f.ctrl.ObserveNeighbor(macBad, f.lan.Addr())
	h := f.hosts(admin)[macBad.String()]
	if h.Isolation != policy.IsolateManagementAndUpdates || h.Reason != ReasonGatewaySpoofing {
		t.Fatalf("機器 = %+v", h)
	}
	if got := f.enf.last().macs[macBad.String()]; got == "" {
		t.Errorf("MAC アドレスで遮断していない: %+v", f.enf.last())
	}
	if h.IP != "" {
		t.Errorf("名乗った GW のアドレスを機器のアドレスにした: %s", h.IP)
	}
	// 続けて名乗っても、検知結果は 1 分に 1 回。
	f.ctrl.ObserveNeighbor(macBad, f.lan.Addr())
	if n := strings.Count(eventsText(t, f.dir), `"gateway_spoofing"`); n != 1 {
		t.Errorf("なりすましの検知結果が %d 件", n)
	}

	status, body := admin.do(http.MethodPost, api.PathHosts+"/"+macBad.String()+"/release", nil)
	if status != http.StatusOK {
		t.Fatalf("解除の応答 = %d %s", status, body)
	}
	if h := f.hosts(admin)[macBad.String()]; h.Isolation != "" || len(f.enf.last().macs) != 0 {
		t.Errorf("解除後の機器 = %+v", h)
	}
	want := []string{"host.isolate:" + macBad.String(), "host.release:" + macBad.String()}
	// 隔離するとインシデントを自動で開く（ID は日付を含むので、別に数える）。
	got, opened := withoutIncidentOpen(auditActions(t, f.dir))
	if !slices.Equal(got, want) || opened != 1 {
		t.Errorf("監査ログ = %v（インシデント %d 件）, 期待値 %v", got, opened, want)
	}
	if status, _ := admin.do(http.MethodPost, api.PathHosts+"/not-a-mac/isolate", nil); status != http.StatusBadRequest {
		t.Errorf("不正な MAC アドレスの応答 = %d", status)
	}
}

func TestIPSpoofing(t *testing.T) {
	f := startWith(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false), &fakeLAN{})
	admin := f.peer(pki.RoleAdmin, "admin")
	victim := netip.MustParseAddr("127.0.0.5")
	f.ctrl.ObserveLease(macPC.String(), victim, "", f.clock.now().Add(time.Hour), false)

	// 割り当てを受けた本人の ARP は問題ない。
	f.ctrl.ObserveNeighbor(macPC, victim)
	// ほかの機器が同じアドレスを名乗ると、名乗った機器を遮断する。
	f.ctrl.ObserveNeighbor(macBad, victim)
	hosts := f.hosts(admin)
	if hosts[macPC.String()].Isolation != "" {
		t.Errorf("割り当てを受けた機器を隔離した: %+v", hosts[macPC.String()])
	}
	if h := hosts[macBad.String()]; h.Isolation == "" || h.Reason != ReasonIPSpoofing {
		t.Errorf("名乗った機器 = %+v", h)
	}
	// 割り当ての期限が切れた後なら、ほかの機器が使っても問題ない。
	f.clock.advance(2 * time.Hour)
	f.ctrl.ObserveNeighbor(macPC2, victim)
	if h := f.hosts(admin)[macPC2.String()]; h.Isolation != "" || h.IP != "127.0.0.5" {
		t.Errorf("期限切れのアドレスを使った機器 = %+v", h)
	}
}

func TestSpoofingByLinkedDeviceIsolatesDevice(t *testing.T) {
	f := startWith(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false), &fakeLAN{})
	admin := f.peer(pki.RoleAdmin, "admin")
	f.ctrl.ObserveLease(macPC.String(), loopback, "", f.clock.now().Add(time.Hour), false)
	pc := f.peer(pki.RoleClient, "pc-001")
	pc.heartbeat()

	f.ctrl.ObserveNeighbor(macPC, f.lan.Addr())
	_, cmd := pc.heartbeat()
	if cmd.Isolation == "" {
		t.Error("なりすました端末に自己隔離を指示していない")
	}
	if d := f.devices(admin)["pc-001"]; d.Reason != ReasonGatewaySpoofing {
		t.Errorf("端末の隔離の理由 = %q", d.Reason)
	}
}

func TestHeartbeatLossAwayAndBack(t *testing.T) {
	f := startWith(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false), &fakeLAN{})
	admin := f.peer(pki.RoleAdmin, "admin")
	f.ctrl.ObserveLease(macPC.String(), loopback, "", f.clock.now().Add(time.Hour), false)
	pc := f.peer(pki.RoleClient, "pc-001")
	pc.heartbeat()

	// LAN にいない端末は、ハートビートが途絶えても隔離しない。
	f.clock.advance(time.Minute)
	f.ctrl.checkHeartbeats()
	d := f.devices(admin)["pc-001"]
	if d.Isolation != "" || !d.Away {
		t.Fatalf("不在の端末 = %+v", d)
	}
	if !strings.Contains(eventsText(t, f.dir), `"device_away"`) {
		t.Error("不在のイベントがない")
	}

	// LAN に戻ると確認を再開し、それでもハートビートがなければ隔離する。
	f.ctrl.ObserveNeighbor(macPC, loopback)
	if d := f.devices(admin)["pc-001"]; d.Away {
		t.Fatalf("LAN に戻っても不在のまま: %+v", d)
	}
	// 戻った端末には、接続し直す時間を見込んで判定までの時間を 2 倍（60 秒）にする。
	f.lan.set(loopback, macPC)
	f.clock.advance(45 * time.Second)
	f.ctrl.checkHeartbeats()
	if d := f.devices(admin)["pc-001"]; d.Isolation != "" {
		t.Fatalf("戻ってすぐに隔離した: %+v", d)
	}
	f.clock.advance(20 * time.Second)
	f.ctrl.checkHeartbeats()
	if d := f.devices(admin)["pc-001"]; d.Isolation == "" || d.Reason != ReasonHeartbeatLost {
		t.Errorf("LAN にいるのにハートビートがない端末 = %+v", d)
	}
}

func TestHeartbeatLossOtherMachineAnswers(t *testing.T) {
	f := startWith(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false), &fakeLAN{})
	admin := f.peer(pki.RoleAdmin, "admin")
	f.ctrl.ObserveLease(macPC.String(), loopback, "", f.clock.now().Add(time.Hour), false)
	f.peer(pki.RoleClient, "pc-001").heartbeat()

	// 端末のアドレスに別の機器が応答しても、端末がいるとはみなさない。
	f.lan.set(loopback, macPC2)
	f.clock.advance(time.Minute)
	f.ctrl.checkHeartbeats()
	if d := f.devices(admin)["pc-001"]; d.Isolation != "" || !d.Away {
		t.Errorf("端末 = %+v", d)
	}
}

func TestHeartbeatLossProbesNewAddress(t *testing.T) {
	f := startWith(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false), &fakeLAN{})
	admin := f.peer(pki.RoleAdmin, "admin")
	f.ctrl.ObserveLease(macPC.String(), loopback, "", f.clock.now().Add(time.Hour), false)
	f.peer(pki.RoleClient, "pc-001").heartbeat()

	// 端末のアドレスが変わり（ARP で分かる）、ハートビートが届かなくなった。
	moved := netip.MustParseAddr("127.0.0.9")
	f.ctrl.ObserveNeighbor(macPC, moved)
	f.lan.set(moved, macPC)
	f.clock.advance(time.Minute)
	f.ctrl.checkHeartbeats()
	if d := f.devices(admin)["pc-001"]; d.Isolation == "" || d.Away {
		t.Errorf("新しいアドレスで LAN にいる端末を不在とした: %+v", d)
	}
}

func TestAdminIsolateHostOfDevice(t *testing.T) {
	f := startWith(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false), &fakeLAN{})
	admin := f.peer(pki.RoleAdmin, "admin")
	f.ctrl.ObserveLease(macPC.String(), loopback, "", f.clock.now().Add(time.Hour), false)
	pc := f.peer(pki.RoleClient, "pc-001")
	pc.heartbeat()

	// 端末に結び付いた機器を指定すると、端末を隔離する。
	status, body := admin.do(http.MethodPost, api.PathHosts+"/"+strings.ToUpper(macPC.String())+"/isolate", api.IsolateRequest{Level: policy.IsolateFull})
	if status != http.StatusOK {
		t.Fatalf("隔離の応答 = %d %s", status, body)
	}
	if d := f.devices(admin)["pc-001"]; d.Isolation != policy.IsolateFull {
		t.Errorf("端末 = %+v", d)
	}
	admin.do(http.MethodPost, api.PathHosts+"/"+macPC.String()+"/release", nil)
	if d := f.devices(admin)["pc-001"]; d.Isolation != "" {
		t.Errorf("解除後の端末 = %+v", d)
	}
}

func TestReportChange(t *testing.T) {
	f := start(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	f.ctrl.ReportChange("/etc/susanoo/policy.json")
	if got := auditActions(t, f.dir); !slices.Equal(got, []string{"config.changed:/etc/susanoo/policy.json"}) {
		t.Errorf("監査ログ = %v", got)
	}
	if !strings.Contains(eventsText(t, f.dir), `"config_changed"`) {
		t.Error("設定の変更のイベントがない")
	}
}
