package controller

import (
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/policy"
)

// heartbeatApplied は、適用済みの版数 applied を報告するハートビートを送り、受け取った指示を返す。
func (d *peer) heartbeatApplied(applied uint64) api.Command {
	d.f.t.Helper()
	d.count++
	status, body := d.do(http.MethodPost, api.PathHeartbeat, d.signedHeartbeat(api.Heartbeat{
		DeviceID: d.id, BootID: d.boot, Counter: d.count, Time: d.f.clock.now(), Hostname: d.id, Applied: applied,
	}))
	return d.command(status, body)
}

// ハートビートは届くのに指示を適用しないままの端末を検知する。すぐに適用する端末は検知しない。
func TestCommandNotApplied(t *testing.T) {
	env := pkitest.New(t)
	f := start(t, env, t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	pc1, pc2 := f.peer(pki.RoleClient, "pc-001"), f.peer(pki.RoleClient, "pc-002")
	admin := f.peer(pki.RoleAdmin, "admin")
	pc1.heartbeatApplied(0)
	pc2.heartbeatApplied(0)
	for _, id := range []string{"pc-001", "pc-002"} {
		if status, body := admin.do(http.MethodPost, api.PathDevices+"/"+id+"/isolate", nil); status != http.StatusOK {
			t.Fatalf("隔離の応答 = %d %s", status, body)
		}
	}
	// pc-002 は指示を受け取るたびに適用する。pc-001 は適用しない（乗っ取られた解析部が渡さない）。
	var applied uint64
	for i := range 4 {
		f.clock.advance(10 * time.Second)
		cmd := pc2.heartbeatApplied(applied)
		applied = cmd.Version
		pc1.heartbeatApplied(0)
		if i < 2 && f.devices(admin)["pc-001"].Lagging {
			t.Fatalf("%d 回目のハートビートで判断しました", i+1)
		}
	}
	devs := f.devices(admin)
	if !devs["pc-001"].Lagging || devs["pc-002"].Lagging {
		t.Fatalf("指示の未適用 = pc-001 %v、pc-002 %v", devs["pc-001"].Lagging, devs["pc-002"].Lagging)
	}
	findings := f.findingsOf(admin, event.FindingTypeCommandNotApplied)
	if len(findings) != 1 || findings[0].Device.UID != "pc-001" || findings[0].SeverityID != event.SeverityHigh {
		t.Fatalf("指示の未適用の検知結果 = %+v", findings)
	}
	if st := f.status(admin); len(st.Lagging) != 1 || st.Lagging[0].ID != "pc-001" {
		t.Errorf("状態の指示の未適用 = %+v", st.Lagging)
	}
	// 遅れ続けても検知結果は重ねない。追いついたら戻す。
	f.clock.advance(10 * time.Second)
	cmd := pc1.heartbeatApplied(0)
	pc1.heartbeatApplied(cmd.Version)
	if f.devices(admin)["pc-001"].Lagging {
		t.Error("追いついても戻しません")
	}
	if n := len(f.findingsOf(admin, event.FindingTypeCommandNotApplied)); n != 1 {
		t.Errorf("指示の未適用の検知結果 = %d 件", n)
	}
}

// 隔離中に更新サーバーが変わったら、版数を上げて指示に入れる（CLIENT の自己隔離にも反映させる）。
func TestUpdatesChangeBumpsVersion(t *testing.T) {
	signer := newPolicySigner(t)
	f, _ := startPolicy(t, signer)
	pc1 := f.peer(pki.RoleClient, "pc-001")
	admin := f.peer(pki.RoleAdmin, "admin")
	pc1.heartbeatApplied(0)
	if status, body := admin.do(http.MethodPost, api.PathDevices+"/pc-001/isolate", api.IsolateRequest{Level: policy.IsolateManagementAndUpdates}); status != http.StatusOK {
		t.Fatalf("隔離の応答 = %d %s", status, body)
	}
	before := pc1.heartbeatApplied(0)
	if !slices.Equal(before.Updates, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}) {
		t.Fatalf("隔離の指示の更新サーバー = %v", before.Updates)
	}
	// 変わらなければ版数は上げない。
	if again := pc1.heartbeatApplied(before.Version); again.Version != before.Version {
		t.Errorf("変わっていないのに版数を上げました: %d → %d", before.Version, again.Version)
	}
	p := groupPolicy()
	p.Version, p.IssuedAt = 2, time.Now()
	p.Groups[0].Updates = []policy.Destination{{CIDR: "198.51.100.0/24"}}
	if status, body := push2(t, admin, signer, p); status != http.StatusOK {
		t.Fatalf("ポリシーの配布の応答 = %d %s", status, body)
	}
	after := pc1.heartbeatApplied(before.Version)
	if after.Version <= before.Version || !slices.Equal(after.Updates, []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}) || after.Isolation != policy.IsolateManagementAndUpdates {
		t.Errorf("更新サーバーを変えた後の指示 = 版数 %d（前 %d）、%v", after.Version, before.Version, after.Updates)
	}
}

// 指示には GW の LAN 側のアドレスと MAC アドレスが入る。端末が知らせた ARP の表のなりすましでは、GW のアドレスを指していた
// 機器をゲートウェイのなりすましとして隔離し、知らせた端末は隔離しない。
func TestARPPoisoningReport(t *testing.T) {
	f := startWith(t, pkitest.New(t), t.TempDir(), testPolicy(policy.ResponseEnforce, false), &fakeLAN{})
	pc1 := f.peer(pki.RoleClient, "pc-001")
	admin := f.peer(pki.RoleAdmin, "admin")
	cmd := pc1.heartbeatApplied(0)
	if g := cmd.Gateway; g == nil || g.IP != f.lan.Addr() || g.MAC != gwMAC.String() {
		t.Fatalf("指示の GW の情報 = %+v", cmd.Gateway)
	}
	f.ctrl.ObserveNeighbor(macBad, netip.MustParseAddr("127.0.0.66")) // 台帳にある機器
	report := func(observed string) {
		t.Helper()
		e := event.New(event.ClassDetectionFinding, event.FindingCreate, event.SeverityHigh, time.Now())
		e.Message = "ARP の表のなりすまし"
		e.FindingInfo = &event.FindingInfo{UID: "x-" + observed, Title: "端末の ARP の表のなりすまし", Types: []string{event.FindingTypeARPPoisoning}}
		e.Unmapped = map[string]any{"arp": map[string]any{"ip": f.lan.Addr().String(), "expected_mac": gwMAC.String(), "observed_mac": observed}}
		if status, body := pc1.do(http.MethodPost, api.PathEvents, api.EventBatch{Events: []event.Event{*e}}); status != http.StatusOK {
			t.Fatalf("イベントの応答 = %d %s", status, body)
		}
	}
	// GW 自身と台帳にない機器は扱わない。
	report(gwMAC.String())
	report("02:00:00:00:00:99")
	if h := f.hosts(admin); len(h) != 1 || h[macBad.String()].Isolation != "" {
		t.Fatalf("扱わない MAC アドレスで機器を変えました: %+v", h)
	}
	report(macBad.String())
	h := f.hosts(admin)[macBad.String()]
	if h.Isolation == "" || h.Reason != ReasonGatewaySpoofing {
		t.Fatalf("なりすました機器 = %+v", h)
	}
	if d := f.devices(admin)["pc-001"]; d.Isolation != "" {
		t.Errorf("知らせた端末を隔離しました: %+v", d)
	}
	text := eventsText(t, f.dir)
	if !strings.Contains(text, `"arp_poisoning"`) || !strings.Contains(text, `"reported_by":"pc-001"`) {
		t.Error("検知結果がありません")
	}
}
