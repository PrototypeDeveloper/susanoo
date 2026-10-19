package controller

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/policy"
)

// heartbeatAt は、端末の時刻を CONTROLLER の時刻から offset ずらし、資源の使用量 r を載せたハートビートを送る。
func (d *peer) heartbeatAt(offset time.Duration, r *api.ResourceUsage) {
	d.f.t.Helper()
	d.count++
	status, body := d.do(http.MethodPost, api.PathHeartbeat, d.signedHeartbeat(api.Heartbeat{
		DeviceID: d.id, BootID: d.boot, Counter: d.count, Time: d.f.clock.now().Add(offset), Hostname: d.id, Resources: r,
	}))
	if status != http.StatusOK {
		d.f.t.Fatalf("ハートビートの応答 = %d %s", status, body)
	}
}

func (f *fixture) findingsOf(admin *peer, typ string) []event.Event {
	f.t.Helper()
	_, body := admin.do(http.MethodGet, api.PathEvents+"?"+api.EventQuery{Class: "finding", Text: typ, Limit: 100}.Values().Encode(), nil)
	var events []event.Event
	if err := json.Unmarshal(body, &events); err != nil {
		f.t.Fatal(err)
	}
	return events
}

// 端末の時刻のずれは直近のハートビートの中央値で判断し、上限を超えたら 1 回だけ検知結果にする。上限の半分以下に戻ったら直ったとする。
func TestClockSkew(t *testing.T) {
	env := pkitest.New(t)
	f := start(t, env, t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	pc1 := f.peer(pki.RoleClient, "pc-001")
	pc2 := f.peer(pki.RoleClient, "pc-002")
	admin := f.peer(pki.RoleAdmin, "admin")

	for i := range 2 {
		pc1.heartbeatAt(10*time.Minute, nil)
		if d := f.devices(admin)["pc-001"]; d.ClockSkewed {
			t.Fatalf("%d 回目のハートビートで判断しました", i+1)
		}
	}
	for range 3 {
		pc1.heartbeatAt(10*time.Minute, nil)
	}
	d := f.devices(admin)["pc-001"]
	if !d.ClockSkewed || d.ClockOffset != 600 {
		t.Fatalf("時刻のずれ = %v %v", d.ClockSkewed, d.ClockOffset)
	}
	findings := f.findingsOf(admin, event.FindingTypeClockSkew)
	if len(findings) != 1 || findings[0].Device.UID != "pc-001" || findings[0].Unmapped["clock_offset"] != float64(600) {
		t.Fatalf("時刻のずれの検知結果 = %+v", findings)
	}
	st := f.status(admin)
	if len(st.ClockSkewed) != 1 || st.ClockSkewed[0].ID != "pc-001" || st.MaxClockSkew != "2m0s" {
		t.Errorf("状態の時刻のずれ = %+v %q", st.ClockSkewed, st.MaxClockSkew)
	}
	if st.Devices.Isolated != 0 {
		t.Error("時刻のずれで隔離しました")
	}
	// 直るまでは検知結果を重ねない。上限の半分（1 分）を超えるずれが残る間は直ったとしない。
	for range 3 {
		pc1.heartbeatAt(90*time.Second, nil)
	}
	if d := f.devices(admin)["pc-001"]; !d.ClockSkewed || d.ClockOffset != 90 {
		t.Errorf("上限の半分を超えるずれで直ったとしました: %+v", d)
	}
	for range 3 {
		pc1.heartbeatAt(-200*time.Millisecond, nil)
	}
	if d := f.devices(admin)["pc-001"]; d.ClockSkewed || d.ClockOffset != -0.2 {
		t.Errorf("直った後の時刻のずれ = %v %v", d.ClockSkewed, d.ClockOffset)
	}
	if n := len(f.findingsOf(admin, event.FindingTypeClockSkew)); n != 1 {
		t.Errorf("時刻のずれの検知結果 = %d 件", n)
	}
	// 一時的な遅れ（1 回だけのずれ）では判断しない。
	for _, off := range []time.Duration{0, 10 * time.Minute, 0, 0, -10 * time.Minute, 0} {
		pc2.heartbeatAt(off, nil)
	}
	if d := f.devices(admin)["pc-002"]; d.ClockSkewed {
		t.Errorf("一時的なずれで判断しました: %v", d.ClockOffset)
	}
}

// CLIENT が報告した資源の使用量を台帳に記録し、監視を間引いている接続中の端末を状態に載せる。
func TestResourceUsage(t *testing.T) {
	env := pkitest.New(t)
	f := start(t, env, t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	pc1 := f.peer(pki.RoleClient, "pc-001")
	admin := f.peer(pki.RoleAdmin, "admin")
	pc1.heartbeatAt(0, &api.ResourceUsage{CPUPercent: 3.5, MemoryBytes: 40 << 20})
	if r := f.devices(admin)["pc-001"].Resources; r == nil || r.CPUPercent != 3.5 || r.MemoryBytes != 40<<20 || r.Throttled {
		t.Errorf("資源の使用量 = %+v", r)
	}
	if st := f.status(admin); len(st.Throttled) != 0 {
		t.Errorf("間引いていない端末が載りました: %+v", st.Throttled)
	}
	pc1.heartbeatAt(0, &api.ResourceUsage{CPUPercent: 25, MemoryBytes: 300 << 20, Throttled: true, Dropped: 12})
	st := f.status(admin)
	if len(st.Throttled) != 1 || st.Throttled[0].ID != "pc-001" || st.Throttled[0].Resources.Dropped != 12 {
		t.Errorf("間引いている端末 = %+v", st.Throttled)
	}
	// 接続が途絶えた端末の報告は古いので、状態に載せない。
	f.clock.advance(time.Minute)
	if st := f.status(admin); len(st.Throttled) != 0 {
		t.Errorf("接続していない端末が載りました: %+v", st.Throttled)
	}
	// 負の値は記録しない。
	pc1.heartbeatAt(0, &api.ResourceUsage{CPUPercent: -1, MemoryBytes: 1})
	if r := f.devices(admin)["pc-001"].Resources; r != nil {
		t.Errorf("不正な使用量を記録しました: %+v", r)
	}
}

func TestClockSynced(t *testing.T) {
	c := &Controller{}
	if c.clockSynced() != nil {
		t.Error("分からないのに値を返しました")
	}
	for _, want := range []bool{true, false} {
		c.cfg.ClockSynced = func() (bool, error) { return want, nil }
		if got := c.clockSynced(); got == nil || *got != want {
			t.Errorf("clockSynced = %v（%v のはず）", got, want)
		}
	}
	c.cfg.ClockSynced = func() (bool, error) { return false, errors.New("adjtimex") }
	if c.clockSynced() != nil {
		t.Error("エラーのときに値を返しました")
	}
}
