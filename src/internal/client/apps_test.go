package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"susanoo/internal/api"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/platform"
	"susanoo/internal/platform/platformtest"
	"susanoo/internal/policy"
	"susanoo/internal/sign"
)

var capsApps = platform.Capabilities{OS: "linux", Features: []platform.Capability{platform.CapIsolation, platform.CapAppControl}}

func apps(mode policy.AppMode) *policy.AppControl {
	return &policy.AppControl{Mode: mode, Default: policy.AppAllow, Rules: []policy.AppRule{
		{Name: "AI エージェントのほか", Agents: []string{"*"}, Action: policy.AppDeny},
	}}
}

// 指示に入ったプロセス単位の通信の制御を Platform に渡す。変わらなければ渡し直さない。再起動しても続ける（C7）。
func TestApplyAppControl(t *testing.T) {
	env := pkitest.New(t)
	ctrl := netip.MustParseAddrPort("10.77.0.1:8443")
	fake := platformtest.New(capsApps)
	stateDir := t.TempDir()
	l := newLocal(t, env, ctrl, stateDir, fake)
	ctx := context.Background()
	apply := func(v uint64, iso policy.IsolationLevel, ac *policy.AppControl) error {
		return l.Apply(ctx, command(t, env.Signer, sign.PurposeCommand, api.Command{DeviceID: "pc-001", Version: v, Isolation: iso, Apps: ac}))
	}
	if err := apply(1, "", apps(policy.AppMonitor)); err != nil {
		t.Fatal(err)
	}
	got, exempt := fake.Apps()
	if got == nil || got.Mode != policy.AppMonitor || !slices.Equal(exempt, []netip.Addr{ctrl.Addr()}) {
		t.Fatalf("渡した制御 = %+v（制御しない宛先 %v）", got, exempt)
	}
	// 隔離だけが変わる指示では、制御を渡し直さない。
	if err := apply(2, policy.IsolateManagement, apps(policy.AppMonitor)); err != nil {
		t.Fatal(err)
	}
	if n := countPrefix(fake.History(), "apps:"); n != 1 {
		t.Errorf("制御を %d 回渡した（%v）", n, fake.History())
	}
	// ハートビートで、効いている制御の扱いを知らせる。
	env2, _ := l.Heartbeat(ctx)
	var hb api.Heartbeat
	json.Unmarshal(env2.Payload, &hb)
	if hb.AppControl != policy.AppMonitor {
		t.Errorf("ハートビートの制御 = %q", hb.AppControl)
	}
	// 渡せなければ、何も変えずにエラーを返す（次の応答で試し直す）。
	fake.AppsErr = errors.New("キューに結び付けません")
	if err := apply(3, "", apps(policy.AppEnforce)); err == nil {
		t.Fatal("渡せないのにエラーを返さない")
	}
	if l.state.Version != 2 || l.state.Isolation != policy.IsolateManagement {
		t.Errorf("失敗した後の状態 = %+v", l.state)
	}
	fake.AppsErr = nil
	if err := apply(3, "", apps(policy.AppEnforce)); err != nil {
		t.Fatal(err)
	}
	// 再起動しても、前回の制御を続ける。
	fake2 := platformtest.New(capsApps)
	l2 := newLocal(t, env, ctrl, stateDir, fake2)
	l2.Restore(ctx)
	if got, _ := fake2.Apps(); got == nil || got.Mode != policy.AppEnforce {
		t.Errorf("再起動後の制御 = %+v", got)
	}
	// 制御がなくなる指示で、やめる。
	if err := l2.Apply(ctx, command(t, env.Signer, sign.PurposeCommand, api.Command{DeviceID: "pc-001", Version: 4})); err != nil {
		t.Fatal(err)
	}
	if got, _ := fake2.Apps(); got != nil {
		t.Errorf("やめた後の制御 = %+v", got)
	}
}

// 制御を使えない端末では、指示を受け付けて、制御は渡さない。
func TestApplyAppControlUnsupported(t *testing.T) {
	env := pkitest.New(t)
	fake := platformtest.New(caps) // app_control なし
	l := newLocal(t, env, netip.MustParseAddrPort("10.77.0.1:8443"), t.TempDir(), fake)
	ctx := context.Background()
	if err := l.Apply(ctx, command(t, env.Signer, sign.PurposeCommand, api.Command{DeviceID: "pc-001", Version: 1, Apps: apps(policy.AppEnforce)})); err != nil {
		t.Fatal(err)
	}
	if got, _ := fake.Apps(); got != nil || l.appControlMode() != "" {
		t.Errorf("使えない端末に渡した: %+v", got)
	}
}

func countPrefix(list []string, prefix string) int {
	n := 0
	for _, x := range list {
		if len(x) >= len(prefix) && x[:len(prefix)] == prefix {
			n++
		}
	}
	return n
}
