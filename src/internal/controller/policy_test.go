package controller

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/keys"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/policy"
	"susanoo/internal/sign"
)

// storeManager は GW の執行部の代わりに、ポリシーの保存先で署名と版数を確かめる。
type storeManager struct{ st *policy.Store }

func (m storeManager) state() (PolicyState, error) {
	cur, can := m.st.Policies()
	var st PolicyState
	var err error
	if st.Current, err = json.Marshal(cur); err != nil {
		return st, err
	}
	if can != nil {
		st.Canary, err = json.Marshal(can)
	}
	return st, err
}

func (m storeManager) ApplyPolicy(_ context.Context, env sign.Envelope, canary bool) (PolicyState, error) {
	if _, err := m.st.Apply(env, canary); err != nil {
		return PolicyState{}, err
	}
	return m.state()
}

func (m storeManager) PromotePolicy(context.Context) (PolicyState, error) {
	if err := m.st.Promote(); err != nil {
		return PolicyState{}, err
	}
	return m.state()
}

func (m storeManager) AbortPolicy(context.Context) (PolicyState, error) {
	if err := m.st.Abort(); err != nil {
		return PolicyState{}, err
	}
	return m.state()
}

func newPolicySigner(t *testing.T) *sign.Signer {
	t.Helper()
	priv, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	s, err := sign.NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func signPolicy(t *testing.T, s *sign.Signer, p *policy.Policy) sign.Envelope {
	t.Helper()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return s.Sign(sign.PurposePolicy, data)
}

// startPolicy は、ポリシーの配布の仕組み（保存先を使う偽物）と外部通信の制御（偽物）をつないで CONTROLLER を起動する。
func startPolicy(t *testing.T, signer *sign.Signer) (*fixture, *fakeEgress) {
	t.Helper()
	st, err := policy.OpenStore(t.TempDir(), signer.PublicKey(), groupPolicy())
	if err != nil {
		t.Fatal(err)
	}
	eg := &fakeEgress{}
	f := &fixture{t: t, env: pkitest.New(t), dir: t.TempDir(), enf: &fakeEnforcer{}, lan: &fakeLAN{}, clock: &clock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}}
	ctrl, err := New(Config{
		Dir: f.dir, CA: f.env.CA.Pool(), Cert: f.env.Leaf(t, pki.RoleController, "main"), Signer: f.env.Signer,
		Policy: groupPolicy(), Enforcer: f.enf, LAN: f.lan, Egress: eg, Policies: storeManager{st},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: f.clock.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.ctrl = ctrl
	f.serve()
	return f, eg
}

// policyVersion は、版数 v で、default グループを全遮断の隔離と原則拒否にしたポリシーを返す。
func policyVersion(v int) *policy.Policy {
	p := groupPolicy()
	p.Version, p.IssuedAt = v, time.Now()
	p.Groups[0].Isolation = policy.IsolateFull
	p.Groups[0].Egress.Default = policy.EgressDeny
	return p
}

// 先行適用では、指定した端末だけが新しい版のグループに入り、隔離の段階なども新しい版に従う。
// 全体に広げると全員が新しい版になり、取り消すと元に戻る。
func TestPolicyCanary(t *testing.T) {
	signer := newPolicySigner(t)
	f, eg := startPolicy(t, signer)
	admin := f.peer(pki.RoleAdmin, "admin")
	f.ctrl.ObserveLease(macPC.String(), loopback, "pc", f.clock.now().Add(time.Hour), false)
	f.ctrl.ObserveLease(macBad.String(), loopback.Next(), "tv", f.clock.now().Add(time.Hour), false)
	f.peer(pki.RoleClient, "pc-001").heartbeat()

	push := func(p *policy.Policy, devices, groups []string) (int, api.PolicyInfo) {
		t.Helper()
		status, body := admin.do(http.MethodPost, api.PathPolicy, api.PolicyPush{Envelope: signPolicy(t, signer, p), CanaryDevices: devices, CanaryGroups: groups})
		var info api.PolicyInfo
		json.Unmarshal(body, &info)
		return status, info
	}
	isolateLevel := func(path string) policy.IsolationLevel {
		t.Helper()
		status, body := admin.do(http.MethodPost, path+"/isolate", api.IsolateRequest{})
		if status != http.StatusOK {
			t.Fatalf("%s の隔離 = %d %s", path, status, body)
		}
		var v struct {
			Isolation policy.IsolationLevel `json:"isolation"`
		}
		json.Unmarshal(body, &v)
		admin.do(http.MethodPost, path+"/release", nil)
		return v.Isolation
	}

	status, info := push(policyVersion(2), []string{"pc-001"}, nil)
	if status != http.StatusOK || info.Canary == nil || info.Canary.Version != 2 || info.Current.Version != 1 || !slices.Equal(info.Canary.Devices, []string{"pc-001"}) {
		t.Fatalf("先行適用の応答 = %d %+v", status, info)
	}
	m := eg.get()
	if m.MACs[macPC.String()] != "default"+policy.CanarySuffix || m.IPs[loopback] != "default"+policy.CanarySuffix {
		t.Errorf("先行適用の端末の所属 = %+v", m)
	}
	if _, ok := m.MACs[macBad.String()]; ok {
		t.Errorf("先行適用でない機器を新しい版のグループに入れた: %+v", m)
	}
	if got := isolateLevel(api.PathDevices + "/pc-001"); got != policy.IsolateFull {
		t.Errorf("先行適用の端末の既定の隔離の段階 = %s（新しい版の full のはず）", got)
	}
	if got := isolateLevel(api.PathHosts + "/" + macBad.String()); got != policy.IsolateManagementAndUpdates {
		t.Errorf("ほかの機器の既定の隔離の段階 = %s（今の版のはず）", got)
	}

	// 全体に広げる。
	status, body := admin.do(http.MethodPost, api.PathPolicy+"/promote", nil)
	info = api.PolicyInfo{}
	json.Unmarshal(body, &info)
	if status != http.StatusOK || info.Current.Version != 2 || info.Canary != nil {
		t.Fatalf("全体に広げた応答 = %d %s", status, body)
	}
	if m := eg.get(); len(m.MACs) != 0 {
		t.Errorf("全体に広げた後の所属 = %+v（全員が default）", m)
	}
	if got := isolateLevel(api.PathHosts + "/" + macBad.String()); got != policy.IsolateFull {
		t.Errorf("全体に広げた後の機器の既定の隔離の段階 = %s", got)
	}

	// グループで先行適用して、取り消す。
	if status, _ := push(policyVersion(3), nil, []string{"default"}); status != http.StatusOK {
		t.Fatalf("グループの先行適用の応答 = %d", status)
	}
	if m := eg.get(); m.MACs[macBad.String()] != "default"+policy.CanarySuffix {
		t.Errorf("グループで先行適用した機器の所属 = %+v", m)
	}
	status, body = admin.do(http.MethodPost, api.PathPolicy+"/abort", nil)
	info = api.PolicyInfo{}
	json.Unmarshal(body, &info)
	if status != http.StatusOK || info.Current.Version != 2 || info.Canary != nil {
		t.Fatalf("取り消した応答 = %d %s", status, body)
	}
	if status, _ := admin.do(http.MethodPost, api.PathPolicy+"/abort", nil); status != http.StatusConflict {
		t.Errorf("先行適用がないときの取り消しの応答 = %d", status)
	}

	// 古い版、別の鍵の署名は受け付けない。
	if status, _ := push(policyVersion(3), nil, nil); status != http.StatusBadRequest {
		t.Errorf("取り消した版数の応答 = %d", status)
	}
	if status, _ := push2(t, admin, newPolicySigner(t), policyVersion(9)); status != http.StatusBadRequest {
		t.Errorf("別の鍵の署名の応答 = %d", status)
	}
	if status, _ := push(policyVersion(4), []string{"PC 1"}, nil); status != http.StatusBadRequest {
		t.Errorf("不正な先行適用の端末の応答 = %d", status)
	}

	// 版の一覧と中身。
	status, body = admin.do(http.MethodGet, api.PathPolicy, nil)
	info = api.PolicyInfo{}
	json.Unmarshal(body, &info)
	var versions []int
	for _, v := range info.Versions {
		versions = append(versions, v.Version)
	}
	if status != http.StatusOK || !slices.Equal(versions, []int{1, 2, 3}) {
		t.Errorf("版の一覧 = %d %v", status, versions)
	}
	status, body = admin.do(http.MethodGet, api.PathPolicy+"/versions/2", nil)
	if p, err := policy.Parse(body); status != http.StatusOK || err != nil || p.Version != 2 {
		t.Errorf("版 2 の中身 = %d %v", status, err)
	}
	actions := auditActions(t, f.dir)
	for _, want := range []string{ActionPolicyCanary + ":2", ActionPolicyPromote + ":2", ActionPolicyCanary + ":3", ActionPolicyAbort + ":3"} {
		if !slices.Contains(actions, want) {
			t.Errorf("監査ログに %s がない: %v", want, actions)
		}
	}

	// 先行適用の選択は再起動しても続く（執行部が渡す先行適用の版と版数が合うとき）。
	push(policyVersion(5), []string{"pc-001"}, nil)
	f.stop()
	restart := func(canary *policy.Policy) *Controller {
		t.Helper()
		ctrl, err := New(Config{
			Dir: f.dir, CA: f.env.CA.Pool(), Cert: f.env.Leaf(t, pki.RoleController, "main"), Signer: f.env.Signer,
			Policy: policyVersion(2), Canary: canary, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: f.clock.now,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ctrl.close)
		return ctrl
	}
	if c := restart(policyVersion(5)); !slices.Equal(c.canarySel.Devices, []string{"pc-001"}) {
		t.Errorf("再起動後の先行適用の端末 = %v", c.canarySel.Devices)
	}
	if c := restart(nil); len(c.canarySel.Devices) != 0 {
		t.Errorf("先行適用がないのに選択が残った: %v", c.canarySel.Devices)
	}
}

func push2(t *testing.T, admin *peer, s *sign.Signer, p *policy.Policy) (int, []byte) {
	t.Helper()
	return admin.do(http.MethodPost, api.PathPolicy, api.PolicyPush{Envelope: signPolicy(t, s, p)})
}
