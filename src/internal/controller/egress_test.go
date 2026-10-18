package controller

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/egress"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/policy"
)

type fakeEgress struct {
	mu   sync.Mutex
	last egress.Membership
	n    int
}

func (f *fakeEgress) SetMembership(_ context.Context, m egress.Membership) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last, f.n = m, f.n+1
	return nil
}

func (f *fakeEgress) get() egress.Membership {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}

func groupPolicy() *policy.Policy {
	p := testPolicy(policy.ResponseEnforce, false)
	p.Groups = append(p.Groups, policy.Group{Name: "strict", Egress: policy.Egress{Default: policy.EgressDeny}, Isolation: policy.IsolateFull})
	return p
}

// startEgress は外部通信の制御（偽物）と GW の LAN（偽物）をつないで CONTROLLER を起動する。
func startEgress(t *testing.T) (*fixture, *fakeEgress) {
	t.Helper()
	eg := &fakeEgress{}
	f := &fixture{t: t, env: pkitest.New(t), dir: t.TempDir(), enf: &fakeEnforcer{}, lan: &fakeLAN{}, clock: &clock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}}
	ctrl, err := New(Config{
		Dir: f.dir, CA: f.env.CA.Pool(), Cert: f.env.Leaf(t, pki.RoleController, "main"), Signer: f.env.Signer,
		Policy: groupPolicy(), Enforcer: f.enf, LAN: f.lan, Egress: eg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: f.clock.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.ctrl = ctrl
	f.serve()
	return f, eg
}

func TestGroupAssignmentPushesMembership(t *testing.T) {
	f, eg := startEgress(t)
	admin := f.peer(pki.RoleAdmin, "admin")
	f.ctrl.ObserveLease(macPC.String(), loopback, "pc", f.clock.now().Add(time.Hour), false)
	f.ctrl.ObserveLease(macBad.String(), netip.MustParseAddr("127.0.0.7"), "tv", f.clock.now().Add(time.Hour), false)
	f.peer(pki.RoleClient, "pc-001").heartbeat()

	// 端末のグループを変えると、結び付いた機器の MAC アドレスとアドレスがそのグループになる。
	status, body := admin.do(http.MethodPost, api.PathDevices+"/pc-001/group", api.GroupRequest{Group: "strict"})
	if status != http.StatusOK {
		t.Fatalf("グループの変更の応答 = %d %s", status, body)
	}
	m := eg.get()
	if m.MACs[macPC.String()] != "strict" || m.IPs[loopback] != "strict" {
		t.Errorf("渡した所属 = %+v", m)
	}
	if h := f.hosts(admin)[macPC.String()]; h.Group != "strict" {
		t.Errorf("機器のグループ = %q", h.Group)
	}

	// CLIENT のない機器もグループに入れられる。端末に結び付いた機器は端末のグループを変える。
	if status, _ := admin.do(http.MethodPost, api.PathHosts+"/"+macBad.String()+"/group", api.GroupRequest{Group: "strict"}); status != http.StatusOK {
		t.Errorf("機器のグループの変更の応答 = %d", status)
	}
	if m := eg.get(); m.MACs[macBad.String()] != "strict" {
		t.Errorf("渡した所属 = %+v", m)
	}
	if status, _ := admin.do(http.MethodPost, api.PathHosts+"/"+macPC.String()+"/group", api.GroupRequest{Group: "strict"}); status != http.StatusConflict {
		t.Errorf("端末に結び付いた機器のグループを直接変えた: %d", status)
	}
	if status, _ := admin.do(http.MethodPost, api.PathDevices+"/pc-001/group", api.GroupRequest{Group: "unknown"}); status != http.StatusBadRequest {
		t.Errorf("ポリシーにないグループにできた: %d", status)
	}

	// 既定のグループに戻すと、所属から外れる。
	admin.do(http.MethodPost, api.PathDevices+"/pc-001/group", api.GroupRequest{Group: "default"})
	if m := eg.get(); m.MACs[macPC.String()] != "" {
		t.Errorf("既定のグループに戻しても所属に残っている: %+v", m)
	}

	// 隔離すると、隔離の状態も渡す。
	f.peer(pki.RoleClient, "pc-001").touchHoneytoken()
	if m := eg.get(); m.Isolated[loopback] != policy.IsolateManagementAndUpdates {
		t.Errorf("隔離の状態 = %+v", m.Isolated)
	}
	actions := auditActions(t, f.dir)
	if !strings.Contains(strings.Join(actions, " "), "device.group:pc-001") || !strings.Contains(strings.Join(actions, " "), "host.group:"+macBad.String()) {
		t.Errorf("監査ログ = %v", actions)
	}
}

func TestLearnedRecords(t *testing.T) {
	f, _ := startEgress(t)
	admin := f.peer(pki.RoleAdmin, "admin")
	for range 3 {
		f.ctrl.RecordLearned("default", "www.example.jp", false)
	}
	f.ctrl.RecordLearned("default", "api.example.jp", false)
	f.ctrl.RecordLearned("strict", "www.example.jp", true)

	status, body := admin.do(http.MethodGet, api.PathLearned, nil)
	if status != http.StatusOK {
		t.Fatalf("応答 = %d", status)
	}
	var list []api.Learned
	json.Unmarshal(body, &list)
	if len(list) != 3 || list[0].Domain != "www.example.jp" || list[0].Count != 3 || list[2].Group != "strict" || !list[2].Blocked {
		t.Errorf("記録 = %+v", list)
	}

	// 停止すると保存し、起動し直すと読み込む。
	f.stop()
	ctrl, err := New(Config{Dir: f.dir, CA: f.env.CA.Pool(), Signer: f.env.Signer, Policy: groupPolicy(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.close()
	if got := ctrl.learnedList(); len(got) != 3 {
		t.Errorf("読み直した記録 = %+v", got)
	}
}

func TestRecordDNS(t *testing.T) {
	f, _ := startEgress(t)
	f.ctrl.ObserveLease(macPC.String(), loopback, "", f.clock.now().Add(time.Hour), false)
	f.peer(pki.RoleClient, "pc-001").heartbeat()
	f.ctrl.RecordDNS(DNSRecord{
		Time: f.clock.now(), Client: loopback, Name: "x.blocked.test", Type: 1, Rcode: 3,
		Action: "block", Reason: "拒否リスト", Group: "default",
	})
	ev := eventsText(t, f.dir)
	for _, want := range []string{`"class_uid":4003`, `"hostname":"x.blocked.test"`, `"type":"A"`, `"rcode_id":3`, `"uid":"pc-001"`, `"reason":"拒否リスト"`} {
		if !strings.Contains(ev, want) {
			t.Errorf("%s が含まれない: %s", want, ev)
		}
	}
}

func TestRecordFlow(t *testing.T) {
	f, _ := startEgress(t)
	f.ctrl.ObserveLease(macPC.String(), loopback, "", f.clock.now().Add(time.Hour), false)
	f.peer(pki.RoleClient, "pc-001").heartbeat()
	src := netip.AddrPortFrom(loopback, 50000)
	dst := netip.MustParseAddrPort("203.0.113.2:443")
	f.ctrl.RecordFlow(FlowRecord{Open: true, Time: f.clock.now(), Proto: 6, Src: src, Dst: dst, SNI: "secure.example.jp", JA4: "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb", TLSVersion: "TLS 1.3", ALPN: "h2"})
	f.ctrl.RecordFlow(FlowRecord{Time: f.clock.now(), Proto: 6, Src: src, Dst: dst, BytesOut: 500, BytesIn: 9000, PacketsOut: 5, PacketsIn: 7,
		Start: f.clock.now().Add(-3 * time.Second), End: f.clock.now(), SNI: "secure.example.jp"})
	f.ctrl.RecordFlow(FlowRecord{Open: true, Time: f.clock.now(), Proto: 6, Src: src, Dst: netip.MustParseAddrPort("203.0.113.2:80"), HTTPMethod: "GET", HTTPHost: "plain.example.jp"})
	ev := eventsText(t, f.dir)
	for _, want := range []string{
		`"type_uid":400101`, `"type_uid":400102`, `"sni":"secure.example.jp"`, `"version":"TLS 1.3"`,
		`"ja4":"t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb"`, `"bytes_in":9000`, `"protocol_name":"tcp"`,
		`"http_method":"GET"`, `"url":{"hostname":"plain.example.jp"}`, `"uid":"pc-001"`, `"start_time":`,
	} {
		if !strings.Contains(ev, want) {
			t.Errorf("%s が含まれない: %s", want, ev)
		}
	}
}
