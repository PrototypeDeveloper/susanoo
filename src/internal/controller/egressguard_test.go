package controller

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/egress"
	"susanoo/internal/event"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/policy"
)

var (
	macStrict = net.HardwareAddr{2, 0, 0, 0, 0, 0x11}
	macLearn  = net.HardwareAddr{2, 0, 0, 0, 0, 0x12}
	ipStrict  = netip.MustParseAddr("127.0.0.11")
	ipLearn   = netip.MustParseAddr("127.0.0.12")
)

// startGuard は、許可リストの strict と学習モードの default のグループで CONTROLLER を起動し、機器を 2 台載せる。
func startGuard(t *testing.T) (*fixture, *peer) {
	t.Helper()
	p := testPolicy(policy.ResponseEnforce, false)
	p.Groups[0].Egress = policy.Egress{Default: policy.EgressLearn}
	p.Groups = append(p.Groups, policy.Group{Name: "strict", Isolation: policy.IsolateFull, Egress: policy.Egress{Default: policy.EgressDeny, Allow: []policy.Destination{
		{Domain: "allowed.test"}, {Domain: "*.cdn.test"}, {CIDR: "192.0.2.0/24"},
	}}})
	f := &fixture{t: t, env: pkitest.New(t), dir: t.TempDir(), enf: &fakeEnforcer{}, lan: &fakeLAN{}, clock: &clock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}}
	ctrl, err := New(Config{
		Dir: f.dir, CA: f.env.CA.Pool(), Cert: f.env.Leaf(t, pki.RoleController, "main"), Signer: f.env.Signer,
		Policy: p, Enforcer: f.enf, LAN: f.lan, Egress: &fakeEgress{}, VerifyLearned: true,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: f.clock.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.ctrl = ctrl
	f.serve()
	admin := f.peer(pki.RoleAdmin, "admin")
	f.ctrl.ObserveLease(macStrict.String(), ipStrict, "strict-pc", f.clock.now().Add(time.Hour), false)
	f.ctrl.ObserveLease(macLearn.String(), ipLearn, "learn-pc", f.clock.now().Add(time.Hour), false)
	if status, body := admin.do(http.MethodPost, api.PathHosts+"/"+macStrict.String()+"/group", api.GroupRequest{Group: "strict"}); status != http.StatusOK {
		t.Fatalf("グループの割り当て = %d %s", status, body)
	}
	return f, admin
}

func (f *fixture) open(src netip.Addr, dst string, sni, host string) {
	f.ctrl.RecordFlow(FlowRecord{Open: true, Time: f.clock.now(), Proto: 6, Src: netip.AddrPortFrom(src, 40000), Dst: netip.MustParseAddrPort(dst), SNI: sni, HTTPHost: host})
}

func (f *fixture) closed(src netip.Addr, proto uint8, dst string) {
	f.ctrl.RecordFlow(FlowRecord{Time: f.clock.now(), Proto: proto, Src: netip.AddrPortFrom(src, 40000), Dst: netip.MustParseAddrPort(dst), BytesOut: 100})
}

// 許可リストのグループの機器が、許可していない名前（SNI か Host）に接続したら検知結果にする。許可した名前、CIDR で許可した
// アドレス、学習モードのグループは検知しない。
func TestUnlistedSNI(t *testing.T) {
	f, admin := startGuard(t)
	f.open(ipStrict, "198.51.100.9:443", "Img.CDN.test.", "")    // 許可した名前（大文字と末尾の「.」は区別しない）
	f.open(ipStrict, "198.51.100.9:80", "", "allowed.test:8080") // HTTP の Host のポートは除く
	f.open(ipStrict, "192.0.2.9:443", "evil.test", "")           // CIDR で許可したアドレス
	f.open(ipStrict, "198.51.100.9:80", "", "198.51.100.9")      // アドレスを書いた Host
	f.open(ipLearn, "198.51.100.9:443", "evil.test", "")         // 学習モードのグループ
	if n := len(f.findingsOf(admin, event.FindingTypeUnlistedSNI)); n != 0 {
		t.Fatalf("許可した接続を %d 件検知しました", n)
	}
	f.open(ipStrict, "198.51.100.9:443", "evil.test", "")
	f.open(ipStrict, "198.51.100.9:443", "evil.test", "") // 続けては検知しない
	f.open(ipStrict, "198.51.100.9:80", "", "other.test")
	found := f.findingsOf(admin, event.FindingTypeUnlistedSNI)
	if len(found) != 2 {
		t.Fatalf("許可していない名前への接続の検知結果 = %d 件", len(found))
	}
	var names []string
	for _, e := range found {
		names = append(names, e.DstEndpoint.Hostname)
		if e.Device.MAC != macStrict.String() || e.DstEndpoint.IP != "198.51.100.9" {
			t.Errorf("検知結果 = %+v %+v", e.Device, e.DstEndpoint)
		}
	}
	if slices.Sort(names); !slices.Equal(names, []string{"evil.test", "other.test"}) {
		t.Errorf("名前 = %v", names)
	}
	if h := f.hosts(admin)[macStrict.String()]; h.Isolation != "" {
		t.Errorf("試験運用のルールで隔離しました: %+v", h)
	}
}

// 学習モードのグループで、DNS で引いていないアドレスへの通信を学習の記録に載せ、許可リストの案に CIDR として入れる。
func TestLearnDirectAddresses(t *testing.T) {
	f, admin := startGuard(t)
	f.ctrl.RecordDNS(DNSRecord{Time: f.clock.now(), Client: ipLearn, Name: "www.cdn.test", Type: 1, Answers: []string{"cname.cdn.test", "198.51.100.20"}, Action: "forward", Group: "default"})
	f.closed(ipLearn, 6, "198.51.100.20:443") // DNS で引いたアドレス
	f.closed(ipLearn, 6, "203.0.113.7:8443")
	f.closed(ipLearn, 6, "203.0.113.7:8443")
	f.closed(ipLearn, 6, "203.0.113.7:22")
	f.closed(ipLearn, 17, "203.0.113.8:123")
	f.closed(ipLearn, 1, "203.0.113.9:0")      // ICMP は載せない
	f.closed(ipStrict, 6, "203.0.113.10:8443") // 許可リストのグループは載せない
	f.ctrl.saveLearned(true)
	_, body := admin.do(http.MethodGet, api.PathLearned, nil)
	var list []api.Learned
	json.Unmarshal(body, &list)
	got := map[string]int{}
	for _, l := range list {
		if l.Address != "" {
			got[learnedLabel(l)+"@"+l.Group] = l.Count
		}
	}
	want := map[string]int{"203.0.113.7:8443/tcp@default": 2, "203.0.113.7:22/tcp@default": 1, "203.0.113.8:123/udp@default": 1}
	if len(got) != len(want) {
		t.Fatalf("直接指定したアドレスの記録 = %v", got)
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%s の回数 = %d（%d のはず）", k, got[k], n)
		}
	}
	_, body = admin.do(http.MethodGet, api.PathLearnedSuggest+"?group=default&min=1", nil)
	var sug api.AllowSuggestion
	json.Unmarshal(body, &sug)
	var cidrs []string
	for _, a := range sug.Allow {
		if a.CIDR != "" {
			cidrs = append(cidrs, a.CIDR+" "+a.Protocol+" "+joinPorts(a.Ports))
		}
	}
	slices.Sort(cidrs)
	if !slices.Equal(cidrs, []string{"203.0.113.7/32 tcp 22,8443", "203.0.113.8/32 udp 123"}) {
		t.Errorf("許可リストの案のアドレス = %v", cidrs)
	}
	// 記録を読み直しても残る。
	entries, err := loadLearned(f.ctrl.learnedPath())
	if err != nil || len(entries) < 3 {
		t.Errorf("保存した記録 = %d 件, %v", len(entries), err)
	}
}

// joinPorts はポートの並びを「,」でつなぐ。
func joinPorts(ns []int) string {
	s := make([]string, len(ns))
	for i, n := range ns {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ",")
}

// 執行部が断ったアドレスは検知結果にし、加えたアドレスは DNS の応答の記録と突き合わせる。LAN の外のアドレスを LAN の機器として
// 知らせたら食い違いとする。
func TestLearnReportsAndMismatch(t *testing.T) {
	f, admin := startGuard(t)
	f.ctrl.ObserveLearn(egress.LearnReport{Group: "strict", Added: []netip.Addr{netip.MustParseAddr("198.51.100.30")},
		Refused: []egress.RefusedAddr{{Addr: netip.MustParseAddr("192.168.77.1"), Reason: egress.RefusePrivate}}})
	found := f.findingsOf(admin, event.FindingTypeLearnAnomaly)
	if len(found) != 1 || !strings.Contains(found[0].Message, "192.168.77.1") {
		t.Fatalf("許可への異常な追加の検知結果 = %+v", found)
	}
	// 待ちの間は突き合わせない。DNS の応答の記録にあるアドレスは食い違わない。
	f.ctrl.RecordDNS(DNSRecord{Time: f.clock.now(), Client: ipStrict, Name: "a.cdn.test", Type: 1, Answers: []string{"198.51.100.31"}, Action: "forward", Group: "strict"})
	f.ctrl.ObserveLearn(egress.LearnReport{Group: "strict", Added: []netip.Addr{netip.MustParseAddr("198.51.100.31")}})
	f.ctrl.checkLearnReports()
	if n := len(f.findingsOf(admin, event.FindingTypeObservationMismatch)); n != 0 {
		t.Fatalf("待ちの間に突き合わせました（%d 件）", n)
	}
	f.clock.advance(learnCheckDelay)
	f.ctrl.checkLearnReports()
	found = f.findingsOf(admin, event.FindingTypeObservationMismatch)
	if len(found) != 1 || !strings.Contains(found[0].Message, "198.51.100.30") || strings.Contains(found[0].Message, "198.51.100.31") {
		t.Fatalf("食い違いの検知結果 = %+v", found)
	}
	// LAN の外のアドレスの貸し出しは台帳に載せず、食い違いとする。
	f.ctrl.ObserveLease("02:00:00:00:00:77", netip.MustParseAddr("192.168.5.5"), "x", f.clock.now().Add(time.Hour), false)
	if _, ok := f.hosts(admin)["02:00:00:00:00:77"]; ok {
		t.Error("LAN の外のアドレスの貸し出しを台帳に載せました")
	}
	f.ctrl.RecordDNS(DNSRecord{Time: f.clock.now(), Client: netip.MustParseAddr("10.9.9.9"), Name: "x.test", Type: 1, Action: "forward", Group: "default"})
	f.ctrl.RecordDNS(DNSRecord{Time: f.clock.now(), Client: netip.MustParseAddr("10.9.9.8"), Name: "x.test", Type: 1, Action: "forward", Group: "default"}) // 同じ種類は続けない
	text := eventsText(t, f.dir)
	if n := strings.Count(text, `"observation_mismatch"`); n != 3 || !strings.Contains(text, `"kind":"lease"`) || !strings.Contains(text, `"kind":"dns"`) {
		t.Errorf("食い違いの検知結果 = %d 件", n)
	}
	// 突き合わせをしない設定（DNS の問い合わせを記録しない）では、待ちに入れない。
	f.ctrl.cfg.VerifyLearned = false
	f.ctrl.ObserveLearn(egress.LearnReport{Group: "strict", Added: []netip.Addr{netip.MustParseAddr("198.51.100.40")}})
	if len(f.ctrl.egw.pending) != 0 {
		t.Error("突き合わせない設定で待ちに入れました")
	}
}
