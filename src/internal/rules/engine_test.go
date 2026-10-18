package rules

import (
	"math"
	"testing"
	"time"

	"susanoo/internal/event"
)

var now = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func finding(typ string) *event.Event {
	e := event.New(event.ClassDetectionFinding, event.FindingCreate, event.SeverityHigh, now)
	e.FindingInfo = &event.FindingInfo{UID: "x", Title: typ, Types: []string{typ}}
	return e
}

func dnsQuery(name string) *event.Event {
	e := event.New(event.ClassDNSActivity, event.DNSActivityResponse, event.SeverityInformational, now)
	e.Query = &event.DNSQuery{Hostname: name, Type: "A"}
	return e
}

func ids(hits []Hit) []string {
	var out []string
	for _, h := range hits {
		s := h.Rule.ID
		if h.Excepted != nil {
			s += "(例外)"
		}
		out = append(out, s)
	}
	return out
}

func TestEngineDefaults(t *testing.T) {
	e := NewEngine(nil)
	var c Counter
	if e.Version() != 0 || e.HalfLife != DefaultHalfLife {
		t.Errorf("既定 = %d %s", e.Version(), e.HalfLife)
	}
	for typ, want := range map[string]string{
		event.FindingTypeHoneytoken: "honeytoken", event.FindingTypeMassChange: "mass-change", event.FindingTypeHeartbeatLost: "heartbeat-lost",
		event.FindingTypeGatewaySpoofing: "gateway-spoofing", event.FindingTypeIPSpoofing: "ip-spoofing", event.FindingTypeTamper: "tamper",
	} {
		hits := e.Evaluate(finding(typ), Subject{Key: "device:pc-001", Group: "default"}, &c, now)
		if len(hits) != 1 || hits[0].Rule.ID != want {
			t.Errorf("%s = %v", typ, ids(hits))
		}
	}
	if e.Relevant(dnsQuery("a.test")) || e.Relevant(finding(event.FindingTypeNewDevice)) {
		t.Error("既定のルールが DNS や新しい機器に当てはまる")
	}
}

func TestEngineEvaluate(t *testing.T) {
	s, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(s)
	var c Counter
	pc := Subject{Key: "device:pc-001", Group: "default", IDs: []string{"pc-001", "192.168.10.23"}}
	if e.Version() != 3 || e.HalfLife != 12*time.Hour {
		t.Errorf("版 = %d %s", e.Version(), e.HalfLife)
	}
	if hits := e.Evaluate(finding(event.FindingTypeHoneytoken), pc, &c, now); len(hits) != 1 || hits[0].Rule.Mode != ModeMonitor {
		t.Errorf("置き換えた既定のルール = %v", ids(hits))
	}
	if hits := e.Evaluate(dnsQuery("x.bad.test"), pc, &c, now); len(hits) != 1 || hits[0].Rule.ID != "dns-bad" || hits[0].Excepted != nil {
		t.Errorf("DNS = %v", ids(hits))
	}
	if hits := e.Evaluate(dnsQuery("good.test"), pc, &c, now); len(hits) != 0 {
		t.Errorf("当てはまらない名前 = %v", ids(hits))
	}
	// 端末の例外（大文字と小文字は区別しない）。
	pc9 := Subject{Key: "device:pc-009", Group: "default", IDs: []string{"PC-009"}}
	if hits := e.Evaluate(dnsQuery("x.bad.test"), pc9, &c, now); len(hits) != 1 || hits[0].Excepted == nil || hits[0].Excepted.Reason != "検証用の端末" {
		t.Errorf("端末の例外 = %v", ids(hits))
	}
	// グループの例外は期限まで。
	lab := Subject{Key: "device:pc-100", Group: "lab"}
	if hits := e.Evaluate(dnsQuery("x.bad.test"), lab, &c, now); len(hits) != 1 || hits[0].Excepted == nil {
		t.Errorf("期限内のグループの例外 = %v", ids(hits))
	}
	if hits := e.Evaluate(dnsQuery("x.bad.test"), lab, &c, now.Add(48*time.Hour)); len(hits) != 1 || hits[0].Excepted != nil {
		t.Errorf("期限後のグループの例外 = %v", ids(hits))
	}

	// 条件の組み合わせ（not in）。
	proc := sampleEvent()
	if hits := e.Evaluate(proc, pc, &c, now); len(hits) != 1 || hits[0].Rule.ID != "curl-pipe" {
		t.Errorf("プロセス = %v", ids(hits))
	}
	proc.Process.User.Name = "builder"
	if hits := e.Evaluate(proc, pc, &c, now); len(hits) != 0 {
		t.Errorf("除外した利用者 = %v", ids(hits))
	}

	// しきい値とグループの指定：server グループで、1 分に 3 回目で当てはまり、数え直す。
	srv := Subject{Key: "device:srv-1", Group: "server"}
	var got []int
	for i := range 7 {
		for _, h := range e.Evaluate(dnsQuery("a.test"), srv, &c, now.Add(time.Duration(i)*time.Second)) {
			if h.Rule.ID == "many-dns" {
				got = append(got, i)
			}
		}
	}
	if len(got) != 2 || got[0] != 2 || got[1] != 5 {
		t.Errorf("しきい値に届いた回 = %v", got)
	}
	for i := range 5 {
		if hits := e.Evaluate(dnsQuery("a.test"), pc, &c, now.Add(time.Duration(i)*time.Second)); len(hits) != 0 {
			t.Errorf("ほかのグループに当てはまった: %v", ids(hits))
		}
	}
}

func TestEngineOff(t *testing.T) {
	s, err := Parse([]byte(`{"version": 1, "issued_at": "2026-10-18T00:00:00Z", "rules": [{"id": "honeytoken", "name": "x", "finding": "honeytoken", "mode": "off"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if hits := NewEngine(s).Evaluate(finding(event.FindingTypeHoneytoken), Subject{}, &Counter{}, now); len(hits) != 0 {
		t.Errorf("止めたルール = %v", ids(hits))
	}
}

func TestCounter(t *testing.T) {
	var c Counter
	add := func(at time.Duration) bool { return c.Add("k", 3, time.Minute, now.Add(at)) }
	// 区間を過ぎた回数は数えない。
	if add(0) || add(30*time.Second) || add(3*time.Minute) || add(3*time.Minute+time.Second) {
		t.Error("区間を過ぎた回数を数えた")
	}
	if !add(3*time.Minute + 2*time.Second) {
		t.Error("区間内の 3 回目で届かない")
	}
	// 1 つ前の区間の回数は、経った割合で減らして数える。
	c = Counter{}
	add(0)
	add(50 * time.Second)
	if add(65 * time.Second) {
		t.Error("前の区間の終わりの 2 回と合わせて届いた（前の区間はほとんど過ぎている）")
	}
	// 上限を超える単位は捨てる。
	c = Counter{}
	for i := range maxCounterKeys + 10 {
		c.Add(string(rune(i)), 5, time.Minute, now)
	}
	if len(c.m) > maxCounterKeys {
		t.Errorf("単位の数 = %d", len(c.m))
	}
}

func TestDecay(t *testing.T) {
	if got := Decay(100, 24*time.Hour, 24*time.Hour); math.Abs(got-50) > 1e-9 {
		t.Errorf("半減期の後 = %v", got)
	}
	if got := Decay(100, 72*time.Hour, 24*time.Hour); math.Abs(got-12.5) > 1e-9 {
		t.Errorf("3 倍の後 = %v", got)
	}
	if Decay(100, -time.Hour, time.Hour) != 100 || Decay(100, time.Hour, 0) != 100 {
		t.Error("時刻が戻ったときや半減期が 0 のとき")
	}
}
