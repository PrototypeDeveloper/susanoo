package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"susanoo/internal/keys"
	"susanoo/internal/sign"
)

const minimal = `{
  "version": 1,
  "name": "試験",
  "issued_at": "2026-10-18T00:00:00Z",
  "response": "enforce",
  "on_failure": "fail_closed",
  "groups": [{"name": "default", "egress": {"default": "deny"}, "isolation": "full"}]
}`

func TestParseExample(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "policy.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(data)
	if err != nil {
		t.Fatalf("config/policy.example.json が検証に通らない: %v", err)
	}
	if g := p.Group("server"); g == nil || !g.RequireApproval || g.Egress.Default != EgressDeny {
		t.Errorf("server グループの内容が違う: %+v", g)
	}
}

func TestParseMinimal(t *testing.T) {
	p, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 1 || p.Response != ResponseEnforce || p.OnFailure != FailClosed {
		t.Errorf("内容が違う: %+v", p)
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name string
		edit func(string) string
		want string
	}{
		{"知らない項目", func(s string) string { return strings.Replace(s, `"version"`, `"versoin": 1, "version"`, 1) }, "unknown field"},
		{"余分なデータ", func(s string) string { return s + `{}` }, "余分なデータ"},
		{"版数が 0", func(s string) string { return strings.Replace(s, `"version": 1`, `"version": 0`, 1) }, "version"},
		{"発行日時なし", func(s string) string {
			return strings.Replace(s, `"issued_at": "2026-10-18T00:00:00Z",`, ``, 1)
		}, "issued_at"},
		{"不明な対応段階", func(s string) string { return strings.Replace(s, `"enforce"`, `"block"`, 1) }, "response"},
		{"不明な障害時の動作", func(s string) string { return strings.Replace(s, `"fail_closed"`, `"closed"`, 1) }, "on_failure"},
		{"default グループなし", func(s string) string { return strings.Replace(s, `"name": "default"`, `"name": "pc"`, 1) }, `"default" が必要`},
		{"グループ名の重複", func(s string) string {
			return strings.Replace(s, `"groups": [`, `"groups": [{"name": "default", "egress": {"default": "deny"}, "isolation": "full"},`, 1)
		}, "重複"},
		{"不明な既定の扱い", func(s string) string { return strings.Replace(s, `"default": "deny"`, `"default": "block"`, 1) }, "egress.default"},
		{"不明な隔離の段階", func(s string) string { return strings.Replace(s, `"isolation": "full"`, `"isolation": "all"`, 1) }, "isolation"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.edit(minimal)))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("エラー = %v, %q を含むはず", err, tt.want)
			}
		})
	}
}

func TestDestination(t *testing.T) {
	tests := []struct {
		d  Destination
		ok bool
	}{
		{Destination{Domain: "example.jp"}, true},
		{Destination{Domain: "*.example.jp"}, true},
		{Destination{Domain: "xn--eckwd4c7c.xn--zckzah"}, true},
		{Destination{Domain: "a-b.example.jp", Ports: []uint16{443}, Protocol: "tcp"}, true},
		{Destination{CIDR: "192.0.2.0/24"}, true},
		{Destination{CIDR: "2001:db8::/32", Protocol: "udp"}, true},
		{Destination{}, false},
		{Destination{Domain: "example.jp", CIDR: "192.0.2.0/24"}, false},
		{Destination{Domain: "Example.jp"}, false},
		{Destination{Domain: "例え.jp"}, false},
		{Destination{Domain: "a.*.example.jp"}, false},
		{Destination{Domain: "localhost"}, false},
		{Destination{Domain: "-a.example.jp"}, false},
		{Destination{Domain: "a..example.jp"}, false},
		{Destination{Domain: "example.jp."}, false},
		{Destination{Domain: strings.Repeat("a", 64) + ".jp"}, false},
		{Destination{CIDR: "192.0.2.1/24"}, false},
		{Destination{CIDR: "192.0.2.0"}, false},
		{Destination{CIDR: "192.0.2.0/24", Ports: []uint16{0}}, false},
		{Destination{CIDR: "192.0.2.0/24", Protocol: "icmp"}, false},
	}
	for _, tt := range tests {
		err := tt.d.validate()
		if (err == nil) != tt.ok {
			t.Errorf("%+v: エラー = %v, 正しいはず = %v", tt.d, err, tt.ok)
		}
	}
}

func TestValidateReportsAllErrors(t *testing.T) {
	p := &Policy{Groups: []Group{{Name: "default", Egress: Egress{Default: EgressDeny}, Isolation: IsolateFull}}}
	err := p.Validate()
	if err == nil {
		t.Fatal("空のポリシーが検証に通った")
	}
	for _, want := range []string{"version", "issued_at", "response", "on_failure"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("エラーに %q が含まれない: %v", want, err)
		}
	}
}

func TestParseSigned(t *testing.T) {
	priv, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	s, err := sign.NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	v, err := sign.NewVerifier(s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseSigned(v, s.Sign(sign.PurposePolicy, []byte(minimal))); err != nil {
		t.Errorf("署名付きのポリシーを読めない: %v", err)
	}
	if _, err := ParseSigned(v, s.Sign(sign.PurposeCommand, []byte(minimal))); err == nil {
		t.Error("用途が違う署名のポリシーを受け付けた")
	}
	env := s.Sign(sign.PurposePolicy, []byte(minimal))
	env.Payload = []byte(strings.Replace(minimal, `"enforce"`, `"monitor"`, 1))
	if _, err := ParseSigned(v, env); err == nil {
		t.Error("改ざんされたポリシーを受け付けた")
	}
}

func TestCheckUpgrade(t *testing.T) {
	v1, v2 := &Policy{Version: 1}, &Policy{Version: 2}
	if err := CheckUpgrade(nil, v1); err != nil {
		t.Errorf("初回の適用が拒否された: %v", err)
	}
	if err := CheckUpgrade(v1, v2); err != nil {
		t.Errorf("新しい版が拒否された: %v", err)
	}
	if err := CheckUpgrade(v2, v1); err == nil {
		t.Error("古い版で上書きできた")
	}
	if err := CheckUpgrade(v2, v2); err == nil {
		t.Error("同じ版で上書きできた")
	}
}

func TestGroup(t *testing.T) {
	p := &Policy{Groups: []Group{{Name: "server"}, {Name: DefaultGroup}}}
	if g := p.Group("server"); g == nil || g.Name != "server" {
		t.Errorf("server グループ = %+v", g)
	}
	if g := p.Group("unknown"); g == nil || g.Name != DefaultGroup {
		t.Errorf("見つからないグループで default を返さない: %+v", g)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(minimal))
	if data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "policy.example.json")); err == nil {
		f.Add(data)
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"groups":[{"egress":{"allow":[{"domain":"*."}]}}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err != nil {
			return
		}
		// 検証に通ったポリシーは、書き出して読み直しても検証に通るはず。
		out, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(out); err != nil {
			t.Fatalf("書き出したポリシーを読み直せない: %v\n%s", err, out)
		}
	})
}

func TestMatchDomain(t *testing.T) {
	tests := []struct {
		rule, name string
		want       bool
	}{
		{"example.jp", "example.jp", true},
		{"example.jp", "www.example.jp", false},
		{"*.example.jp", "www.example.jp", true},
		{"*.example.jp", "a.b.example.jp", true},
		{"*.example.jp", "example.jp", false},
		{"*.example.jp", "badexample.jp", false},
		{"*.example.jp", "www.example.jp.evil.com", false},
	}
	for _, tt := range tests {
		if got := (Destination{Domain: tt.rule}).MatchDomain(tt.name); got != tt.want {
			t.Errorf("%s と %s: %v, 期待値 %v", tt.rule, tt.name, got, tt.want)
		}
	}
	if (Destination{CIDR: "192.0.2.0/24"}).MatchDomain("example.jp") {
		t.Error("CIDR の宛先がドメインに一致した")
	}
}

func TestBypassDefaultsToBlock(t *testing.T) {
	p, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if b := p.Group(DefaultGroup).Bypass; b.AllowQUIC || b.AllowDoH || b.AllowVPN || b.AllowECH {
		t.Errorf("省略した抜け道の設定 = %+v", b)
	}
	withBypass := strings.Replace(minimal, `"isolation": "full"`, `"isolation": "full", "bypass": {"allow_vpn": true}`, 1)
	if p, err := Parse([]byte(withBypass)); err != nil || !p.Group(DefaultGroup).Bypass.AllowVPN {
		t.Errorf("抜け道の設定を読めない: %v", err)
	}
}
