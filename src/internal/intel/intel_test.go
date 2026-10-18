package intel

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"susanoo/internal/keys"
	"susanoo/internal/sign"
)

var now = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

const feedText = `# 例の一覧
! 広告の遮断の形式の注釈
[Adblock Plus 2.0]
evil.example
Login.Phish.EXAMPLE.   # 大文字と末尾の「.」
0.0.0.0 tracker.example ads.example
127.0.0.1 localhost
::1 ip6-localhost
http://malware.example/payload.exe
https://203.0.113.77:8443/c2
||adblock.example^
*.wild.example
203.0.113.5
203.0.113.0/24
198.51.100.9/32
2001:db8:bad::1
2001:db8:bad::/48
not a valid line here
bad_tld.123
-bad.example
`

func TestParseFeed(t *testing.T) {
	f, err := ParseFeed(strings.NewReader(feedText))
	if err != nil {
		t.Fatal(err)
	}
	wantDomains := []string{"adblock.example", "ads.example", "evil.example", "login.phish.example", "malware.example", "tracker.example", "wild.example"}
	if !slices.Equal(f.Domains, wantDomains) {
		t.Errorf("ドメイン = %v", f.Domains)
	}
	wantCIDRs := []string{"198.51.100.9/32", "203.0.113.0/24", "2001:db8:bad::/48"}
	if !slices.Equal(f.CIDRs, wantCIDRs) {
		t.Errorf("アドレスの範囲 = %v", f.CIDRs)
	}
	if f.Skipped != 3 {
		t.Errorf("読み飛ばした行 = %d", f.Skipped)
	}
}

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{
		"Evil.Example.":                      "evil.example",
		"a_b.evil.example":                   "a_b.evil.example",
		"xn--eckwd4c7c.xn--zckzah":           "xn--eckwd4c7c.xn--zckzah",
		"localhost":                          "",
		"203.0.113.5":                        "",
		"a..example":                         "",
		"-a.example":                         "",
		"a.123":                              "",
		"日本.example":                         "",
		strings.Repeat("a", 64) + ".example": "",
	} {
		if got := NormalizeDomain(in); got != want {
			t.Errorf("NormalizeDomain(%q) = %q, 期待値 %q", in, got, want)
		}
	}
}

func testSet() *Set {
	return &Set{Version: 2, IssuedAt: now, Lists: []List{
		{Name: "watch", Action: ActionAlert, Updated: now, Domains: []string{"evil.example", "watch.example"}, CIDRs: []string{"203.0.113.0/24"}},
		{Name: "phishing", Action: ActionBlock, Updated: now, Domains: []string{"evil.example", "phish.example"}, CIDRs: []string{"203.0.113.5/32", "2001:db8:bad::/48"}},
	}}
}

func TestValidate(t *testing.T) {
	if err := testSet().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Set){
		"版数がない":        func(s *Set) { s.Version = 0 },
		"発行時刻がない":      func(s *Set) { s.IssuedAt = time.Time{} },
		"不正な名前":        func(s *Set) { s.Lists[0].Name = "Bad Name" },
		"名前の重複":        func(s *Set) { s.Lists[1].Name = "watch" },
		"不正な扱い":        func(s *Set) { s.Lists[0].Action = "drop" },
		"正規化していないドメイン": func(s *Set) { s.Lists[0].Domains = []string{"Evil.Example"} },
		"不正な範囲":        func(s *Set) { s.Lists[0].CIDRs = []string{"203.0.113.1/24"} },
		"多すぎる一覧": func(s *Set) {
			for i := range MaxLists {
				s.Lists = append(s.Lists, List{Name: fmt.Sprintf("l%d", i), Action: ActionAlert})
			}
		},
	} {
		s := testSet()
		mod(s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s を受け付けた", name)
		}
	}
	if _, err := Parse([]byte(`{"version": 1, "issued_at": "2026-10-19T00:00:00Z", "lists": [], "extra": 1}`)); err == nil {
		t.Error("知らない項目を受け付けた")
	}
}

func TestMatcher(t *testing.T) {
	m := NewMatcher(testSet())
	// ドメインはその下の名前にも当てはまり、遮断の一覧を先にする。
	if ms := m.Domain("Login.Evil.Example."); len(ms) != 2 || ms[0].List != "phishing" || ms[0].Action != ActionBlock || ms[0].Indicator != "evil.example" {
		t.Errorf("evil.example の下の名前 = %+v", ms)
	}
	for _, name := range []string{"example", "notevil.example", "evil.example.org", ""} {
		if ms := m.Domain(name); len(ms) != 0 {
			t.Errorf("%q が当てはまった: %+v", name, ms)
		}
	}
	// アドレスは最も狭い範囲で当てはめる。
	if ms := m.Addr(netip.MustParseAddr("203.0.113.5")); len(ms) != 1 || ms[0].List != "phishing" || ms[0].Indicator != "203.0.113.5/32" {
		t.Errorf("203.0.113.5 = %+v", ms)
	}
	if ms := m.Addr(netip.MustParseAddr("::ffff:203.0.113.9")); len(ms) != 1 || ms[0].List != "watch" {
		t.Errorf("IPv4 射影の 203.0.113.9 = %+v", ms)
	}
	if ms := m.Addr(netip.MustParseAddr("2001:db8:bad:1::1")); len(ms) != 1 || ms[0].List != "phishing" {
		t.Errorf("IPv6 = %+v", ms)
	}
	if ms := m.Addr(netip.MustParseAddr("198.51.100.1")); len(ms) != 0 {
		t.Errorf("一覧にないアドレス = %+v", ms)
	}
	// 扱いで絞る。
	if ms := NewMatcher(testSet(), ActionBlock).Domain("watch.example"); len(ms) != 0 {
		t.Errorf("遮断の一覧だけの照合で検知だけの一覧に当てはまった: %+v", ms)
	}
	if !NewMatcher(nil).Empty() || m.Empty() {
		t.Error("Empty が違う")
	}
	// 遮断のアドレスと、LAN 側の処理に渡すドメイン。
	if got := testSet().BlockedPrefixes(); len(got) != 2 || got[0].String() != "203.0.113.5/32" {
		t.Errorf("遮断する範囲 = %v", got)
	}
	b := testSet().Blocklist()
	data, _ := json.Marshal(b)
	var b2 Blocklist
	json.Unmarshal(data, &b2)
	bm := b2.Matcher()
	if ms := bm.Domain("a.phish.example"); len(ms) != 1 || ms[0].Action != ActionBlock {
		t.Errorf("渡した一覧の照合 = %+v", ms)
	}
	if ms := bm.Domain("watch.example"); len(ms) != 0 {
		t.Errorf("検知だけの一覧を渡した: %+v", ms)
	}
}

func TestMergePrefixes(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("10.2.3.4/32"),
		netip.MustParsePrefix("192.0.2.0/25"), netip.MustParsePrefix("192.0.2.128/25"), netip.MustParsePrefix("::/0"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	got := MergePrefixes(in)
	want := []string{"10.0.0.0/8", "192.0.2.0/25", "192.0.2.128/25", "::/0"}
	var s []string
	for _, p := range got {
		s = append(s, p.String())
	}
	if !slices.Equal(s, want) {
		t.Errorf("MergePrefixes = %v", s)
	}
}

func newSigner(t *testing.T) *sign.Signer {
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

func signed(t *testing.T, s *sign.Signer, p sign.Purpose, version int) sign.Envelope {
	t.Helper()
	set := testSet()
	set.Version = version
	data, _ := json.Marshal(set)
	return s.Sign(p, data)
}

func TestStore(t *testing.T) {
	signer := newSigner(t)
	dir := t.TempDir()
	st, err := OpenStore(dir, signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if cur, _ := st.Current(); cur != nil {
		t.Fatal("空の保存先に版がある")
	}
	if _, err := st.Check(signed(t, signer, sign.PurposeIntel, 1)); err != nil {
		t.Fatal(err)
	}
	if cur, _ := st.Current(); cur != nil {
		t.Fatal("Check で保存した")
	}
	if _, err := st.Apply(signed(t, signer, sign.PurposeIntel, 3)); err != nil {
		t.Fatal(err)
	}
	for name, env := range map[string]sign.Envelope{
		"古い版":      signed(t, signer, sign.PurposeIntel, 2),
		"検知ルールの署名": signed(t, signer, sign.PurposeRules, 4),
		"ほかの鍵":     signed(t, newSigner(t), sign.PurposeIntel, 4),
	} {
		if _, err := st.Apply(env); err == nil {
			t.Errorf("%s を受け付けた", name)
		}
		if _, err := st.Check(env); err == nil {
			t.Errorf("%s を確かめて通した", name)
		}
	}
	st2, err := OpenStore(dir, signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if cur, payload := st2.Current(); cur == nil || cur.Version != 3 || !strings.Contains(string(payload), `"phishing"`) {
		t.Errorf("開き直した保存先 = %+v", cur)
	}
	// 書き換えた版は開けない。
	path := filepath.Join(dir, currentFile)
	data, _ := os.ReadFile(path)
	var env sign.Envelope
	json.Unmarshal(data, &env)
	env.Payload = []byte(strings.Replace(string(env.Payload), `"block"`, `"alert"`, 1))
	data, _ = json.Marshal(env)
	os.WriteFile(path, data, 0o600)
	if _, err := OpenStore(dir, signer.PublicKey()); err == nil {
		t.Error("書き換えた版を開けた")
	}
}

// 上限いっぱいの一覧でも、署名した大きさが privsep の 1 フレーム（8 MiB）に収まり、照合できる。
func TestLargeSet(t *testing.T) {
	s := &Set{Version: 1, IssuedAt: now, Lists: []List{{Name: "big", Action: ActionBlock, Updated: now, Source: strings.Repeat("u", 1024)}}}
	size := 0
	for i := range MaxCIDRs {
		c := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String() + "/32"
		s.Lists[0].CIDRs = append(s.Lists[0].CIDRs, c)
		size += len(c) + 3
	}
	for i := 0; ; i++ {
		d := fmt.Sprintf("host-%06d.malware-example.com", i)
		if size+len(d)+3 > MaxBytes || len(s.Lists[0].Domains) == MaxDomains {
			break
		}
		s.Lists[0].Domains = append(s.Lists[0].Domains, d)
		size += len(d) + 3
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(s)
	env, _ := json.Marshal(sign.Envelope{Purpose: sign.PurposeIntel, Payload: data, Signature: make([]byte, 64)})
	if len(env) > 8<<20-64<<10 {
		t.Errorf("署名した大きさ = %d バイト", len(env))
	}
	s.Lists[0].Domains = append(s.Lists[0].Domains, "one-more-domain-over-the-limit.example")
	if err := s.Validate(); err == nil {
		t.Error("大きすぎる一覧を受け付けた")
	}
	m := NewMatcher(s)
	if ms := m.Domain("x.host-000123.malware-example.com"); len(ms) != 1 {
		t.Error("大きな一覧で照合できない")
	}
}
