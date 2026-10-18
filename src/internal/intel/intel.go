// Package intel は脅威情報（G7）の形式、検証、照合を定める。
//
// 脅威情報は、公開されている悪性のドメインとアドレスの一覧を、名前を付けた一覧（List）にまとめたもの。
// 管理者が ctl で一覧のファイルを取り込み（ParseFeed）、ポリシーと同じ鍵で署名して配布する（sign.PurposeIntel）。
// 一覧ごとに、遮断する（block）か、検知だけする（alert）かを選ぶ。
//
//   - 遮断：GW の DNS は一覧のドメイン（とその下の名前）を引かせず、nftables は一覧のアドレスへの転送を落とす
//   - 照合：CONTROLLER は、DNS の問い合わせと通信の宛先（アドレス、SNI、HTTP の Host）を一覧と照合し、検知結果にする
//
// 脅威情報の取得（外部への接続）は、この仕組みでは行わない。管理者が入手したファイルを取り込む。
package intel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"

	"susanoo/internal/sign"
)

// Action は一覧に当てはまったときの扱い。
type Action string

const (
	ActionBlock Action = "block" // 遮断して検知する
	ActionAlert Action = "alert" // 検知だけする
)

// 上限。GW の各プロセスに 1 回で渡せる大きさ（privsep の 1 フレーム、8 MiB）に収める。署名すると中身は base64 で
// 4/3 倍になるので、ドメインとアドレスの範囲の文字数の合計（区切りを含む）を MaxBytes までとする。
const (
	MaxLists   = 32
	MaxDomains = 200000 // すべての一覧の合計
	MaxCIDRs   = 50000
	MaxBytes   = 5 << 20
	maxNameLen = 63
)

// Set は脅威情報の一式。
type Set struct {
	Version  int       `json:"version"` // 1 から始まり、配布のたびに増やす
	IssuedAt time.Time `json:"issued_at"`
	Lists    []List    `json:"lists"`
}

// List は名前を付けた一覧。
type List struct {
	Name    string    `json:"name"` // 英小文字、数字、「-」
	Action  Action    `json:"action"`
	Source  string    `json:"source,omitempty"` // 入手元（記録のため）
	Updated time.Time `json:"updated"`          // 取り込んだ時刻
	Domains []string  `json:"domains,omitempty"`
	CIDRs   []string  `json:"cidrs,omitempty"`
}

// Parse は脅威情報を読んで検証する。
func Parse(data []byte) (*Set, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var s Set
	if err := d.Decode(&s); err != nil {
		return nil, fmt.Errorf("intel: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("intel: JSON の後ろに余分なデータがあります")
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// ParseSigned は署名（sign.PurposeIntel）を検証してから脅威情報を読む。
func ParseSigned(v *sign.Verifier, env sign.Envelope) (*Set, error) {
	payload, err := v.Verify(sign.PurposeIntel, env)
	if err != nil {
		return nil, err
	}
	return Parse(payload)
}

// Validate は脅威情報を確かめる。ドメインとアドレスは正規化した形（ParseFeed の出力）であること。
func (s *Set) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf("intel: "+format, args...)) }
	if s.Version < 1 {
		add("version は 1 以上にしてください")
	}
	if s.IssuedAt.IsZero() {
		add("issued_at がありません")
	}
	if len(s.Lists) > MaxLists {
		add("一覧は %d 個までです", MaxLists)
	}
	seen := map[string]bool{}
	domains, cidrs, size := 0, 0, 0
	for i, l := range s.Lists {
		where := fmt.Sprintf("lists[%d]（%s）", i, l.Name)
		if !ValidName(l.Name) {
			add("%s: name は英小文字、数字、「-」で %d 文字までにしてください", where, maxNameLen)
		} else if seen[l.Name] {
			add("%s: name が重複しています", where)
		}
		seen[l.Name] = true
		if l.Action != ActionBlock && l.Action != ActionAlert {
			add("%s: action は block か alert にしてください", where)
		}
		if len(l.Source) > 1024 {
			add("%s: source が長すぎます", where)
		}
		for _, d := range l.Domains {
			if NormalizeDomain(d) != d {
				add("%s: ドメイン %q が不正です", where, d)
				break
			}
		}
		for _, c := range l.CIDRs {
			p, err := netip.ParsePrefix(c)
			if err != nil || p.Masked() != p || p.Addr().Zone() != "" {
				add("%s: アドレスの範囲 %q が不正です", where, c)
				break
			}
		}
		domains += len(l.Domains)
		cidrs += len(l.CIDRs)
		for _, x := range l.Domains {
			size += len(x) + 3
		}
		for _, x := range l.CIDRs {
			size += len(x) + 3
		}
	}
	if domains > MaxDomains || cidrs > MaxCIDRs {
		add("ドメインは合計 %d 個、アドレスの範囲は合計 %d 個までです（%d、%d）", MaxDomains, MaxCIDRs, domains, cidrs)
	}
	if size > MaxBytes {
		add("一覧が大きすぎます（ドメインとアドレスの範囲の合計 %d バイト。%d バイトまで）", size, MaxBytes)
	}
	return errors.Join(errs...)
}

// ValidName は一覧の名前として使えるかを返す。
func ValidName(name string) bool {
	if name == "" || len(name) > maxNameLen {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// NormalizeDomain はドメインを照合に使う形（小文字、末尾の「.」なし）にする。ドメインとして扱えなければ空を返す。
// ラベルは英数字、「-」、「_」（マルウェアが使うことがある）だけを受け付ける。日本語ドメインは Punycode で書く。
func NormalizeDomain(s string) string {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if len(s) == 0 || len(s) > 253 {
		return ""
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return ""
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return ""
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return ""
			}
		}
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "" // アドレス
	}
	if tld := labels[len(labels)-1]; strings.Trim(tld, "0123456789") == "" {
		return ""
	}
	return s
}

// Match は照合の結果。
type Match struct {
	List      string
	Action    Action
	Indicator string // 一覧に載っていたドメインかアドレスの範囲
}

// Matcher は脅威情報と照合する。作った後は変更しないので、ロックなしで共有できる。
type Matcher struct {
	Set     *Set // nil なら脅威情報なし
	domains map[string][]int
	v4, v6  map[int]map[netip.Prefix][]int // 長さ → 範囲 → 一覧の番号
	bits4   []int                          // 使っている長さ（長い順）
	bits6   []int
}

// NewMatcher は s（nil なら空）と照合する Matcher を作る。actions を指定すると、その扱いの一覧だけを使う。
func NewMatcher(s *Set, actions ...Action) *Matcher {
	m := &Matcher{Set: s, domains: map[string][]int{}, v4: map[int]map[netip.Prefix][]int{}, v6: map[int]map[netip.Prefix][]int{}}
	if s == nil {
		return m
	}
	for i, l := range s.Lists {
		if len(actions) > 0 && !slices.Contains(actions, l.Action) {
			continue
		}
		for _, d := range l.Domains {
			m.domains[d] = append(m.domains[d], i)
		}
		for _, c := range l.CIDRs {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				continue
			}
			tbl := m.v4
			if p.Addr().Is6() {
				tbl = m.v6
			}
			if tbl[p.Bits()] == nil {
				tbl[p.Bits()] = map[netip.Prefix][]int{}
			}
			tbl[p.Bits()][p] = append(tbl[p.Bits()][p], i)
		}
	}
	for b := range m.v4 {
		m.bits4 = append(m.bits4, b)
	}
	for b := range m.v6 {
		m.bits6 = append(m.bits6, b)
	}
	slices.Sort(m.bits4)
	slices.Reverse(m.bits4)
	slices.Sort(m.bits6)
	slices.Reverse(m.bits6)
	return m
}

// Empty は照合するものがないかを返す。
func (m *Matcher) Empty() bool {
	return len(m.domains) == 0 && len(m.v4) == 0 && len(m.v6) == 0
}

func (m *Matcher) matches(idx []int, indicator string) []Match {
	out := make([]Match, 0, len(idx))
	for _, i := range idx {
		l := m.Set.Lists[i]
		out = append(out, Match{List: l.Name, Action: l.Action, Indicator: indicator})
	}
	return out
}

// Domain は名前 name か、その上位のドメインが一覧にあれば、当てはまった一覧を返す（遮断の一覧を先にする）。
func (m *Matcher) Domain(name string) []Match {
	if len(m.domains) == 0 {
		return nil
	}
	name = NormalizeDomain(name)
	for name != "" {
		if idx, ok := m.domains[name]; ok {
			return sortMatches(m.matches(idx, name))
		}
		_, rest, ok := strings.Cut(name, ".")
		if !ok || !strings.Contains(rest, ".") {
			break
		}
		name = rest
	}
	return nil
}

// Addr はアドレスが一覧の範囲にあれば、当てはまった一覧を返す（最も狭い範囲。遮断の一覧を先にする）。
func (m *Matcher) Addr(a netip.Addr) []Match {
	a = a.Unmap()
	tbl, bits := m.v4, m.bits4
	if a.Is6() {
		tbl, bits = m.v6, m.bits6
	}
	for _, b := range bits {
		p, err := a.Prefix(b)
		if err != nil {
			continue
		}
		if idx, ok := tbl[b][p]; ok {
			return sortMatches(m.matches(idx, p.String()))
		}
	}
	return nil
}

func sortMatches(ms []Match) []Match {
	slices.SortStableFunc(ms, func(a, b Match) int {
		if a.Action == b.Action {
			return 0
		}
		if a.Action == ActionBlock {
			return -1
		}
		return 1
	})
	return ms
}

// BlockedPrefixes は遮断する一覧のアドレスの範囲を、重なりを除いて返す（nftables の集合に入れる）。
func (s *Set) BlockedPrefixes() []netip.Prefix {
	if s == nil {
		return nil
	}
	var ps []netip.Prefix
	for _, l := range s.Lists {
		if l.Action != ActionBlock {
			continue
		}
		for _, c := range l.CIDRs {
			if p, err := netip.ParsePrefix(c); err == nil {
				ps = append(ps, p)
			}
		}
	}
	return MergePrefixes(ps)
}

// Blocklist は、DNS で引かせないドメインの一覧（遮断する一覧のドメインだけ）。GW の LAN 側の処理に渡す。
type Blocklist struct {
	Version int             `json:"version"`
	Lists   []BlocklistPart `json:"lists"`
}

// BlocklistPart は Blocklist の 1 つの一覧。
type BlocklistPart struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
}

// Blocklist は遮断する一覧のドメインを返す。
func (s *Set) Blocklist() Blocklist {
	b := Blocklist{Lists: []BlocklistPart{}}
	if s == nil {
		return b
	}
	b.Version = s.Version
	for _, l := range s.Lists {
		if l.Action == ActionBlock && len(l.Domains) > 0 {
			b.Lists = append(b.Lists, BlocklistPart{Name: l.Name, Domains: l.Domains})
		}
	}
	return b
}

// Matcher は Blocklist のドメインと照合する Matcher を作る。
func (b Blocklist) Matcher() *Matcher {
	s := &Set{Version: b.Version}
	for _, p := range b.Lists {
		var ds []string
		for _, d := range p.Domains {
			if NormalizeDomain(d) == d {
				ds = append(ds, d)
			}
		}
		if ValidName(p.Name) {
			s.Lists = append(s.Lists, List{Name: p.Name, Action: ActionBlock, Domains: ds})
		}
	}
	return NewMatcher(s)
}

// MergePrefixes は、ほかの範囲に含まれる範囲を取り除き、アドレスの順に並べて返す。
func MergePrefixes(ps []netip.Prefix) []netip.Prefix {
	sorted := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		if p.IsValid() {
			sorted = append(sorted, p.Masked())
		}
	}
	slices.SortFunc(sorted, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	// 並べると、ある範囲を含む範囲は、残した最後の範囲だけになる（残した範囲どうしは重ならない）。
	var out []netip.Prefix
	for _, p := range sorted {
		if n := len(out); n > 0 {
			last := out[n-1]
			if last.Addr().BitLen() == p.Addr().BitLen() && last.Bits() <= p.Bits() && last.Contains(p.Addr()) {
				continue
			}
		}
		out = append(out, p)
	}
	return out
}
