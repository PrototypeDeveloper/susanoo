package nft

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"susanoo/internal/policy"
)

// EgressTable は外部通信の制御（G2、G3、G4）のテーブルの名前。
const EgressTable = "susanoo_egress"

// Egress は外部通信の制御のルール。LAN から新しく始まる転送の通信だけを対象にする。
//
// グループごとにチェインを分け、所属は MAC アドレスの集合で決める（どれにも属さない端末は 0 番目の既定のグループ）。
// チェインでは、抜け道の遮断（G4）、拒否、許可の順に評価し、最後にグループの既定の扱い（通す・遮断）を適用する。
// 許可は、静的な CIDR の集合と、DNS で得たアドレスを有効期限付きで入れる集合の両方で照合する。
// DNS が有効なら、LAN から外部の DNS サーバーへの問い合わせを GW のリゾルバに向け直す（G3）。
type Egress struct {
	LAN    string
	DNS    netip.Addr     // GW の LAN 側のアドレス。無効なら DNS を向け直さない
	DoH    []netip.Prefix // 既知の DoH サーバー
	Groups []EgressGroup  // 0 番目が既定のグループ
}

// EgressGroup はグループのルール。
type EgressGroup struct {
	Name    string
	Members []string // MAC アドレス（既定のグループでは使わない）
	Default policy.EgressDefault
	Bypass  policy.Bypass
	Allow   []EgressRule
	Deny    []netip.Prefix
}

// EgressRule は、ポートの指定が同じ許可をまとめたもの。DNS で得たアドレスもここに入る。
type EgressRule struct {
	Protocol string // tcp、udp、または空（両方）
	Ports    []uint16
	CIDRs    []netip.Prefix
}

// AllowSet は、グループ g の許可 r のうち DNS で得たアドレスを入れる集合の名前を返す。
func AllowSet(g, r int, v6 bool) string {
	return fmt.Sprintf("g%d_a%d_d%s", g, r, ipSuffix(v6))
}

func ipSuffix(v6 bool) string {
	if v6 {
		return "6"
	}
	return "4"
}

func (e Egress) validate() error {
	if !ifacePattern.MatchString(e.LAN) {
		return fmt.Errorf("nft: インターフェースの名前 %q が不正です", e.LAN)
	}
	if len(e.Groups) == 0 {
		return fmt.Errorf("nft: グループがありません")
	}
	for _, g := range e.Groups {
		switch g.Default {
		case policy.EgressAllow, policy.EgressLearn, policy.EgressDeny:
		default:
			return fmt.Errorf("nft: グループ %q の既定の扱い %q が不正です", g.Name, g.Default)
		}
		for _, r := range g.Allow {
			switch r.Protocol {
			case "", "tcp", "udp":
			default:
				return fmt.Errorf("nft: プロトコル %q が不正です", r.Protocol)
			}
		}
	}
	return nil
}

// Script はテーブルを作り直すスクリプトを返す。DNS で得たアドレスは消える。
func (e Egress) Script() (string, error) {
	if err := e.validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(replaceTable(EgressTable))
	fmt.Fprintf(&b, "table inet %s {\n", EgressTable)

	doh4, doh6 := splitPrefixes(e.DoH)
	writeSet(&b, "doh_4", "ipv4_addr", true, doh4)
	writeSet(&b, "doh_6", "ipv6_addr", true, doh6)
	for i, g := range e.Groups {
		if i > 0 {
			macs, err := canonicalMACs(g.Members)
			if err != nil {
				return "", err
			}
			writeSet(&b, fmt.Sprintf("g%d_m", i), "ether_addr", false, macs)
		}
		d4, d6 := splitPrefixes(g.Deny)
		writeSet(&b, fmt.Sprintf("g%d_d_s4", i), "ipv4_addr", true, d4)
		writeSet(&b, fmt.Sprintf("g%d_d_s6", i), "ipv6_addr", true, d6)
		for j, r := range g.Allow {
			s4, s6 := splitPrefixes(r.CIDRs)
			writeSet(&b, fmt.Sprintf("g%d_a%d_s4", i, j), "ipv4_addr", true, s4)
			writeSet(&b, fmt.Sprintf("g%d_a%d_s6", i, j), "ipv6_addr", true, s6)
			writeTimeoutSet(&b, AllowSet(i, j, false), "ipv4_addr")
			writeTimeoutSet(&b, AllowSet(i, j, true), "ipv6_addr")
		}
	}

	forward := []string{
		fmt.Sprintf("iifname != %q accept", e.LAN),
		"ct state established,related accept",
	}
	for i := 1; i < len(e.Groups); i++ {
		forward = append(forward, fmt.Sprintf("ether saddr @g%d_m jump g%d", i, i))
	}
	forward = append(forward, "jump g0")
	writeChainPriority(&b, "forward", "filter", "forward", "-5", "accept", forward)

	for i, g := range e.Groups {
		writeRegularChain(&b, fmt.Sprintf("g%d", i), groupRules(i, g))
	}
	if e.DNS.Is4() {
		writeChainPriority(&b, "dns", "nat", "prerouting", "dstnat", "accept", []string{
			fmt.Sprintf("iifname %q ip daddr != %s udp dport 53 dnat ip to %s:53", e.LAN, e.DNS, e.DNS),
			fmt.Sprintf("iifname %q ip daddr != %s tcp dport 53 dnat ip to %s:53", e.LAN, e.DNS, e.DNS),
		})
	}
	b.WriteString("}\n")
	return b.String(), nil
}

// groupRules はグループのチェインのルールを返す。
func groupRules(i int, g EgressGroup) []string {
	var rules []string
	if !g.Bypass.AllowQUIC {
		rules = append(rules, "udp dport 443 drop")
	}
	if !g.Bypass.AllowDoH {
		rules = append(rules,
			"meta l4proto { tcp, udp } th dport 853 drop",
			"ip daddr @doh_4 meta l4proto { tcp, udp } th dport 443 drop",
			"ip6 daddr @doh_6 meta l4proto { tcp, udp } th dport 443 drop")
	}
	if !g.Bypass.AllowVPN {
		rules = append(rules,
			"udp dport { 500, 1194, 1701, 4500, 51820 } drop",
			"tcp dport { 1194, 1723 } drop",
			"meta l4proto { esp, ah, gre } drop")
	}
	rules = append(rules,
		fmt.Sprintf("ip daddr @g%d_d_s4 drop", i),
		fmt.Sprintf("ip6 daddr @g%d_d_s6 drop", i))
	for j, r := range g.Allow {
		spec := portSpec(r)
		for _, set := range []string{
			fmt.Sprintf("ip daddr @g%d_a%d_s4", i, j),
			fmt.Sprintf("ip daddr @%s", AllowSet(i, j, false)),
			fmt.Sprintf("ip6 daddr @g%d_a%d_s6", i, j),
			fmt.Sprintf("ip6 daddr @%s", AllowSet(i, j, true)),
		} {
			rules = append(rules, strings.TrimSpace(set+" "+spec)+" accept")
		}
	}
	if g.Default == policy.EgressDeny {
		rules = append(rules, "drop")
	} else {
		rules = append(rules, "accept")
	}
	return rules
}

// portSpec はポートとプロトコルの照合の式を返す。指定がなければ空。
func portSpec(r EgressRule) string {
	ports := portSet(r.Ports)
	switch {
	case ports == "" && r.Protocol == "":
		return ""
	case ports == "":
		return "meta l4proto " + r.Protocol
	case r.Protocol == "":
		return "meta l4proto { tcp, udp } th dport " + ports
	default:
		return r.Protocol + " dport " + ports
	}
}

// MembersScript はグループの所属の集合だけを入れ替えるスクリプトを返す。DNS で得たアドレスは保つ。
func (e Egress) MembersScript() (string, error) {
	var b strings.Builder
	for i := 1; i < len(e.Groups); i++ {
		macs, err := canonicalMACs(e.Groups[i].Members)
		if err != nil {
			return "", err
		}
		set := fmt.Sprintf("g%d_m", i)
		fmt.Fprintf(&b, "flush set inet %s %s\n", EgressTable, set)
		if len(macs) > 0 {
			fmt.Fprintf(&b, "add element inet %s %s { %s }\n", EgressTable, set, strings.Join(macs, ", "))
		}
	}
	return b.String(), nil
}

// AddWithTimeout は、集合に有効期限付きでアドレスを加えるスクリプトを返す。既にあれば期限を延ばす。
// 「加える → 消す → 加える」を 1 回の nft -f で行い、要素の有無にかかわらず失敗しないようにする。
func AddWithTimeout(table, set string, addrs []netip.Addr, timeout time.Duration) string {
	secs := max(int(timeout/time.Second), 1)
	var elems, plain []string
	for _, a := range addrs {
		_, s := family(a)
		elems = append(elems, fmt.Sprintf("%s timeout %ds", s, secs))
		plain = append(plain, s)
	}
	if len(elems) == 0 {
		return ""
	}
	e, p := strings.Join(elems, ", "), strings.Join(plain, ", ")
	return fmt.Sprintf("add element inet %[1]s %[2]s { %[3]s }\ndelete element inet %[1]s %[2]s { %[4]s }\nadd element inet %[1]s %[2]s { %[3]s }\n",
		table, set, e, p)
}

// FailOpenScript は障害時に通信を通す（fail_open）ときのテーブルを返す。外部通信の制御をやめ、
// upstream が有効なら LAN の DNS を上流の DNS サーバーに向け直す（GW のリゾルバが止まっても名前を引けるように）。
func FailOpenScript(lan string, gw netip.Addr, upstream netip.AddrPort) (string, error) {
	if !ifacePattern.MatchString(lan) {
		return "", fmt.Errorf("nft: インターフェースの名前 %q が不正です", lan)
	}
	if !upstream.Addr().Is4() || !gw.Is4() {
		return DeleteTable(EgressTable), nil
	}
	var b strings.Builder
	b.WriteString(replaceTable(EgressTable))
	fmt.Fprintf(&b, "table inet %s {\n", EgressTable)
	writeChainPriority(&b, "dns", "nat", "prerouting", "dstnat", "accept", []string{
		fmt.Sprintf("iifname %q ip daddr %s udp dport 53 dnat ip to %s", lan, gw, upstream),
		fmt.Sprintf("iifname %q ip daddr %s tcp dport 53 dnat ip to %s", lan, gw, upstream),
	})
	b.WriteString("}\n")
	return b.String(), nil
}

func splitPrefixes(ps []netip.Prefix) (v4, v6 []string) {
	for _, p := range ps {
		if !p.IsValid() {
			continue
		}
		if p.Addr().Is4() {
			v4 = append(v4, p.Masked().String())
		} else {
			v6 = append(v6, p.Masked().String())
		}
	}
	return mergePrefixes(v4), mergePrefixes(v6)
}

// mergePrefixes は、ほかの CIDR に含まれる CIDR を取り除く（auto-merge を使わない集合で重なりを避ける）。
func mergePrefixes(ps []string) []string {
	parsed := make([]netip.Prefix, 0, len(ps))
	for _, s := range ps {
		parsed = append(parsed, netip.MustParsePrefix(s))
	}
	slices.SortFunc(parsed, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	// 並べると、ある範囲を含む範囲は、残した最後の範囲だけになる（残した範囲どうしは重ならない）。
	// 脅威情報の大きな一覧でも、並べ替えの手間で済む。
	var out []string
	var last netip.Prefix
	for _, p := range parsed {
		if last.IsValid() && last.Bits() <= p.Bits() && last.Contains(p.Addr()) {
			continue
		}
		last = p
		out = append(out, p.String())
	}
	return out
}

func canonicalMACs(macs []string) ([]string, error) {
	var out []string
	for _, s := range macs {
		hw, err := net.ParseMAC(s)
		if err != nil || len(hw) != 6 {
			return nil, fmt.Errorf("nft: MAC アドレス %q が不正です", s)
		}
		out = append(out, hw.String())
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

func writeTimeoutSet(b *strings.Builder, name, typ string) {
	fmt.Fprintf(b, "\tset %s {\n\t\ttype %s\n\t\tflags timeout\n\t}\n", name, typ)
}

func writeRegularChain(b *strings.Builder, name string, rules []string) {
	fmt.Fprintf(b, "\tchain %s {\n", name)
	for _, r := range rules {
		fmt.Fprintf(b, "\t\t%s\n", r)
	}
	b.WriteString("\t}\n")
}
