package nft

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// ClientIsolation は CLIENT の自己隔離のルール（C6）。
// 管理通信、DHCP、許可した更新サーバーとの通信を除き、すべての通信を遮断する。
type ClientIsolation struct {
	Management []netip.AddrPort // 管理通信（TCP）の宛先。CONTROLLER など
	Updates    []netip.Prefix   // 許可する更新サーバー
	AllowDHCP  bool             // DHCP（v4）を許可して、アドレスを失わないようにする
}

// Script はテーブルを作り直すスクリプトを返す。
func (c ClientIsolation) Script() (string, error) {
	if len(c.Management) == 0 {
		return "", errors.New("nft: 管理通信の宛先がないと、隔離を解除する指示を受け取れません")
	}
	var in, out []string
	v6 := false
	for _, ap := range c.Management {
		if !ap.IsValid() || ap.Port() == 0 {
			return "", fmt.Errorf("nft: 管理通信の宛先 %v が不正です", ap)
		}
		fam, addr := family(ap.Addr())
		v6 = v6 || fam == "ip6"
		in = append(in, fmt.Sprintf("%s saddr %s tcp sport %d ct state established,related accept", fam, addr, ap.Port()))
		out = append(out, fmt.Sprintf("%s daddr %s tcp dport %d accept", fam, addr, ap.Port()))
	}
	if c.AllowDHCP {
		in = append(in, "udp sport 67 udp dport 68 accept")
		out = append(out, "udp sport 68 udp dport 67 accept")
	}
	if v6 {
		// IPv6 で管理通信をするには近隣探索が必要。
		in = append(in, "icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept")
		out = append(out, "icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept")
	}
	for _, p := range c.Updates {
		if !p.IsValid() {
			return "", fmt.Errorf("nft: 更新サーバー %v が不正です", p)
		}
		fam := "ip"
		if !p.Addr().Is4() {
			fam = "ip6"
		}
		in = append(in, fmt.Sprintf("%s saddr %s ct state established,related accept", fam, p.Masked()))
		out = append(out, fmt.Sprintf("%s daddr %s accept", fam, p.Masked()))
	}

	var b strings.Builder
	b.WriteString(replaceTable(ClientTable))
	fmt.Fprintf(&b, "table inet %s {\n", ClientTable)
	writeChain(&b, "input", "drop", append([]string{`iif "lo" accept`}, in...))
	writeChain(&b, "output", "drop", append([]string{`oif "lo" accept`}, out...))
	writeChain(&b, "forward", "drop", nil)
	b.WriteString("}\n")
	return b.String(), nil
}

// family はアドレスのファミリー（ip か ip6）と、ルールに書く文字列を返す。
// IPv4 射影アドレスは IPv4 として扱う。
func family(a netip.Addr) (string, string) {
	a = a.Unmap()
	if a.Is4() {
		return "ip", a.String()
	}
	return "ip6", a.WithZone("").String()
}

func writeChain(b *strings.Builder, name, policy string, rules []string) {
	fmt.Fprintf(b, "\tchain %s {\n", name)
	fmt.Fprintf(b, "\t\ttype filter hook %s priority %s; policy %s;\n", name, priority, policy)
	for _, r := range rules {
		fmt.Fprintf(b, "\t\t%s\n", r)
	}
	b.WriteString("\t}\n")
}
