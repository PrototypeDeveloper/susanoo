package nft

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// RouterTable はルーター方式（G1）のテーブルの名前。
const RouterTable = "susanoo_router"

var ifacePattern = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,15}$`)

// Router はルーター方式の GW のルール（G1、G12）。
//
//   - LAN から WAN への通信を NAT で送り出し、その戻りの通信だけを通す
//   - LAN の IPv6 の転送は遮断する（IPv6 の抜け道を防ぐ。MVP では LAN で IPv6 を使わない）
//   - GW 自身には、LAN から DHCP、DNS、管理通信、管理用のポート（SSH など）、ping（IPv4 と IPv6）だけを受け付ける
//
// 端末単位の遮断（GWTable）はこれより先に評価する。
type Router struct {
	LAN, WAN       string   // インターフェースの名前
	ManagementPort uint16   // CONTROLLER の待ち受けポート
	AdminPorts     []uint16 // LAN から受け付ける管理用のポート（SSH など）
	DHCP           bool     // LAN から DHCP を受け付ける
	DNS            bool     // LAN から DNS を受け付ける
	WANDHCP        bool     // WAN 側のアドレスを DHCP で得る
}

// Script はテーブルを作り直すスクリプトを返す。
func (r Router) Script() (string, error) {
	for _, name := range []string{r.LAN, r.WAN} {
		if !ifacePattern.MatchString(name) {
			return "", fmt.Errorf("nft: インターフェースの名前 %q が不正です", name)
		}
	}
	if r.LAN == r.WAN {
		return "", fmt.Errorf("nft: LAN と WAN に同じインターフェース %q は使えません", r.LAN)
	}
	if r.ManagementPort == 0 {
		return "", fmt.Errorf("nft: 管理通信のポートがありません")
	}
	lan, wan := fmt.Sprintf("%q", r.LAN), fmt.Sprintf("%q", r.WAN)

	input := []string{
		`iif "lo" accept`,
		"ct state established,related accept",
		"ct state invalid drop",
		"icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept",
		fmt.Sprintf("iifname %s icmp type echo-request accept", lan),
		fmt.Sprintf("iifname %s icmpv6 type echo-request accept", lan),
		fmt.Sprintf("iifname %s tcp dport %d accept", lan, r.ManagementPort),
	}
	if r.DHCP {
		input = append(input, fmt.Sprintf("iifname %s udp sport 68 udp dport 67 accept", lan))
	}
	if r.DNS {
		input = append(input, fmt.Sprintf("iifname %s meta l4proto { tcp, udp } th dport 53 accept", lan))
	}
	if ports := portSet(r.AdminPorts); ports != "" {
		input = append(input, fmt.Sprintf("iifname %s tcp dport %s accept", lan, ports))
	}
	if r.WANDHCP {
		input = append(input, fmt.Sprintf("iifname %s udp sport 67 udp dport 68 accept", wan))
	}

	forward := []string{
		"meta nfproto ipv6 drop",
		"ct state established,related accept",
		"ct state invalid drop",
		fmt.Sprintf("iifname %s oifname %s accept", lan, wan),
	}

	var b strings.Builder
	b.WriteString(replaceTable(RouterTable))
	fmt.Fprintf(&b, "table inet %s {\n", RouterTable)
	writeChainPriority(&b, "input", "filter", "input", "0", "drop", input)
	writeChainPriority(&b, "forward", "filter", "forward", "0", "drop", forward)
	writeChainPriority(&b, "postrouting", "nat", "postrouting", "srcnat", "accept",
		[]string{fmt.Sprintf("oifname %s masquerade", wan)})
	b.WriteString("}\n")
	return b.String(), nil
}

// portSet はポートの一覧を nft の集合の形にする。空なら空文字列。
func portSet(ports []uint16) string {
	var s []string
	for _, p := range slices.Compact(slices.Sorted(slices.Values(ports))) {
		if p != 0 {
			s = append(s, fmt.Sprint(p))
		}
	}
	if len(s) == 0 {
		return ""
	}
	return "{ " + strings.Join(s, ", ") + " }"
}

func writeChainPriority(b *strings.Builder, name, typ, hook, prio, policy string, rules []string) {
	fmt.Fprintf(b, "\tchain %s {\n", name)
	fmt.Fprintf(b, "\t\ttype %s hook %s priority %s; policy %s;\n", typ, hook, prio, policy)
	for _, r := range rules {
		fmt.Fprintf(b, "\t\t%s\n", r)
	}
	b.WriteString("\t}\n")
}
