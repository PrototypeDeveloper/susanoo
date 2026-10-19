package nft

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// BridgeTable はブリッジ方式（G1）のテーブルの名前。bridge と inet の 2 つの種類に同じ名前で作る。
const BridgeTable = "susanoo_bridge"

// BridgeRules はブリッジ方式の GW のルール（G1、G3、G8、G12）。GW は上流のルーターと LAN の間に透過のブリッジとして入る。
//
//   - GW 自身には、LAN 側のポートから、管理通信、DNS、管理用のポート（SSH など）、ping だけを受け付ける。
//     上流のルーター側のポートからは、GW が始めた通信の戻りと、DHCP の応答（ブリッジのアドレスを DHCP で得るとき）だけを受け付ける
//   - LAN 側のポートから入るルーター広告と DHCPv6 のサーバーの応答は、ブリッジを越えさせず、GW 自身も受け取らない（認めたルーターを除く）
//   - DNS が有効なら、LAN から外部の DNS サーバーへの問い合わせの宛先の MAC アドレスを GW に書き換えてブリッジの外に上げ、
//     GW のアドレスに向け直す（bridge のテーブルでは DNAT できないため、inet のテーブルで向け直す）。IPv6 の DNS は向け直し先が
//     ないので落とす（端末は IPv4 の DNS を使う）
type BridgeRules struct {
	Bridge         string           // ブリッジの装置（GW のアドレスを持つ）
	LAN, WAN       string           // ブリッジのポート
	ManagementPort uint16           // CONTROLLER の待ち受けポート
	AdminPorts     []uint16         // LAN から受け付ける管理用のポート
	WANDHCP        bool             // ブリッジのアドレスを DHCP で得る
	DNS            netip.Addr       // GW のアドレス。有効なら LAN の DNS を GW のリゾルバに向け直す
	MAC            net.HardwareAddr // ブリッジの MAC アドレス（DNS を GW に上げるのに使う）
	TrustedRouters []string         // LAN にいてよいルーター（RA と DHCPv6 を通す）の MAC アドレス
}

// Script は bridge と inet のテーブルを作り直すスクリプトを返す。
func (r BridgeRules) Script() (string, error) {
	for _, name := range []string{r.Bridge, r.LAN, r.WAN} {
		if !ifacePattern.MatchString(name) {
			return "", fmt.Errorf("nft: インターフェースの名前 %q が不正です", name)
		}
	}
	if r.LAN == r.WAN || r.Bridge == r.LAN || r.Bridge == r.WAN {
		return "", fmt.Errorf("nft: ブリッジ %q、LAN %q、WAN %q は別々の装置にしてください", r.Bridge, r.LAN, r.WAN)
	}
	if r.ManagementPort == 0 {
		return "", fmt.Errorf("nft: 管理通信のポートがありません")
	}
	redirect := r.DNS.Is4()
	if redirect && len(r.MAC) != 6 {
		return "", fmt.Errorf("nft: DNS を向け直すには、ブリッジの MAC アドレスが必要です")
	}
	trusted, err := canonicalMACs(r.TrustedRouters)
	if err != nil {
		return "", err
	}
	lan, wan := fmt.Sprintf("%q", r.LAN), fmt.Sprintf("%q", r.WAN)

	input := []string{
		"meta protocol arp accept",
		"ct state established,related accept",
		"ct state invalid drop",
		// GW 自身も LAN の機器のルーター広告には従わない（上流のルーターの広告は WAN 側のポートから入る）。
		fmt.Sprintf("iifname %s ether saddr != @trusted_routers icmpv6 type nd-router-advert drop", lan),
		"icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept",
		fmt.Sprintf("iifname %s icmp type echo-request accept", lan),
		fmt.Sprintf("iifname %s icmpv6 type echo-request accept", lan),
		fmt.Sprintf("iifname %s tcp dport %d accept", lan, r.ManagementPort),
	}
	if redirect {
		input = append(input, fmt.Sprintf("iifname %s meta l4proto { tcp, udp } th dport 53 accept", lan))
	}
	if ports := portSet(r.AdminPorts); ports != "" {
		input = append(input, fmt.Sprintf("iifname %s tcp dport %s accept", lan, ports))
	}
	if r.WANDHCP {
		input = append(input, fmt.Sprintf("iifname %s udp sport 67 udp dport 68 accept", wan))
	}
	input = append(input, "meta protocol { ip, ip6 } drop")

	forward := []string{
		fmt.Sprintf("iifname %s ether saddr != @trusted_routers icmpv6 type nd-router-advert drop", lan),
		fmt.Sprintf("iifname %s ether saddr != @trusted_routers udp sport 547 udp dport 546 drop", lan),
	}
	if redirect {
		forward = append(forward, fmt.Sprintf("iifname %s meta protocol ip6 meta l4proto { tcp, udp } th dport 53 drop", lan))
	}

	var b strings.Builder
	b.WriteString(replaceTableIn(Bridge, BridgeTable))
	b.WriteString(replaceTableIn(Inet, BridgeTable))
	fmt.Fprintf(&b, "table bridge %s {\n", BridgeTable)
	writeSet(&b, "trusted_routers", "ether_addr", false, trusted)
	if redirect {
		writeChainPriority(&b, "prerouting", "filter", "prerouting", "-350", "accept", []string{
			fmt.Sprintf("iifname %s ip daddr != %s meta l4proto { tcp, udp } th dport 53 meta pkttype set host ether daddr set %s", lan, r.DNS, r.MAC),
		})
	}
	writeChainPriority(&b, "input", "filter", "input", priority, "accept", input)
	writeChainPriority(&b, "forward", "filter", "forward", "-20", "accept", forward)
	b.WriteString("}\n")
	if redirect {
		fmt.Fprintf(&b, "table inet %s {\n", BridgeTable)
		br := fmt.Sprintf("%q", r.Bridge)
		writeChainPriority(&b, "dns", "nat", "prerouting", "dstnat", "accept", []string{
			fmt.Sprintf("iifname %s ip daddr != %s udp dport 53 dnat ip to %s:53", br, r.DNS, r.DNS),
			fmt.Sprintf("iifname %s ip daddr != %s tcp dport 53 dnat ip to %s:53", br, r.DNS, r.DNS),
		})
		b.WriteString("}\n")
	}
	return b.String(), nil
}
