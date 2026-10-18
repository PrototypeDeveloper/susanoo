package nft

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"susanoo/internal/policy"
)

// GWIsolation は GW の端末単位の遮断のルール（G9）。
//
//   - full：その端末との通信をすべて遮断する（GW 自身への通信も含む）
//   - management：GW 上の CONTROLLER への管理通信と DHCP だけを許可する
//   - management_and_updates：management に加え、更新サーバーとの通信を許可する
//
// 端末はアドレスと MAC アドレスの両方で遮断する。隔離された端末がアドレスを変えても、
// LAN から届く通信は MAC アドレスで止まる。management_and_updates の端末には GW の DNS を許可し、
// ドメインで指定した更新サーバーのアドレスは、DNS で解決したときに UpdatesDynamicSet に入れる。
type GWIsolation struct {
	ManagementPort uint16                               // GW 上の CONTROLLER の待ち受けポート（TCP）
	Addrs          map[netip.Addr]policy.IsolationLevel // アドレスで遮断する端末と段階
	MACs           map[string]policy.IsolationLevel     // MAC アドレスで遮断する端末と段階
	Updates        []netip.Prefix                       // 更新サーバー
}

// gwLevel は隔離の段階と、その端末を入れる集合の名前（接尾辞を除く）。
type gwLevel struct {
	level policy.IsolationLevel
	set   string
}

var gwLevels = []gwLevel{
	{policy.IsolateFull, "isolate_full"},
	{policy.IsolateManagement, "isolate_management"},
	{policy.IsolateManagementAndUpdates, "isolate_updates"},
}

func levelSet(level policy.IsolationLevel) (string, error) {
	i := slices.IndexFunc(gwLevels, func(l gwLevel) bool { return l.level == level })
	if i < 0 {
		return "", fmt.Errorf("nft: 不明な隔離の段階です: %q", level)
	}
	return gwLevels[i].set, nil
}

// UpdatesDynamicSet は、DNS で解決した更新サーバーのアドレスを入れる集合の名前を返す。
func UpdatesDynamicSet(v6 bool) string { return "updates_dyn_" + ipSuffix(v6) }

// staticSets は端末と更新サーバーの集合の名前と型を返す（DNS で得たアドレスの集合を除く）。
func staticSets() [][3]string {
	var sets [][3]string
	for _, l := range gwLevels {
		sets = append(sets, [3]string{l.set + "_v4", "ipv4_addr", ""}, [3]string{l.set + "_v6", "ipv6_addr", ""}, [3]string{l.set + "_mac", "ether_addr", ""})
	}
	return append(sets, [3]string{"updates_v4", "ipv4_addr", "interval"}, [3]string{"updates_v6", "ipv6_addr", "interval"})
}

// SetsScript は端末と更新サーバーの集合だけを入れ替えるスクリプトを返す。
// DNS で得た更新サーバーのアドレスは保つ。テーブルがない場合は Script を使う。
func (g GWIsolation) SetsScript() (string, error) {
	members, err := g.members()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, s := range staticSets() {
		fmt.Fprintf(&b, "flush set inet %s %s\n", GWTable, s[0])
		if elems := members[s[0]]; len(elems) > 0 {
			slices.Sort(elems)
			fmt.Fprintf(&b, "add element inet %s %s { %s }\n", GWTable, s[0], strings.Join(slices.Compact(elems), ", "))
		}
	}
	return b.String(), nil
}

// members は集合の名前ごとの要素を返す。
func (g GWIsolation) members() (map[string][]string, error) {
	members := map[string][]string{}
	for addr, level := range g.Addrs {
		if !addr.IsValid() {
			return nil, fmt.Errorf("nft: 端末のアドレス %v が不正です", addr)
		}
		set, err := levelSet(level)
		if err != nil {
			return nil, err
		}
		fam, s := family(addr)
		members[set+suffix(fam)] = append(members[set+suffix(fam)], s)
	}
	for s, level := range g.MACs {
		hw, err := net.ParseMAC(s)
		if err != nil || len(hw) != 6 {
			return nil, fmt.Errorf("nft: MAC アドレス %q が不正です", s)
		}
		set, err := levelSet(level)
		if err != nil {
			return nil, err
		}
		members[set+"_mac"] = append(members[set+"_mac"], hw.String())
	}
	for _, p := range g.Updates {
		if !p.IsValid() {
			return nil, fmt.Errorf("nft: 更新サーバー %v が不正です", p)
		}
		fam := "ip"
		if !p.Addr().Is4() {
			fam = "ip6"
		}
		members["updates"+suffix(fam)] = append(members["updates"+suffix(fam)], p.Masked().String())
	}
	members["updates_v4"] = mergePrefixes(members["updates_v4"])
	members["updates_v6"] = mergePrefixes(members["updates_v6"])
	return members, nil
}

// Script はテーブルを作り直すスクリプトを返す。
func (g GWIsolation) Script() (string, error) {
	if g.ManagementPort == 0 {
		return "", fmt.Errorf("nft: 管理通信のポートがありません")
	}
	members, err := g.members()
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString(replaceTable(GWTable))
	fmt.Fprintf(&b, "table inet %s {\n", GWTable)
	for _, s := range staticSets() {
		writeSet(&b, s[0], s[1], s[2] == "interval", members[s[0]])
	}
	writeTimeoutSet(&b, UpdatesDynamicSet(false), "ipv4_addr")
	writeTimeoutSet(&b, UpdatesDynamicSet(true), "ipv6_addr")

	var input, forward []string
	// 送信元は、アドレス（IPv4、IPv6）と MAC アドレスのそれぞれで照合する。
	// MAC アドレスで照合できるのは、LAN から届く通信だけ。
	for _, m := range []struct{ key, sfx string }{{"ip saddr", "_v4"}, {"ip6 saddr", "_v6"}, {"ether saddr", "_mac"}} {
		full, mgmt, upd := "@isolate_full"+m.sfx, "@isolate_management"+m.sfx, "@isolate_updates"+m.sfx

		input = append(input, fmt.Sprintf("%s %s drop", m.key, full))
		for _, set := range []string{mgmt, upd} {
			input = append(input, fmt.Sprintf("%s %s tcp dport %d accept", m.key, set, g.ManagementPort))
			if m.sfx != "_v6" {
				input = append(input, fmt.Sprintf("%s %s udp dport 67 accept", m.key, set))
			}
			if set == upd {
				input = append(input, fmt.Sprintf("%s %s meta l4proto { tcp, udp } th dport 53 accept", m.key, set))
			}
			input = append(input, fmt.Sprintf("%s %s drop", m.key, set))
		}

		forward = append(forward, fmt.Sprintf("%s %s drop", m.key, full), fmt.Sprintf("%s %s drop", m.key, mgmt))
		switch m.sfx {
		case "_v4", "_v6":
			fam := strings.Fields(m.key)[0]
			forward = append(forward,
				fmt.Sprintf("%s %s %s daddr @updates%s accept", m.key, upd, fam, m.sfx),
				fmt.Sprintf("%s %s %s daddr @%s accept", m.key, upd, fam, UpdatesDynamicSet(m.sfx == "_v6")))
		case "_mac":
			forward = append(forward,
				fmt.Sprintf("%s %s ip daddr @updates_v4 accept", m.key, upd),
				fmt.Sprintf("%s %s ip daddr @%s accept", m.key, upd, UpdatesDynamicSet(false)),
				fmt.Sprintf("%s %s ip6 daddr @updates_v6 accept", m.key, upd),
				fmt.Sprintf("%s %s ip6 daddr @%s accept", m.key, upd, UpdatesDynamicSet(true)))
		}
		forward = append(forward, fmt.Sprintf("%s %s drop", m.key, upd))
	}
	// 遮断した端末への通信（戻りの通信を含む）も止める。更新サーバーからの戻りの通信だけは通す。
	for _, fam := range []string{"ip", "ip6"} {
		sfx := suffix(fam)
		forward = append(forward,
			fmt.Sprintf("%s daddr @isolate_full%s drop", fam, sfx),
			fmt.Sprintf("%s daddr @isolate_management%s drop", fam, sfx),
			fmt.Sprintf("%s daddr @isolate_updates%s %s saddr @updates%s ct state established,related accept", fam, sfx, fam, sfx),
			fmt.Sprintf("%s daddr @isolate_updates%s %s saddr @%s ct state established,related accept", fam, sfx, fam, UpdatesDynamicSet(fam == "ip6")),
			fmt.Sprintf("%s daddr @isolate_updates%s drop", fam, sfx))
	}
	writeChain(&b, "input", "accept", input)
	writeChain(&b, "forward", "accept", forward)
	b.WriteString("}\n")
	return b.String(), nil
}

func suffix(fam string) string {
	if fam == "ip" {
		return "_v4"
	}
	return "_v6"
}

func writeSet(b *strings.Builder, name, typ string, interval bool, elements []string) {
	fmt.Fprintf(b, "\tset %s {\n\t\ttype %s\n", name, typ)
	if interval {
		b.WriteString("\t\tflags interval\n\t\tauto-merge\n")
	}
	if len(elements) > 0 {
		slices.Sort(elements)
		elements = slices.Compact(elements)
		fmt.Fprintf(b, "\t\telements = { %s }\n", strings.Join(elements, ", "))
	}
	b.WriteString("\t}\n")
}
