package nft

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// AppsTable は CLIENT のプロセス単位の通信の制御（C7）のテーブル。
const AppsTable = "susanoo_apps"

// AppsDenyMark は、拒否する接続の最初のパケットに付ける印。CLIENT が NFQUEUE の判断でこの印を付けてパケットを戻すと（NF_REPEAT）、
// テーブルの先頭のルールで拒否を返す（接続しようとしたアプリはすぐに失敗を知る）。
const AppsDenyMark = 0x53550001

// AppsQueue は既定の NFQUEUE の番号。
const AppsQueue = 4242

// AppControl は CLIENT のプロセス単位の通信の制御のルール。外向きの新しい TCP と UDP の接続の最初のパケットを NFQUEUE に渡し、
// CLIENT がプロセスを調べて判断する。CLIENT が止まっていると、パケットは判断を待たずに通る（bypass。障害時に端末の通信を止めない）。
type AppControl struct {
	Queue  uint16       // NFQUEUE の番号
	Exempt []netip.Addr // 制御しない宛先（CONTROLLER と GW。管理通信と DNS）
}

// Script はテーブルを作り直すスクリプトを返す。
func (a AppControl) Script() (string, error) {
	if a.Queue == 0 {
		return "", errors.New("nft: NFQUEUE の番号がありません")
	}
	var v4, v6 []string
	for _, e := range a.Exempt {
		if !e.IsValid() {
			return "", fmt.Errorf("nft: 制御しない宛先 %v が不正です", e)
		}
		fam, s := family(e)
		if fam == "ip" {
			v4 = append(v4, s)
		} else {
			v6 = append(v6, s)
		}
	}
	slices.Sort(v4)
	slices.Sort(v6)
	rules := []string{
		fmt.Sprintf("meta mark 0x%08x meta l4proto tcp reject with tcp reset", AppsDenyMark),
		fmt.Sprintf("meta mark 0x%08x reject with icmpx admin-prohibited", AppsDenyMark),
		`oif "lo" accept`,
	}
	if len(v4) > 0 {
		rules = append(rules, fmt.Sprintf("ip daddr { %s } accept", strings.Join(slices.Compact(v4), ", ")))
	}
	if len(v6) > 0 {
		rules = append(rules, fmt.Sprintf("ip6 daddr { %s } accept", strings.Join(slices.Compact(v6), ", ")))
	}
	rules = append(rules,
		"ip daddr { 224.0.0.0/4, 255.255.255.255, 169.254.0.0/16 } accept",
		"ip6 daddr { fe80::/10, ff00::/8 } accept",
		fmt.Sprintf("meta l4proto { tcp, udp } ct state new queue num %d bypass", a.Queue),
	)
	var b strings.Builder
	b.WriteString(replaceTable(AppsTable))
	fmt.Fprintf(&b, "table inet %s {\n", AppsTable)
	b.WriteString("\tchain output {\n")
	// 自己隔離（優先度 -10）の後に評価する。どちらかで落とせば落ちる。
	b.WriteString("\t\ttype filter hook output priority 5; policy accept;\n")
	for _, r := range rules {
		fmt.Fprintf(&b, "\t\t%s\n", r)
	}
	b.WriteString("\t}\n}\n")
	return b.String(), nil
}
