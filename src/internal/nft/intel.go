package nft

import (
	"fmt"
	"net/netip"
	"strings"
)

// IntelTable は脅威情報（G7）のアドレスの遮断のテーブルの名前。
const IntelTable = "susanoo_intel"

// Intel は、LAN から脅威情報のアドレスへの転送を落とすルール。落とすパケットの一部（1 秒に 20 個まで）を
// NFLOG のグループ Group で渡し、どの機器が接続しようとしたかを記録できるようにする。
// 外部通信の制御（susanoo_egress）より先に評価する。新しい接続だけでなく、続いている接続も落とす。
type Intel struct {
	Family Family // テーブルの種類（空なら inet。ブリッジ方式は bridge で、LAN はブリッジの LAN 側のポート）
	LAN    string
	Group  uint16         // 0 なら NFLOG で渡さない
	Block  []netip.Prefix // 遮断するアドレスの範囲
}

// Script はテーブルを作り直すスクリプトを返す。遮断する範囲がなければ、テーブルを消す。
func (i Intel) Script() (string, error) {
	if !ifacePattern.MatchString(i.LAN) {
		return "", fmt.Errorf("nft: インターフェースの名前 %q が不正です", i.LAN)
	}
	if err := i.Family.valid(); err != nil {
		return "", err
	}
	v4, v6 := splitPrefixes(i.Block)
	if len(v4) == 0 && len(v6) == 0 {
		return DeleteTableIn(i.Family, IntelTable), nil
	}
	var b strings.Builder
	b.WriteString(replaceTableIn(i.Family, IntelTable))
	fmt.Fprintf(&b, "table %s %s {\n", i.Family, IntelTable)
	writeSet(&b, "block4", "ipv4_addr", true, v4)
	writeSet(&b, "block6", "ipv6_addr", true, v6)
	var rules []string
	for _, f := range []struct{ fam, set string }{{"ip", "block4"}, {"ip6", "block6"}} {
		match := fmt.Sprintf("iifname %q %s daddr @%s", i.LAN, f.fam, f.set)
		if i.Group != 0 {
			rules = append(rules, fmt.Sprintf("%s limit rate 20/second burst 40 packets log group %d snaplen 128", match, i.Group))
		}
		rules = append(rules, match+" drop")
	}
	writeChainPriority(&b, "forward", "filter", "forward", "-10", "accept", rules)
	b.WriteString("}\n")
	return b.String(), nil
}
