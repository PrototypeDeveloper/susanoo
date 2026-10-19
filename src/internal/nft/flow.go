package nft

import (
	"fmt"
	"strings"
)

// FlowTable は通信の記録（G5）のテーブルの名前。
const FlowTable = "susanoo_flow"

// FlowLog は、LAN から始まる TCP の接続の最初の数パケットを NFLOG で渡すルール。
// TLS の SNI と指紋、平文の HTTP の Host を取り出すのに使う。遮断より先に評価するので、
// 遮断された接続の SNI も記録できる。パケットの数え方には nf_conntrack_acct が必要。
type FlowLog struct {
	Family  Family // テーブルの種類（空なら inet。ブリッジ方式は bridge で、LAN はブリッジの LAN 側のポート）
	LAN     string
	Group   uint16   // NFLOG のグループ
	Ports   []uint16 // 対象のポート。既定 80 と 443
	Packets int      // 接続ごとに渡すパケットの数。既定 10
}

// Script はテーブルを作り直すスクリプトを返す。
func (f FlowLog) Script() (string, error) {
	if !ifacePattern.MatchString(f.LAN) {
		return "", fmt.Errorf("nft: インターフェースの名前 %q が不正です", f.LAN)
	}
	if f.Group == 0 {
		return "", fmt.Errorf("nft: NFLOG のグループがありません")
	}
	if err := f.Family.valid(); err != nil {
		return "", err
	}
	ports := portSet(f.Ports)
	if ports == "" {
		ports = "{ 80, 443 }"
	}
	packets := f.Packets
	if packets <= 0 {
		packets = 10
	}
	var b strings.Builder
	b.WriteString(replaceTableIn(f.Family, FlowTable))
	fmt.Fprintf(&b, "table %s %s {\n", f.Family, FlowTable)
	writeChainPriority(&b, "forward", "filter", "forward", "-20", "accept", []string{
		fmt.Sprintf("iifname %q tcp dport %s ct original packets < %d log group %d snaplen 4096", f.LAN, ports, packets+1, f.Group),
	})
	b.WriteString("}\n")
	return b.String(), nil
}
