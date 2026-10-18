// Package gw は GW モードの機能をまとめる。
//
//   - 端末単位の遮断（G9）：アドレスと MAC アドレスの両方で遮断する
//   - ルーター方式（G1）：NAT、転送の制限、GW 自身の保護（G12）
//   - LAN の監視（G8）：ARP の観測と、機器が LAN にいるかの確認
//
// 遮断のルールはカーネルの nftables に入るので、susanoo のプロセスが止まっても遮断は続く。
// 停止時にもルールは消さない（障害で止まった場合と同じく、隔離した端末を通さない）。
package gw

import (
	"context"
	"net/netip"
	"sync"

	"susanoo/internal/nft"
	"susanoo/internal/policy"
)

// Enforcer は nftables で端末を遮断する。controller.Enforcer を満たす。
type Enforcer struct {
	NFT            nft.Runner
	ManagementPort uint16         // GW 上の CONTROLLER の待ち受けポート
	Updates        []netip.Prefix // 隔離中も許可する更新サーバー

	mu      sync.Mutex
	created bool // テーブルを作った後か
}

// Sync は遮断する端末の一覧を、アドレス addrs と MAC アドレス macs に置き換える。
// 最初はテーブルを作り、その後は集合だけを入れ替えて、DNS で得た更新サーバーのアドレスを保つ。
// 集合の入れ替えに失敗したら（テーブルが消されていたなど）、テーブルを作り直す。
func (e *Enforcer) Sync(ctx context.Context, addrs map[netip.Addr]policy.IsolationLevel, macs map[string]policy.IsolationLevel) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	rules := nft.GWIsolation{ManagementPort: e.ManagementPort, Addrs: addrs, MACs: macs, Updates: e.Updates}
	if e.created {
		script, err := rules.SetsScript()
		if err != nil {
			return err
		}
		if err := e.NFT.Run(ctx, script); err == nil {
			return nil
		}
	}
	script, err := rules.Script()
	if err != nil {
		return err
	}
	if err := e.NFT.Run(ctx, script); err != nil {
		return err
	}
	e.created = true
	return nil
}

// SetUpdates は、隔離中も許可する更新サーバーを置き換える（ポリシーを切り替えたとき）。次の Sync から使う。
func (e *Enforcer) SetUpdates(updates []netip.Prefix) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Updates = updates
}
