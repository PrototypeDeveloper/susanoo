// Package platform は CLIENT が使う OS の機能を抽象化する Platform インターフェースを定める。
//
// OS ごとに使える機能の差は Capabilities として申告し（C12）、CONTROLLER はそれを見て
// 端末ごとに期待できる検知と対応を判断する。プロセス単位の通信制御（C7）は v1 で追加する。
// GW の通信制御は Linux の nftables に固有のため、このインターフェースには含めない。
package platform

import (
	"context"
	"net/netip"
	"slices"

	"susanoo/internal/event"
	"susanoo/internal/policy"
)

// Capability は OS で使える機能の 1 つ。
type Capability string

const (
	CapProcessEvents Capability = "process_events" // プロセスの起動・終了の監視（C1）
	CapNetworkEvents Capability = "network_events" // 接続と発信元プロセスの監視（C2）
	CapFileEvents    Capability = "file_events"    // 重要なファイルの変更の監視（C3）
	CapHoneytoken    Capability = "honeytoken"     // おとりへの接触の検知（C5）
	CapIsolation     Capability = "isolation"      // ホストのファイアウォールによる自己隔離（C6）
)

// Capabilities は OS と、使える機能の一覧。
type Capabilities struct {
	OS       string       `json:"os"`
	Arch     string       `json:"arch"`
	Kernel   string       `json:"kernel,omitempty"`
	Features []Capability `json:"features"`
}

// Has は機能 f が使えるかどうかを返す。
func (c Capabilities) Has(f Capability) bool { return slices.Contains(c.Features, f) }

// Isolation は自己隔離の指示。
type Isolation struct {
	Level policy.IsolationLevel
	// Management は隔離中も許可する管理通信の宛先（CONTROLLER と GW）。Level が full のときは使わない。
	Management []netip.AddrPort
	// Updates は Level が management_and_updates のときに許可する更新サーバー。
	Updates []netip.Prefix
}

// Platform は OS の機能。実装は OS ごとに用意する。
type Platform interface {
	// Capabilities は使える機能を返す。
	Capabilities() Capabilities
	// Watch はイベントを out に送り続け、ctx が終わるか回復できないエラーが起きたら返る。
	Watch(ctx context.Context, out chan<- event.Event) error
	// Isolate はホストのファイアウォールで自己隔離する。隔離中に呼ぶと指示を置き換える。
	Isolate(ctx context.Context, iso Isolation) error
	// Release は自己隔離を解除する。隔離していなければ何もしない。
	Release(ctx context.Context) error
	// IsolationActive は自己隔離のルールが有効かを返す。ルールが消されていないかを確かめるのに使う（C10）。
	IsolationActive(ctx context.Context) (bool, error)
}
