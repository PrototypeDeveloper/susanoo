// Package platform は CLIENT が使う OS の機能を抽象化する Platform インターフェースを定める。
//
// OS ごとに使える機能の差は Capabilities として申告し（C12）、CONTROLLER はそれを見て
// 端末ごとに期待できる検知と対応を判断する。証拠の保全（C11）とプロセス単位の通信制御（C7）は、
// それぞれ Collector と AppFirewall を満たす Platform だけが行う。資源の上限（2l）と時刻の同期の確認は、
// Resources と Clock を満たす Platform だけが行う。
// GW の通信制御は Linux の nftables に固有のため、このインターフェースには含めない。
package platform

import (
	"context"
	"net/netip"
	"slices"
	"time"

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
	CapKernelModules Capability = "kernel_modules" // カーネルモジュールの読み込みの監視（C4）
	CapEvidence      Capability = "evidence"       // 隔離のときの証拠の保全（C11）
	CapAppControl    Capability = "app_control"    // プロセス単位の通信の制御（C7）
	CapLogons        Capability = "logons"         // ログオンとログオフ、失敗したログオンの記録（C4）
)

// AppFirewall はプロセス単位の通信の制御（C7）ができる Platform。
type AppFirewall interface {
	// SetAppControl は制御のルールを置き換える。ac が nil なら制御をやめる。exempt の宛先（CONTROLLER など）は制御しない。
	SetAppControl(ctx context.Context, ac *policy.AppControl, exempt []netip.Addr) error
}

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

// Snapshot は、ある時点の端末の状態の記録（証拠の保全、C11）。集められなかったものは Errors に書く。
type Snapshot struct {
	Processes   []SnapshotProcess `json:"processes"`
	Connections []SnapshotConn    `json:"connections"`
	Modules     []string          `json:"modules,omitempty"` // 読み込まれているカーネルモジュール
	Logs        []SnapshotLog     `json:"logs,omitempty"`    // ログの末尾
	Errors      []string          `json:"errors,omitempty"`
}

// SnapshotProcess は動いているプロセス。
type SnapshotProcess struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	UID     string `json:"uid,omitempty"`
	Name    string `json:"name,omitempty"`
	Exe     string `json:"exe,omitempty"`
	CmdLine string `json:"cmd_line,omitempty"`
	Started int64  `json:"started,omitempty"` // 起動した時刻（UNIX 時間のミリ秒）
}

// SnapshotConn はソケット（接続と待ち受け）と、持ち主のプロセス。
type SnapshotConn struct {
	Proto   string `json:"proto"` // tcp、udp
	State   string `json:"state"` // established、listen など
	Local   string `json:"local"`
	Remote  string `json:"remote,omitempty"`
	PID     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
	UID     string `json:"uid,omitempty"`
}

// SnapshotLog はログのファイルの末尾。
type SnapshotLog struct {
	Path      string   `json:"path"`
	Lines     []string `json:"lines"`
	Truncated bool     `json:"truncated,omitempty"` // 先頭を省いた
}

// Collector は証拠を集められる Platform（C11）。
type Collector interface {
	// Snapshot は今の端末の状態を集める。一部を集められなくても、集めた分を返す。
	Snapshot(ctx context.Context) (*Snapshot, error)
}

// Usage は CLIENT の資源の使用量（2l）。
type Usage struct {
	CPU     time.Duration // 動いているプロセス（CLIENT と、その子）が使った CPU の時間の合計
	Memory  int64         // 実メモリ（RSS）の合計（バイト）
	Dropped uint64        // 監視を間引いている間に捨てたイベントの数（起動してから）
}

// Resources は CLIENT の資源の使用量を測り、上限を超えたときに監視を間引ける Platform（2l）。
type Resources interface {
	// Usage は今の資源の使用量を返す。
	Usage() (Usage, error)
	// SetThrottle は監視の間引きを始めるかやめる。間引いている間も、検知結果のイベントは捨てない。
	SetThrottle(on bool)
}

// Clock は時刻の同期の状態を返せる Platform（2l）。
type Clock interface {
	// ClockSynchronized は、OS の時刻が NTP などで同期しているかを返す。
	ClockSynchronized() (bool, error)
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
