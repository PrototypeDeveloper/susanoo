// Package api は CLIENT、ctl と CONTROLLER の間でやり取りするデータの形を定める。
//
// 通信は相互TLS上の HTTP/2 で、本文は JSON。CLIENT がハートビートとイベントを送ると、
// CONTROLLER はその端末に期待する状態（隔離するかどうか）を署名付きの指示として返す。
// 指示は「状態」を表すので、途中の指示が失われても次の応答で正しい状態に収束する。
package api

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"susanoo/internal/event"
	"susanoo/internal/platform"
	"susanoo/internal/policy"
	"susanoo/internal/sign"
)

// API のパス。
const (
	PathHeartbeat = "/v1/heartbeat"
	PathEvents    = "/v1/events" // CLIENT は POST でイベントを送り、管理者は GET で検索する（EventQuery の項目をクエリに書く）
	PathDevices   = "/v1/devices"
	PathHosts     = "/v1/hosts"
	PathLearned   = "/v1/learned"
	// PathCertificate は CLIENT が自分の証明書を更新する（M1）。本文はなし。応答は CertificateResponse。
	PathCertificate = "/v1/certificate"
	// PathStatus は全体の状態（M8）。応答は Status。
	PathStatus = "/v1/status"
	// PathPolicy はポリシーの配布と版の管理（M2）。GET で PolicyInfo、POST で PolicyPush を受け付ける。
	// PathPolicy+"/versions/{版数}" で版の中身、PathPolicy+"/promote" と "/abort" で先行適用を全体に広げるか取り消す。
	PathPolicy = "/v1/policy"
	// PathRules は検知ルールの配布と版の管理（M3）。GET で RulesInfo、POST で RulesPush を受け付ける。
	// PathRules+"/versions/{版数}" で版の中身。
	PathRules = "/v1/rules"
	// PathIntel は脅威情報の配布（G7）。GET で IntelInfo、POST で IntelPush を受け付ける。
	// PathIntel+"/payload" で今の版の中身（intel.Set）、PathIntel+"/check?q=名前かアドレス" で照合の結果（[]IntelMatch）。
	PathIntel = "/v1/intel"
	// PathEvidence は証拠の保全（C11）。CLIENT は POST で EvidenceUpload を送り、管理者は GET で一覧（[]EvidenceInfo。
	// ?device=端末 で絞る）を見る。PathEvidence+"/{端末}/{ID}" で中身（Evidence。?signed=1 なら署名付きのまま）。
	// 証拠を集めさせるのは PathDevices+"/{端末}/evidence" への POST。
	PathEvidence = "/v1/evidence"
	// PathNotifyTest は試験の通知を送る（M7）。応答は []NotifyResult。
	PathNotifyTest = "/v1/notify/test"
	// PathLearnedSuggest は学習した名前から作った許可リストの案（G2）。?group=グループ&min=回数。応答は AllowSuggestion。
	PathLearnedSuggest = "/v1/learned/suggest"
	// PathIncidents はインシデント対応の支援（M9）。GET で一覧（[]Incident。?all=1 なら閉じたものも）、POST で開く（IncidentOpen）。
	// PathIncidents+"/{ID}" の GET で中身、POST で変える（IncidentUpdate）。"/{ID}/steps/{手順}" の POST で手順の状態を変える
	// （StepUpdate）。"/{ID}/timeline" の GET で時系列（[]TimelineEntry。?all=1 ならすべての種類のイベント、?before=24h で
	// 開く前のどこから並べるか）。
	PathIncidents = "/v1/incidents"
)

// MaxBodyBytes は要求の本文の上限。
const MaxBodyBytes = 1 << 20

// MaxIntelBytes は脅威情報の配布と中身の取得の、本文の上限（一覧が大きいため、ほかの要求より大きくする）。
const MaxIntelBytes = 8 << 20

// MaxEvidenceBytes は証拠の送信の本文の上限（中身の上限 MaxEvidencePayload を署名して base64 にした大きさに収まる）。
const MaxEvidenceBytes = 8 << 20

// MaxEvidencePayload は証拠の中身（Evidence の JSON）の上限。超えるときは CLIENT がログ、プロセスの順に削る。
const MaxEvidencePayload = 4 << 20

// MaxEventsPerBatch は 1 回で送れるイベントの上限。
const MaxEventsPerBatch = 500

// Heartbeat は CLIENT の生存通知（G10、C10）。端末の鍵で署名して送る（sign.PurposeHeartbeat）。
//
// 同じ起動の間は Counter を 1 ずつ増やす。CLIENT が起動し直すと BootID が変わり、Counter は 1 に戻る。
type Heartbeat struct {
	DeviceID     string                `json:"device_id"`
	BootID       string                `json:"boot_id"`
	Counter      uint64                `json:"counter"`
	Time         time.Time             `json:"time"`
	Hostname     string                `json:"hostname,omitempty"`
	Applied      uint64                `json:"applied"`               // 適用済みの指示の版数
	Isolation    policy.IsolationLevel `json:"isolation,omitempty"`   // 今の自己隔離の状態（空なら隔離していない）
	AppControl   policy.AppMode        `json:"app_control,omitempty"` // 効いているプロセス単位の通信の制御の扱い（C7。空なら効いていない）
	Capabilities platform.Capabilities `json:"capabilities"`
}

// EventBatch は CLIENT が送るイベントのまとまり。
type EventBatch struct {
	Events []event.Event `json:"events"`
}

// Desired はハートビートとイベントへの応答。Command は CONTROLLER の鍵による署名付きの Command。
type Desired struct {
	Command sign.Envelope `json:"command"`
}

// Command は端末に期待する状態（sign.PurposeCommand で署名する）。
//
// Version は状態が変わるたびに増える。CLIENT は適用済みの版数より新しい指示だけを適用する。
// DeviceID を含めるので、ほかの端末への指示を使い回すことはできない。
type Command struct {
	DeviceID  string                `json:"device_id"`
	Version   uint64                `json:"version"`
	Isolation policy.IsolationLevel `json:"isolation,omitempty"` // 空なら隔離しない
	Updates   []netip.Prefix        `json:"updates,omitempty"`   // 隔離中も許可する更新サーバー
	Evidence  uint64                `json:"evidence,omitempty"`  // 証拠を集める要求の番号。適用済みより大きければ集める（C11）
	Apps      *policy.AppControl    `json:"apps,omitempty"`      // プロセス単位の通信の制御（C7。端末のグループの設定。なければ制御しない）
	IssuedAt  time.Time             `json:"issued_at"`
}

// 証拠を集めたきっかけ（Evidence.Reason）。
const (
	EvidenceReasonIsolation = "isolation" // 隔離の指示を受けた
	EvidenceReasonRequest   = "request"   // 管理者が求めた（ctl evidence collect）
)

// Evidence は CLIENT の執行部が集めた証拠（C11）。端末の鍵で署名して送る（sign.PurposeEvidence）。
type Evidence struct {
	DeviceID  string                `json:"device_id"`
	ID        string                `json:"id"` // 証拠の ID（crypto/rand.Text の形）
	Time      time.Time             `json:"time"`
	Reason    string                `json:"reason"`  // EvidenceReason*
	Command   uint64                `json:"command"` // きっかけになった指示の版数
	Isolation policy.IsolationLevel `json:"isolation,omitempty"`
	Hostname  string                `json:"hostname,omitempty"`
	Snapshot  platform.Snapshot     `json:"snapshot"`
}

// EvidenceUpload は CLIENT が送る証拠。
type EvidenceUpload struct {
	Envelope sign.Envelope `json:"envelope"` // sign.PurposeEvidence で署名した Evidence
}

// EvidenceInfo は CONTROLLER が保存した証拠の概要。
type EvidenceInfo struct {
	Device      string    `json:"device"`
	ID          string    `json:"id"`
	Time        time.Time `json:"time"`     // 端末が集めた時刻
	Received    time.Time `json:"received"` // CONTROLLER が受け取った時刻
	Reason      string    `json:"reason"`
	SHA256      string    `json:"sha256"` // 中身（署名した JSON）のハッシュ。監査ログにも記録する
	Bytes       int       `json:"bytes"`
	Processes   int       `json:"processes"`
	Connections int       `json:"connections"`
	Logs        int       `json:"logs"`
}

// インシデントの状態。
const (
	IncidentOpen   = "open"
	IncidentClosed = "closed"
)

// 手順の状態。
const (
	StepTodo    = "todo"
	StepDone    = "done"
	StepSkipped = "skipped"
)

// Incident はインシデント（M9）。
type Incident struct {
	ID             string         `json:"id"`
	Title          string         `json:"title"`
	Devices        []string       `json:"devices"` // 端末 ID か、CLIENT のない機器の MAC アドレス
	Status         string         `json:"status"`  // open、closed
	Opened         time.Time      `json:"opened"`
	OpenedBy       string         `json:"opened_by"`
	KnownAt        time.Time      `json:"known_at"` // 事態を知った時刻（報告の期限の起算点）
	Closed         time.Time      `json:"closed,omitzero"`
	PersonalData   bool           `json:"personal_data,omitempty"`  // 個人情報の漏えい等のおそれがある
	Malicious      bool           `json:"malicious,omitempty"`      // 不正の目的をもって行われたおそれがある（確報の期限が 60 日になる）
	PrelimReported time.Time      `json:"prelim_reported,omitzero"` // 個人情報保護委員会に速報した時刻
	FinalReported  time.Time      `json:"final_reported,omitzero"`  // 確報した時刻
	Steps          []IncidentStep `json:"steps"`
	Deadlines      []Deadline     `json:"deadlines,omitempty"` // 個人情報の漏えい等のおそれがあるときの報告の期限の目安
	Notes          []IncidentNote `json:"notes,omitempty"`
}

// IncidentStep は対応の手順の 1 つ。
type IncidentStep struct {
	ID     string    `json:"id"`
	Title  string    `json:"title"`
	Guide  string    `json:"guide"`
	Status string    `json:"status"`         // todo、done、skipped
	Auto   bool      `json:"auto,omitempty"` // 状態から自動で済みにする手順
	By     string    `json:"by,omitempty"`
	At     time.Time `json:"at,omitzero"`
	Note   string    `json:"note,omitempty"`
}

// Deadline は報告の期限の目安。
type Deadline struct {
	Name string    `json:"name"`          // 速報、確報
	From time.Time `json:"from,omitzero"` // 目安の期間の始まり（速報の「概ね 3〜5 日」の 3 日目）
	Due  time.Time `json:"due"`           // 期限
	Done time.Time `json:"done,omitzero"` // 報告した時刻
}

// IncidentNote はインシデントの記録。
type IncidentNote struct {
	At   time.Time `json:"at"`
	By   string    `json:"by"`
	Text string    `json:"text"`
}

// IncidentOpenRequest はインシデントを開く要求。
type IncidentOpenRequest struct {
	Title        string    `json:"title"`
	Devices      []string  `json:"devices"`
	KnownAt      time.Time `json:"known_at,omitzero"` // 省略すると今
	PersonalData bool      `json:"personal_data,omitempty"`
	Malicious    bool      `json:"malicious,omitempty"`
	Note         string    `json:"note,omitempty"`
}

// IncidentUpdate はインシデントを変える要求。書いた項目だけを変える。
type IncidentUpdate struct {
	Title          *string    `json:"title,omitempty"`
	KnownAt        *time.Time `json:"known_at,omitempty"`
	PersonalData   *bool      `json:"personal_data,omitempty"`
	Malicious      *bool      `json:"malicious,omitempty"`
	PrelimReported *time.Time `json:"prelim_reported,omitempty"` // ゼロの時刻なら取り消す
	FinalReported  *time.Time `json:"final_reported,omitempty"`
	Note           string     `json:"note,omitempty"`   // 記録を足す
	Status         string     `json:"status,omitempty"` // open か closed にする
}

// StepUpdate は手順の状態を変える要求。
type StepUpdate struct {
	Status string `json:"status"` // todo、done、skipped
	Note   string `json:"note,omitempty"`
}

// TimelineEntry は時系列の 1 件。
type TimelineEntry struct {
	Time     time.Time      `json:"time"`
	Source   string         `json:"source"` // event、audit、evidence
	Kind     string         `json:"kind"`   // イベントの種類、監査ログの操作など
	Device   string         `json:"device,omitempty"`
	Severity event.Severity `json:"severity,omitempty"`
	Summary  string         `json:"summary"`
}

// LearningGroup は学習モードのグループの状態（G2）。
type LearningGroup struct {
	Group   string    `json:"group"`
	Started time.Time `json:"started"` // 学習モードになった時刻
	Ends    time.Time `json:"ends"`    // 期間が終わる時刻
	Due     bool      `json:"due"`     // 期間が終わった（原則拒否に移るかを決める時期）
	Learned int       `json:"learned"` // 学習した（通した）名前の数
	Blocked int       `json:"blocked"` // 拒否リストで遮断した名前の数
}

// AllowSuggestion は、学習した名前から作った許可リストの案（G2）。
type AllowSuggestion struct {
	Group    string                 `json:"group"`
	Started  time.Time              `json:"started,omitzero"` // 学習モードになった時刻（分からなければ空）
	MinCount int                    `json:"min_count"`        // 案に入れた名前の、問い合わせの回数の下限
	Allow    []SuggestedDestination `json:"allow"`
	Excluded []ExcludedName         `json:"excluded,omitempty"`
}

// SuggestedDestination は許可リストの案の 1 件。
type SuggestedDestination struct {
	Domain   string   `json:"domain"`             // 名前か「*.」で始まる名前
	Count    int      `json:"count"`              // 問い合わせの回数の合計
	Names    int      `json:"names"`              // まとめた名前の数
	Examples []string `json:"examples,omitempty"` // まとめた名前の例
}

// ExcludedName は案に入れなかった名前と理由。
type ExcludedName struct {
	Domain string `json:"domain"`
	Reason string `json:"reason"`
}

// IncidentCounts は全体の状態に載せるインシデントの数と、最も近い報告の期限。
type IncidentCounts struct {
	Open int               `json:"open"`
	Next *IncidentDeadline `json:"next,omitempty"`
}

// IncidentDeadline はインシデントの報告の期限。
type IncidentDeadline struct {
	Incident string    `json:"incident"`
	Name     string    `json:"name"`
	Due      time.Time `json:"due"`
}

// NotifyResult は試験の通知の結果（M7）。
type NotifyResult struct {
	Name  string `json:"name"`
	Error string `json:"error,omitempty"` // 空なら送れた
}

// NotifyStatus は通知の宛先ごとの送信の状況（M7）。
type NotifyStatus struct {
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Sent       int64     `json:"sent"`
	Failed     int64     `json:"failed"`
	Suppressed int64     `json:"suppressed"`
	LastSent   time.Time `json:"last_sent,omitzero"`
	LastError  string    `json:"last_error,omitempty"`
	LastFailed time.Time `json:"last_failed,omitzero"`
}

// Device は ctl に返す端末の状態。
type Device struct {
	ID         string                `json:"id"`
	Group      string                `json:"group"`
	Addr       string                `json:"addr,omitempty"`
	Hostname   string                `json:"hostname,omitempty"`
	MACs       []string              `json:"macs,omitempty"` // 結び付いた LAN の機器
	LastSeen   time.Time             `json:"last_seen"`
	Isolation  policy.IsolationLevel `json:"isolation,omitempty"`   // 指示している隔離
	Applied    policy.IsolationLevel `json:"applied,omitempty"`     // CLIENT が報告した自己隔離の状態
	Reason     string                `json:"reason,omitempty"`      // 隔離の理由
	Since      time.Time             `json:"since,omitzero"`        // 隔離した時刻
	Pending    string                `json:"pending,omitempty"`     // 承認待ちの隔離の理由
	Away       bool                  `json:"away,omitempty"`        // ハートビートが途絶え、LAN にもいない（不在）
	Features   []platform.Capability `json:"features,omitempty"`    // CLIENT が申告した機能
	CertExpiry time.Time             `json:"cert_expiry,omitzero"`  // 端末が最後に示した証明書の有効期限
	Revoked    time.Time             `json:"revoked,omitzero"`      // 証明書を失効させた時刻（それより前に発行した証明書は使えない）
	Risk       int                   `json:"risk,omitempty"`        // 危険度（M5）
	AppControl policy.AppMode        `json:"app_control,omitempty"` // CLIENT が報告した、効いているプロセス単位の通信の制御の扱い（C7）
}

// CertificateResponse は更新した証明書。
type CertificateResponse struct {
	Certificate []byte   `json:"certificate"`     // DER
	Chain       [][]byte `json:"chain,omitempty"` // 連ねる認証局の証明書（二段構えの発行用の認証局。DER）
}

// Host は ctl に返す LAN の機器の状態（G8）。
type Host struct {
	MAC       string                `json:"mac"`
	IP        string                `json:"ip,omitempty"`
	Hostname  string                `json:"hostname,omitempty"`
	Group     string                `json:"group"`               // グループ（端末に結び付いた機器は端末のグループ）
	DeviceID  string                `json:"device_id,omitempty"` // 結び付いた端末（CLIENT のない機器は空）
	FirstSeen time.Time             `json:"first_seen"`
	LastSeen  time.Time             `json:"last_seen"`
	Lease     time.Time             `json:"lease,omitzero"` // DHCP の割り当ての期限
	Isolation policy.IsolationLevel `json:"isolation,omitempty"`
	Reason    string                `json:"reason,omitempty"`
	Since     time.Time             `json:"since,omitzero"`
	Pending   string                `json:"pending,omitempty"`
	Risk      int                   `json:"risk,omitempty"` // 危険度（M5。端末に結び付いた機器は端末の危険度）
}

// Learned は、学習モードで通した名前と、遮断した名前の記録（G2）。許可リストを作るときに使う。
type Learned struct {
	Group   string    `json:"group"`
	Domain  string    `json:"domain"`
	Blocked bool      `json:"blocked"`
	Count   int       `json:"count"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
}

// GroupRequest は ctl からのグループの割り当て。
type GroupRequest struct {
	Group string `json:"group"`
}

// IsolateRequest は ctl からの隔離の指示。Level を省略するとグループのポリシーに従う。
type IsolateRequest struct {
	Level  policy.IsolationLevel `json:"level,omitempty"`
	Reason string                `json:"reason,omitempty"`
}

// Error はエラーの応答。
type Error struct {
	Error string `json:"error"`
}

// PolicyPush は署名付きのポリシーの配布。CanaryDevices か CanaryGroups があれば、その端末にだけ先に適用する。
type PolicyPush struct {
	Envelope      sign.Envelope `json:"envelope"`                 // sign.PurposePolicy で署名したポリシー
	CanaryDevices []string      `json:"canary_devices,omitempty"` // 先行適用する端末 ID か MAC アドレス
	CanaryGroups  []string      `json:"canary_groups,omitempty"`  // 先行適用するグループ（その端末と機器すべて）
}

// PolicyVersion はポリシーの版の概要。
type PolicyVersion struct {
	Version   int       `json:"version"`
	Name      string    `json:"name"`
	IssuedAt  time.Time `json:"issued_at"`
	AppliedAt time.Time `json:"applied_at,omitzero"` // CONTROLLER が受け付けた時刻
}

// PolicyCanary は先行適用の状態。
type PolicyCanary struct {
	PolicyVersion
	Devices []string `json:"devices,omitempty"`
	Groups  []string `json:"groups,omitempty"`
}

// PolicyInfo はポリシーの状態。
type PolicyInfo struct {
	Current  PolicyVersion   `json:"current"`
	Canary   *PolicyCanary   `json:"canary,omitempty"`
	Versions []PolicyVersion `json:"versions"` // CONTROLLER が受け付けたすべての版（古い順）
}

// Status は全体の状態（M8）。
type Status struct {
	Version        string          `json:"version"`
	StartedAt      time.Time       `json:"started_at"`
	Response       policy.Response `json:"response"` // 今の版の対応の方式
	Policy         PolicyVersion   `json:"policy"`
	Canary         *PolicyCanary   `json:"canary,omitempty"`
	CertExpiry     time.Time       `json:"cert_expiry"`             // CONTROLLER の証明書の期限
	IssuerExpiry   *time.Time      `json:"issuer_expiry,omitempty"` // 二段構えの発行用の認証局の証明書の期限（ctl root sign-issuer で更新する）
	Devices        DeviceCounts    `json:"devices"`
	Hosts          HostCounts      `json:"hosts"`
	ExpiringCerts  []Device        `json:"expiring_certs,omitempty"`  // 証明書の期限が近いのに更新していない端末
	RecentFindings []event.Event   `json:"recent_findings,omitempty"` // 最近の検知（古い順）
	Rules          RulesVersion    `json:"rules"`                     // 検知ルールの今の版（版数 0 は既定のルールだけ）
	Intel          IntelInfo       `json:"intel"`                     // 脅威情報の今の版
	Risky          []Risk          `json:"risky,omitempty"`           // 危険度の高い端末と機器（高い順）
	Notify         []NotifyStatus  `json:"notify,omitempty"`          // 通知の宛先ごとの送信の状況
	Incidents      IncidentCounts  `json:"incidents"`                 // 開いているインシデント（M9）
	Learning       []LearningGroup `json:"learning,omitempty"`        // 学習モードのグループ（G2）
}

// RulesPush は署名付きの検知ルールの配布（M3）。
type RulesPush struct {
	Envelope sign.Envelope `json:"envelope"` // sign.PurposeRules で署名した検知ルール
}

// RulesVersion は検知ルールの版の概要。
type RulesVersion = PolicyVersion

// RulesInfo は検知ルールの状態。
type RulesInfo struct {
	Current    RulesVersion   `json:"current"`  // 版数 0 は既定のルールだけ
	Versions   []RulesVersion `json:"versions"` // 受け付けたすべての版（古い順）
	HalfLife   string         `json:"half_life"`
	Exceptions int            `json:"exceptions"` // 誤検知の例外の数
	Rules      []RuleStatus   `json:"rules"`
}

// RuleStatus は検知ルールの設定と、当てはまった回数（CONTROLLER を起動してから。ctl rules stats で表示する）。
type RuleStatus struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Mode      string    `json:"mode"` // enforce、monitor、off
	Score     int       `json:"score"`
	Target    string    `json:"target"`            // 対象（finding:honeytoken、dns など）
	Default   bool      `json:"default,omitempty"` // 既定のルール（配布したルールで置き換えていない）
	Groups    []string  `json:"groups,omitempty"`
	Hits      int64     `json:"hits"`      // 当てはまって危険度に加えた回数
	Monitored int64     `json:"monitored"` // 試験運用（monitor）で当てはまった回数
	Excepted  int64     `json:"excepted"`  // 例外に当てはまった回数
	Last      time.Time `json:"last,omitzero"`
}

// IntelPush は署名付きの脅威情報の配布（G7）。
type IntelPush struct {
	Envelope sign.Envelope `json:"envelope"` // sign.PurposeIntel で署名した脅威情報
}

// IntelInfo は脅威情報の状態（一覧の中身は含めない）。
type IntelInfo struct {
	Version  int             `json:"version"` // 0 は脅威情報なし
	IssuedAt time.Time       `json:"issued_at,omitzero"`
	Lists    []IntelListInfo `json:"lists"`
}

// IntelListInfo は一覧の概要。
type IntelListInfo struct {
	Name    string    `json:"name"`
	Action  string    `json:"action"` // block、alert
	Source  string    `json:"source,omitempty"`
	Updated time.Time `json:"updated"`
	Domains int       `json:"domains"`
	CIDRs   int       `json:"cidrs"`
}

// IntelMatch は照合の結果。
type IntelMatch struct {
	List      string `json:"list"`
	Action    string `json:"action"`
	Indicator string `json:"indicator"` // 一覧に載っていたドメインかアドレスの範囲
}

// Risk は端末か機器の危険度（M5）。
type Risk struct {
	Target    string   `json:"target"`         // 端末 ID か、CLIENT のない機器の MAC アドレス
	Host      bool     `json:"host,omitempty"` // CLIENT のない機器
	Score     int      `json:"score"`
	Threshold int      `json:"threshold"`       // 自動対応する危険度（グループの設定）
	Rules     []string `json:"rules,omitempty"` // 最近加えたルールの ID（新しい順）
}

// DeviceCounts は端末の台数。
type DeviceCounts struct {
	Total    int `json:"total"`
	Online   int `json:"online"`   // ハートビートが届いている
	Isolated int `json:"isolated"` // 隔離中
	Pending  int `json:"pending"`  // 隔離の承認待ち
	Away     int `json:"away"`     // 不在
	Revoked  int `json:"revoked"`  // 証明書を失効させた
}

// HostCounts は LAN の機器の台数。
type HostCounts struct {
	Total        int `json:"total"`
	Unregistered int `json:"unregistered"` // CLIENT のない機器
	Isolated     int `json:"isolated"`     // 機器として隔離中（CLIENT のない機器）
	Pending      int `json:"pending"`
}

// EventClasses は、イベントの検索で使う種類の名前と OCSF のクラス。
var EventClasses = map[string]event.ClassUID{
	"file":    event.ClassFileSystemActivity,
	"process": event.ClassProcessActivity,
	"finding": event.ClassDetectionFinding,
	"network": event.ClassNetworkActivity,
	"dns":     event.ClassDNSActivity,
	"dhcp":    event.ClassDHCPActivity,
}

// Severities は、イベントの検索で使う重大度の名前。
var Severities = map[string]event.Severity{
	"info":     event.SeverityInformational,
	"low":      event.SeverityLow,
	"medium":   event.SeverityMedium,
	"high":     event.SeverityHigh,
	"critical": event.SeverityCritical,
}

// EventQuery はイベントの検索の条件（GET PathEvents のクエリ）。空の項目は条件にしない。
type EventQuery struct {
	Device   string    // 端末 ID、アドレス、MAC アドレス、ホスト名のどれか
	Class    string    // EventClasses の名前か、OCSF のクラスの番号
	Severity string    // この重大度以上（Severities の名前か番号）
	Since    time.Time // この時刻以降
	Until    time.Time // この時刻以前
	Text     string    // 含む文字列
	Limit    int       // 新しいものからこの件数まで（既定 100、最大 MaxEventQuery）
}

// MaxEventQuery は 1 回の検索で返すイベントの上限。
const MaxEventQuery = 1000

// Values は検索の条件を URL のクエリにする。
func (q EventQuery) Values() url.Values {
	v := url.Values{}
	set := func(k, s string) {
		if s != "" {
			v.Set(k, s)
		}
	}
	set("device", q.Device)
	set("class", q.Class)
	set("severity", q.Severity)
	set("q", q.Text)
	if !q.Since.IsZero() {
		v.Set("since", q.Since.UTC().Format(time.RFC3339Nano))
	}
	if !q.Until.IsZero() {
		v.Set("until", q.Until.UTC().Format(time.RFC3339Nano))
	}
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	return v
}

// ParseEventQuery は URL のクエリから検索の条件を読み、確かめる。
func ParseEventQuery(v url.Values) (EventQuery, error) {
	q := EventQuery{Device: v.Get("device"), Class: v.Get("class"), Severity: v.Get("severity"), Text: v.Get("q"), Limit: 100}
	for _, t := range []struct {
		key string
		dst *time.Time
	}{{"since", &q.Since}, {"until", &q.Until}} {
		if s := v.Get(t.key); s != "" {
			var err error
			if *t.dst, err = time.Parse(time.RFC3339Nano, s); err != nil {
				return q, fmt.Errorf("%s は RFC 3339 の時刻で書いてください", t.key)
			}
		}
	}
	if s := v.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > MaxEventQuery {
			return q, fmt.Errorf("limit は 1 から %d までにしてください", MaxEventQuery)
		}
		q.Limit = n
	}
	if _, err := q.ClassUID(); err != nil {
		return q, err
	}
	if _, err := q.MinSeverity(); err != nil {
		return q, err
	}
	return q, nil
}

// ClassUID は検索するイベントのクラスを返す。条件がなければ 0。
func (q EventQuery) ClassUID() (event.ClassUID, error) {
	if q.Class == "" {
		return 0, nil
	}
	if c, ok := EventClasses[q.Class]; ok {
		return c, nil
	}
	if n, err := strconv.Atoi(q.Class); err == nil && n > 0 {
		return event.ClassUID(n), nil
	}
	return 0, fmt.Errorf("イベントの種類 %q は file、process、finding、network、dns、dhcp かクラスの番号で書いてください", q.Class)
}

// MinSeverity は検索する重大度の下限を返す。条件がなければ 0。
func (q EventQuery) MinSeverity() (event.Severity, error) {
	if q.Severity == "" {
		return 0, nil
	}
	if s, ok := Severities[q.Severity]; ok {
		return s, nil
	}
	if n, err := strconv.Atoi(q.Severity); err == nil && n >= 0 && n <= int(event.SeverityFatal) {
		return event.Severity(n), nil
	}
	return 0, fmt.Errorf("重大度 %q は info、low、medium、high、critical か番号で書いてください", q.Severity)
}
