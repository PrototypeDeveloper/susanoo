// Package event は GW と CLIENT が出すイベントの共通形式を定める（M4）。
//
// 形式は OCSF（Open Cybersecurity Schema Framework）1.3 に準拠し、MVP で使うクラスと項目だけを定義する。
// 項目の名前は OCSF に合わせ、OCSF に対応する項目がない情報は Unmapped に入れる。
package event

import (
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	"susanoo/internal/version"
)

// SchemaVersion は準拠する OCSF の版。
const SchemaVersion = "1.3.0"

// ClassUID は OCSF のイベントクラス。上 1 桁がカテゴリーを表す。
type ClassUID int

const (
	ClassFileSystemActivity ClassUID = 1001 // ファイルの操作（C3、C5）
	ClassProcessActivity    ClassUID = 1007 // プロセスの起動・終了（C1）
	ClassDetectionFinding   ClassUID = 2004 // 検知結果（おとりへの接触、ハートビートの途絶など）
	ClassAuthentication     ClassUID = 3002 // ログオンとログオフ、失敗したログオン（C4）
	ClassNetworkActivity    ClassUID = 4001 // 通信（G5、C2）
	ClassDNSActivity        ClassUID = 4003 // DNS の問い合わせ（G3）
	ClassDHCPActivity       ClassUID = 4004 // DHCP によるアドレスの割り当て（G8）
)

// Category はクラスが属するカテゴリーを返す。
func (c ClassUID) Category() int { return int(c) / 1000 }

// 各クラスの activity_id。
const (
	ActivityUnknown = 0
	ActivityOther   = 99

	FileCreate        = 1
	FileRead          = 2
	FileUpdate        = 3
	FileDelete        = 4
	FileRename        = 5
	FileSetAttributes = 6
	FileOpen          = 14

	ProcessLaunch    = 1
	ProcessTerminate = 2

	FindingCreate = 1
	FindingUpdate = 2
	FindingClose  = 3

	NetworkOpen    = 1
	NetworkClose   = 2
	NetworkRefuse  = 5
	NetworkTraffic = 6

	DNSActivityQuery    = 1
	DNSActivityResponse = 2

	DHCPAssign  = 1
	DHCPRenew   = 2
	DHCPRelease = 3

	AuthLogon  = 1
	AuthLogoff = 2
)

// Authentication の status_id と logon_type_id。
const (
	StatusSuccess = 1
	StatusFailure = 2

	LogonInteractive       = 2  // 端末の前でのログオン（コンソール、画面）
	LogonNetwork           = 3  // 端末を割り当てない遠隔のログオン（ssh で命令だけを実行するなど）
	LogonRemoteInteractive = 10 // 端末を割り当てる遠隔のログオン（ssh の対話など）
)

// Severity は OCSF の severity_id。
type Severity int

const (
	SeverityUnknown       Severity = 0
	SeverityInformational Severity = 1
	SeverityLow           Severity = 2
	SeverityMedium        Severity = 3
	SeverityHigh          Severity = 4
	SeverityCritical      Severity = 5
	SeverityFatal         Severity = 6
	SeverityOther         Severity = 99
)

// Event は 1 件のイベント。
type Event struct {
	ClassUID    ClassUID `json:"class_uid"`
	CategoryUID int      `json:"category_uid"`
	ActivityID  int      `json:"activity_id"`
	TypeUID     int      `json:"type_uid"`
	Time        int64    `json:"time"`                 // 発生時刻（UNIX 時間のミリ秒）
	StartTime   int64    `json:"start_time,omitempty"` // 通信などの始まり（UNIX 時間のミリ秒）
	EndTime     int64    `json:"end_time,omitempty"`   // 通信などの終わり（UNIX 時間のミリ秒）
	SeverityID  Severity `json:"severity_id"`
	Message     string   `json:"message,omitempty"`
	Metadata    Metadata `json:"metadata"`

	Device      *Device      `json:"device,omitempty"`
	Actor       *Actor       `json:"actor,omitempty"`
	Process     *Process     `json:"process,omitempty"`
	File        *File        `json:"file,omitempty"`
	SrcEndpoint *Endpoint    `json:"src_endpoint,omitempty"`
	DstEndpoint *Endpoint    `json:"dst_endpoint,omitempty"`
	Connection  *Connection  `json:"connection_info,omitempty"`
	Traffic     *Traffic     `json:"traffic,omitempty"`
	TLS         *TLS         `json:"tls,omitempty"`
	HTTPRequest *HTTPRequest `json:"http_request,omitempty"`
	Query       *DNSQuery    `json:"query,omitempty"`
	Answers     []DNSAnswer  `json:"answers,omitempty"`
	RcodeID     *int         `json:"rcode_id,omitempty"`
	FindingInfo *FindingInfo `json:"finding_info,omitempty"`
	// 以下は Authentication（ログオン）の項目。
	User         *User    `json:"user,omitempty"`          // ログオンした（しようとした）利用者
	StatusID     int      `json:"status_id,omitempty"`     // StatusSuccess か StatusFailure
	StatusDetail string   `json:"status_detail,omitempty"` // 失敗の理由など
	IsRemote     *bool    `json:"is_remote,omitempty"`
	LogonTypeID  int      `json:"logon_type_id,omitempty"`
	AuthProtocol string   `json:"auth_protocol,omitempty"` // password、publickey など
	Service      *Service `json:"service,omitempty"`       // ログオンを受け付けたサービス（sshd、login など）
	Session      *Session `json:"session,omitempty"`
	LogonProcess *Process `json:"logon_process,omitempty"`

	Evidences []Evidence     `json:"evidences,omitempty"`
	Unmapped  map[string]any `json:"unmapped,omitempty"`
}

// Metadata はイベントそのものの情報。
type Metadata struct {
	Version        string  `json:"version"` // OCSF の版
	Product        Product `json:"product"`
	UID            string  `json:"uid"`                       // イベントの ID
	CorrelationUID string  `json:"correlation_uid,omitempty"` // 関連するイベントをまとめる ID
	LoggedTime     int64   `json:"logged_time,omitempty"`     // 記録した時刻（UNIX 時間のミリ秒）
}

// Product はイベントを出した製品。
type Product struct {
	Name       string   `json:"name"`
	VendorName string   `json:"vendor_name"`
	Version    string   `json:"version"`
	Feature    *Feature `json:"feature,omitempty"`
}

// Feature はイベントを出した機能（GW、CLIENT など）。
type Feature struct {
	Name string `json:"name"`
}

// Device はイベントが起きた端末。UID には証明書の ID（端末 ID）を入れ、端末ごとの相関に使う。
type Device struct {
	UID      string `json:"uid,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	IP       string `json:"ip,omitempty"`
	MAC      string `json:"mac,omitempty"`
	OS       *OS    `json:"os,omitempty"`
}

// OS は端末の OS。
type OS struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Actor は操作をした主体。
type Actor struct {
	Process *Process `json:"process,omitempty"`
	User    *User    `json:"user,omitempty"`
}

// User は利用者。
type User struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}

// Service はサービス。
type Service struct {
	Name string `json:"name"`
}

// Session はログオンのセッション。
type Session struct {
	UID         string `json:"uid,omitempty"`
	Terminal    string `json:"terminal,omitempty"`     // tty や pts
	CreatedTime int64  `json:"created_time,omitempty"` // 始まった時刻（UNIX 時間のミリ秒）
}

// Process はプロセス。
type Process struct {
	PID         int      `json:"pid,omitempty"`
	Name        string   `json:"name,omitempty"`
	CmdLine     string   `json:"cmd_line,omitempty"`
	File        *File    `json:"file,omitempty"` // 実行ファイル
	User        *User    `json:"user,omitempty"`
	Parent      *Process `json:"parent_process,omitempty"`
	CreatedTime int64    `json:"created_time,omitempty"`
	// Lineage は祖先のプロセスの実行ファイルのパス（古い順。親が最後）。親子関係の検知と、AI エージェントの帰属に使う（C8、C9）。
	Lineage []string `json:"lineage,omitempty"`
}

// File はファイル。
type File struct {
	Name   string        `json:"name"`
	Path   string        `json:"path,omitempty"`
	Size   int64         `json:"size,omitempty"`
	Hashes []Fingerprint `json:"hashes,omitempty"`
}

// HashSHA256 は OCSF の fingerprint.algorithm_id で SHA-256 を表す値。
const HashSHA256 = 3

// Fingerprint はハッシュ値。
type Fingerprint struct {
	AlgorithmID int    `json:"algorithm_id"`
	Value       string `json:"value"`
}

// Endpoint は通信の端点。
type Endpoint struct {
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	MAC      string `json:"mac,omitempty"`
	UID      string `json:"uid,omitempty"` // 端末 ID が分かる場合
}

// Connection は接続の情報。
type Connection struct {
	ProtocolName string `json:"protocol_name,omitempty"` // tcp、udp など
	DirectionID  int    `json:"direction_id,omitempty"`  // 1: 内向き、2: 外向き、3: 内部同士
}

// Traffic は通信量。
type Traffic struct {
	BytesIn    int64 `json:"bytes_in,omitempty"`
	BytesOut   int64 `json:"bytes_out,omitempty"`
	PacketsIn  int64 `json:"packets_in,omitempty"`
	PacketsOut int64 `json:"packets_out,omitempty"`
}

// TLS は TLS の情報。
type TLS struct {
	SNI     string `json:"sni,omitempty"`
	Version string `json:"version,omitempty"`
}

// HTTPRequest は HTTP の要求。
type HTTPRequest struct {
	Method string `json:"http_method,omitempty"`
	URL    *URL   `json:"url,omitempty"`
}

// URL は URL。
type URL struct {
	Hostname string `json:"hostname,omitempty"`
}

// DNSQuery は DNS の問い合わせ。
type DNSQuery struct {
	Hostname string `json:"hostname"`
	Type     string `json:"type,omitempty"` // A、AAAA、HTTPS など
	Class    string `json:"class,omitempty"`
}

// DNSAnswer は DNS の応答の 1 件。
type DNSAnswer struct {
	Rdata string `json:"rdata"`
	Type  string `json:"type,omitempty"`
	TTL   int    `json:"ttl,omitempty"`
}

// FindingInfo は検知結果の内容。
type FindingInfo struct {
	UID      string    `json:"uid"`
	Title    string    `json:"title"`
	Desc     string    `json:"desc,omitempty"`
	Types    []string  `json:"types,omitempty"`
	Analytic *Analytic `json:"analytic,omitempty"`
}

// Analytic は検知結果を作った検知ルール（OCSF の analytic）。
type Analytic struct {
	UID    string `json:"uid"`
	Name   string `json:"name"`
	TypeID int    `json:"type_id"` // AnalyticRule など
}

// AnalyticRule は Analytic.TypeID で、検知ルールを表す値。
const AnalyticRule = 1

// FindingInfo.Types に入れる検知の種類。
const (
	FindingTypeHoneytoken      = "honeytoken"       // おとりへの接触（C5）
	FindingTypeHeartbeatLost   = "heartbeat_lost"   // ハートビートの途絶（G10）
	FindingTypeDeviceAway      = "device_away"      // ハートビートが途絶えた端末が LAN にいない（G10）
	FindingTypeNewDevice       = "new_device"       // 初めて見た機器（G8）
	FindingTypeGatewaySpoofing = "gateway_spoofing" // ゲートウェイのアドレスを名乗る ARP（G8）
	FindingTypeIPSpoofing      = "ip_spoofing"      // ほかの機器に割り当て中のアドレスを名乗る ARP（G8）
	FindingTypeConfigChanged   = "config_changed"   // 設定ファイルの変更（G12）
	FindingTypeMassChange      = "mass_change"      // 短時間の大量のファイルの変更（C3、T7）
	FindingTypeTamper          = "tamper"           // 自己隔離のルールなど、防御の仕組みの改ざん（C10）
	FindingTypeRule            = "rule_match"       // 検知ルールの条件に当てはまった（M3）。ルールは Analytic
	FindingTypeBeacon          = "beacon"           // 周期的な通信（G6）
	FindingTypeLargeUpload     = "large_upload"     // 大量の送信（G6）
	FindingTypeInternalScan    = "internal_scan"    // LAN 内のスキャン（G6）
	FindingTypeNewDestinations = "new_destinations" // 新しい宛先の急増（G6）
	FindingTypeOffHours        = "off_hours"        // 時間外の通信（G6）
	FindingTypeThreatIntel     = "threat_intel"     // 脅威情報の一覧に当てはまる問い合わせや通信（G7）
	// CLIENT の検知（2c-1）。
	FindingTypePersistence         = "persistence"          // 自動起動、cron、サービスなど、永続化に使われる場所の変更（C4）
	FindingTypePrivilegeChange     = "privilege_change"     // 利用者、sudo、PAM など、権限の設定の変更（C4）
	FindingTypePrivilegeEscalation = "privilege_escalation" // 一般の利用者のプロセスから root の権限のプロセスが起動した（C4）
	FindingTypeCredentialAccess    = "credential_access"    // 認証情報のファイルを、ふだん読むプログラム以外が読んだ（C8、C9）
	FindingTypeKernelModule        = "kernel_module"        // カーネルモジュールの読み込み（C4）
	FindingTypeEvidence            = "evidence"             // 端末の証拠を保全した（C11）。時系列に載せるための記録
	FindingTypeAppControl          = "app_control"          // プロセス単位の通信の制御で拒否した、または拒否に当たった接続（C7）
	FindingTypeEnrollLock          = "enroll_lock"          // 誤った登録の証明が続き、登録コードを消した（M1。コードの総当たりの疑い）
	FindingTypeRogueRouter         = "rogue_router"         // LAN の機器のルーター広告（G8。IPv6 の通信の横取りの疑い）
	FindingTypeRogueDHCPv6         = "rogue_dhcpv6"         // LAN の機器が DHCPv6 のサーバーとして答えた（G8。DNS の差し替えの疑い）
	FindingTypeClockSkew           = "clock_skew"           // 端末の時刻が CONTROLLER と大きくずれている（相関の精度が落ちる。時刻の改ざんの疑い）
	FindingTypeResourceLimit       = "resource_limit"       // CLIENT が資源の上限を超え、監視を間引き始めた（大量の操作で監視を妨げる攻撃の疑い）
)

// HasType は検知の種類に t が含まれるかどうかを返す。
func (f *FindingInfo) HasType(t string) bool {
	return f != nil && slices.Contains(f.Types, t)
}

// Evidence は検知結果の根拠となった情報（OCSF の evidences）。
type Evidence struct {
	Actor   *Actor   `json:"actor,omitempty"`
	File    *File    `json:"file,omitempty"`
	Process *Process `json:"process,omitempty"`
}

// ProductName と VendorName は metadata.product に入れる値。
const (
	ProductName = "susanoo"
	VendorName  = "susanoo"
)

// New は共通の項目を埋めたイベントを作る。クラス固有の項目は呼び出し側が埋める。
func New(class ClassUID, activity int, severity Severity, at time.Time) *Event {
	return &Event{
		ClassUID:    class,
		CategoryUID: class.Category(),
		ActivityID:  activity,
		TypeUID:     int(class)*100 + activity,
		Time:        at.UnixMilli(),
		SeverityID:  severity,
		Metadata: Metadata{
			Version: SchemaVersion,
			Product: Product{Name: ProductName, VendorName: VendorName, Version: version.Version},
			UID:     rand.Text(),
		},
	}
}

// Validate は共通の項目が揃って矛盾がないこと、クラスに必要な項目があることを確かめる。
func (e *Event) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf("event: "+format, args...)) }

	need, known := required[e.ClassUID]
	if !known {
		add("不明なクラスです: %d", e.ClassUID)
	}
	if e.CategoryUID != e.ClassUID.Category() {
		add("category_uid %d がクラス %d と合いません", e.CategoryUID, e.ClassUID)
	}
	if e.ActivityID < 0 || e.ActivityID > ActivityOther {
		add("activity_id %d は範囲外です", e.ActivityID)
	}
	if e.TypeUID != int(e.ClassUID)*100+e.ActivityID {
		add("type_uid %d が class_uid と activity_id から計算した値と合いません", e.TypeUID)
	}
	if e.Time <= 0 {
		add("time がありません")
	}
	switch {
	case e.SeverityID >= SeverityUnknown && e.SeverityID <= SeverityFatal, e.SeverityID == SeverityOther:
	default:
		add("severity_id %d は範囲外です", e.SeverityID)
	}
	if e.Metadata.Version == "" || e.Metadata.UID == "" || e.Metadata.Product.Name == "" {
		add("metadata の version、uid、product.name は必須です")
	}
	if known {
		for _, n := range need {
			if !n.present(e) {
				add("クラス %d には %s が必要です", e.ClassUID, n.name)
			}
		}
	}
	return errors.Join(errs...)
}

type field struct {
	name    string
	present func(*Event) bool
}

var (
	hasDevice  = field{"device", func(e *Event) bool { return e.Device != nil }}
	hasFile    = field{"file", func(e *Event) bool { return e.File != nil && e.File.Name != "" }}
	hasProcess = field{"process", func(e *Event) bool { return e.Process != nil }}
	hasSrc     = field{"src_endpoint", func(e *Event) bool { return e.SrcEndpoint != nil }}
	hasDst     = field{"dst_endpoint", func(e *Event) bool { return e.DstEndpoint != nil }}
	hasQuery   = field{"query", func(e *Event) bool { return e.Query != nil && e.Query.Hostname != "" }}
	hasUser    = field{"user", func(e *Event) bool { return e.User != nil && (e.User.Name != "" || e.User.UID != "") }}
	hasFinding = field{"finding_info", func(e *Event) bool {
		return e.FindingInfo != nil && e.FindingInfo.UID != "" && e.FindingInfo.Title != ""
	}}
)

// required はクラスごとに必須とする項目。
var required = map[ClassUID][]field{
	ClassFileSystemActivity: {hasDevice, hasFile},
	ClassProcessActivity:    {hasDevice, hasProcess},
	ClassDetectionFinding:   {hasFinding},
	ClassAuthentication:     {hasUser},
	ClassNetworkActivity:    {hasSrc, hasDst},
	ClassDNSActivity:        {hasQuery},
	ClassDHCPActivity:       {hasDst},
}
