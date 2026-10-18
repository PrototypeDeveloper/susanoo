// Package policy はポリシーの形式と検証を定める（G2、G9、G12、M2、M6）。
//
// ポリシーは JSON で書き、署名を付けて配布する（sign.PurposePolicy）。受け取った側は署名を検証し、
// 版数が今のものより新しい場合だけ適用する。古い内容に戻す（ロールバック）ときも、
// 古い内容に新しい版数を付けて配布し直す。
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"susanoo/internal/sign"
)

// DefaultGroup はグループを指定していない端末が属するグループの名前。ポリシーに必ず含める。
const DefaultGroup = "default"

// Response は検知したときの対応の段階。「監視→警告→遮断」と段階的に有効にする。
type Response string

const (
	ResponseMonitor Response = "monitor" // 記録だけする
	ResponseAlert   Response = "alert"   // 記録して警告する
	ResponseEnforce Response = "enforce" // 遮断と隔離まで行う
)

// FailureMode は防御システムに障害が起きたときの通信の扱い（G12）。
type FailureMode string

const (
	FailOpen   FailureMode = "fail_open"   // 通す
	FailClosed FailureMode = "fail_closed" // 遮断する
)

// EgressDefault は許可・拒否リストのどれにも当たらない外部通信の扱い（G2）。
type EgressDefault string

const (
	EgressAllow EgressDefault = "allow" // 通す
	EgressLearn EgressDefault = "learn" // 通して記録する（学習モード）
	EgressDeny  EgressDefault = "deny"  // 遮断する（原則拒否）
)

// IsolationLevel は隔離の段階（G9）。
type IsolationLevel string

const (
	IsolateFull                 IsolationLevel = "full"                   // 全遮断
	IsolateManagement           IsolationLevel = "management"             // 管理通信のみ許可
	IsolateManagementAndUpdates IsolationLevel = "management_and_updates" // 更新サーバーも許可
)

// Policy はポリシー全体。
type Policy struct {
	Version   int         `json:"version"` // 1 から始まり、配布のたびに増やす
	Name      string      `json:"name"`
	IssuedAt  time.Time   `json:"issued_at"`
	Response  Response    `json:"response"`
	OnFailure FailureMode `json:"on_failure"`
	Groups    []Group     `json:"groups"`
}

// Group は端末グループごとのポリシー。
type Group struct {
	Name            string         `json:"name"`
	Egress          Egress         `json:"egress"`
	Isolation       IsolationLevel `json:"isolation"`                  // 自動隔離の段階
	Updates         []Destination  `json:"updates,omitempty"`          // 隔離中も許可する更新サーバー
	RequireApproval bool           `json:"require_approval,omitempty"` // 隔離に人の承認を必須にする（M6）
	RiskThreshold   int            `json:"risk_threshold,omitempty"`   // 自動対応する危険度（M5）。省略すると DefaultRiskThreshold
	Bypass          Bypass         `json:"bypass,omitzero"`            // 抜け道の遮断の例外（G4）
}

// Bypass は抜け道の遮断（G4）の例外。省略するとすべて遮断する。
type Bypass struct {
	AllowQUIC bool `json:"allow_quic,omitempty"` // QUIC（UDP 443）を通す
	AllowDoH  bool `json:"allow_doh,omitempty"`  // DNS over HTTPS / TLS を通す
	AllowVPN  bool `json:"allow_vpn,omitempty"`  // VPN、トンネル、iCloud プライベートリレーを通す
	AllowECH  bool `json:"allow_ech,omitempty"`  // ECH の設定を含む DNS の HTTPS・SVCB レコードを返す
}

// Egress は外部通信の制御。拒否リストは許可リストより優先する。
type Egress struct {
	Default EgressDefault `json:"default"`
	Allow   []Destination `json:"allow,omitempty"`
	Deny    []Destination `json:"deny,omitempty"`
}

// Destination は通信先。Domain と CIDR のどちらか一方を指定する。
// Domain は「example.jp」で完全一致、「*.example.jp」でその下のすべての名前に一致する。
// 日本語ドメインは Punycode（xn--）で書く。Ports と Protocol を省略すると、すべてのポートとプロトコルに一致する。
type Destination struct {
	Domain   string   `json:"domain,omitempty"`
	CIDR     string   `json:"cidr,omitempty"`
	Ports    []uint16 `json:"ports,omitempty"`
	Protocol string   `json:"protocol,omitempty"` // tcp、udp、または空
}

// Parse は JSON のポリシーを読み、検証する。知らない項目は書き間違いとみなして拒否する。
func Parse(data []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: JSON を解析できません: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("policy: JSON の後に余分なデータがあります")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// ParseSigned は署名を検証してからポリシーを読む。
func ParseSigned(v *sign.Verifier, env sign.Envelope) (*Policy, error) {
	payload, err := v.Verify(sign.PurposePolicy, env)
	if err != nil {
		return nil, err
	}
	return Parse(payload)
}

// CheckUpgrade は current を next で置き換えてよいかを確かめる。current が nil なら初回の適用とみなす。
func CheckUpgrade(current, next *Policy) error {
	if current != nil && next.Version <= current.Version {
		return fmt.Errorf("policy: 版数 %d は適用中の版数 %d より新しくありません", next.Version, current.Version)
	}
	return nil
}

// Group は名前が name のグループを返す。見つからなければ default グループを返す。
func (p *Policy) Group(name string) *Group {
	var def *Group
	for i := range p.Groups {
		switch p.Groups[i].Name {
		case name:
			return &p.Groups[i]
		case DefaultGroup:
			def = &p.Groups[i]
		}
	}
	return def
}

// MatchDomain は、宛先がドメインで指定されていて name に一致するかを返す。
// 「example.jp」は完全一致、「*.example.jp」はその下の名前（example.jp 自身は含まない）に一致する。
// name は小文字で、末尾の「.」を付けない形で渡す。
func (d Destination) MatchDomain(name string) bool {
	switch {
	case d.Domain == "":
		return false
	case strings.HasPrefix(d.Domain, "*."):
		return strings.HasSuffix(name, d.Domain[1:]) && len(name) > len(d.Domain)-1
	default:
		return name == d.Domain
	}
}

// DefaultRiskThreshold は、グループに risk_threshold がないときの、自動対応する危険度（M5）。
// 既定の検知ルール（おとりへの接触など）は 100 点なので、1 回の検知で対応する。
const DefaultRiskThreshold = 100

// Threshold は自動対応する危険度を返す。
func (g *Group) Threshold() int {
	if g.RiskThreshold > 0 {
		return g.RiskThreshold
	}
	return DefaultRiskThreshold
}

// UpdatePrefixes はグループの更新サーバーのうち、CIDR で指定したものを返す。
// ドメインで指定したものは、DNS で解決したアドレスを GW が許可する。
func (g *Group) UpdatePrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, d := range g.Updates {
		if p, err := netip.ParsePrefix(d.CIDR); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// AllUpdatePrefixes はすべてのグループの、CIDR で指定した更新サーバーを返す。
func (p *Policy) AllUpdatePrefixes() []netip.Prefix {
	var out []netip.Prefix
	for i := range p.Groups {
		out = append(out, p.Groups[i].UpdatePrefixes()...)
	}
	return out
}

// HasGroup は名前が name のグループがあるかを返す。
func (p *Policy) HasGroup(name string) bool {
	for i := range p.Groups {
		if p.Groups[i].Name == name {
			return true
		}
	}
	return false
}

// Validate はポリシーの内容が正しいか確かめる。問題をまとめて返す。
func (p *Policy) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf("policy: "+format, args...)) }

	if p.Version < 1 {
		add("version は 1 以上にしてください")
	}
	if p.IssuedAt.IsZero() {
		add("issued_at がありません")
	}
	switch p.Response {
	case ResponseMonitor, ResponseAlert, ResponseEnforce:
	default:
		add("response %q は monitor、alert、enforce のどれかにしてください", p.Response)
	}
	switch p.OnFailure {
	case FailOpen, FailClosed:
	default:
		add("on_failure %q は fail_open か fail_closed にしてください", p.OnFailure)
	}

	seen := map[string]bool{}
	for i, g := range p.Groups {
		where := fmt.Sprintf("groups[%d]", i)
		if g.Name == "" {
			add("%s: name がありません", where)
		} else if strings.Contains(g.Name, "~") {
			add("%s: グループ名 %q に「~」は使えません（先行適用のグループの印に使う）", where, g.Name)
		} else if seen[g.Name] {
			add("%s: グループ名 %q が重複しています", where, g.Name)
		}
		seen[g.Name] = true
		switch g.Egress.Default {
		case EgressAllow, EgressLearn, EgressDeny:
		default:
			add("%s: egress.default %q は allow、learn、deny のどれかにしてください", where, g.Egress.Default)
		}
		switch g.Isolation {
		case IsolateFull, IsolateManagement, IsolateManagementAndUpdates:
		default:
			add("%s: isolation %q は full、management、management_and_updates のどれかにしてください", where, g.Isolation)
		}
		if g.RiskThreshold < 0 || g.RiskThreshold > 100000 {
			add("%s: risk_threshold は 1 から 100000 にしてください", where)
		}
		for j, d := range g.Egress.Allow {
			if err := d.validate(); err != nil {
				add("%s.egress.allow[%d]: %v", where, j, err)
			}
		}
		for j, d := range g.Egress.Deny {
			if err := d.validate(); err != nil {
				add("%s.egress.deny[%d]: %v", where, j, err)
			}
		}
		for j, d := range g.Updates {
			if err := d.validate(); err != nil {
				add("%s.updates[%d]: %v", where, j, err)
			}
		}
	}
	if !seen[DefaultGroup] {
		add("グループ %q が必要です", DefaultGroup)
	}
	return errors.Join(errs...)
}

func (d Destination) validate() error {
	var errs []error
	switch {
	case d.Domain != "" && d.CIDR != "":
		errs = append(errs, errors.New("domain と cidr は同時に指定できません"))
	case d.Domain != "":
		if err := validateDomain(d.Domain); err != nil {
			errs = append(errs, err)
		}
	case d.CIDR != "":
		pfx, err := netip.ParsePrefix(d.CIDR)
		if err != nil {
			errs = append(errs, fmt.Errorf("cidr %q を解析できません", d.CIDR))
		} else if pfx != pfx.Masked() {
			errs = append(errs, fmt.Errorf("cidr %q はネットワークアドレスで書いてください（%s）", d.CIDR, pfx.Masked()))
		}
	default:
		errs = append(errs, errors.New("domain か cidr のどちらかが必要です"))
	}
	for _, port := range d.Ports {
		if port == 0 {
			errs = append(errs, errors.New("ポート 0 は指定できません"))
		}
	}
	switch d.Protocol {
	case "", "tcp", "udp":
	default:
		errs = append(errs, fmt.Errorf("protocol %q は tcp か udp にしてください", d.Protocol))
	}
	return errors.Join(errs...)
}

// validateDomain はドメイン名の形を確かめる。英小文字、数字、「-」のラベルを「.」でつなぎ、
// 先頭にだけ「*.」を付けられる。
func validateDomain(name string) error {
	host := strings.TrimPrefix(name, "*.")
	if len(host) == 0 || len(host) > 253 {
		return fmt.Errorf("domain %q の長さが不正です", name)
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return fmt.Errorf("domain %q にはトップレベルドメインまで書いてください", name)
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("domain %q のラベル %q が不正です", name, l)
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("domain %q に使えない文字 %q があります（英小文字、数字、「-」。日本語ドメインは Punycode）", name, c)
			}
		}
	}
	return nil
}
