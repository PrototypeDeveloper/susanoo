// Package rules は検知ルールの形式、検証、評価を定める（M3、M5）。
//
// 検知ルールは JSON で書き、管理者の鍵で署名して配布する（sign.PurposeRules）。ルールは 2 種類ある。
//
//   - 検知結果のルール（finding）：CLIENT や GW が出した検知結果の種類（おとりへの接触など）に、危険度の点を付ける
//   - 条件のルール（match）：イベントの項目の条件に当てはまったら検知結果を作る。同じ端末で一定の時間に
//     決まった回数を超えたら、とするしきい値も付けられる
//
// ルールごとに、危険度に加える（enforce）、記録だけする（monitor）、使わない（off）を選ぶ。新しいルールは
// monitor で誤検知の数を確かめてから enforce にする（フェーズ2のゲート「学習モードで誤検知が許容範囲に収まる」）。
// groups を書くと、そのグループの端末と機器だけに使う（一部のグループから広げる段階配布）。
// 誤検知の例外（Exception）は、ルール、端末、グループ、イベントの条件、期限で指定する。
//
// 既定のルール（Defaults）は、フェーズ1の検知（おとりへの接触など）を同じ動きで表したもの。配布したルールに
// 同じ ID があれば置き換え、なければ既定のまま残す（書き忘れで検知が止まらないように）。
package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"susanoo/internal/behavior"
	"susanoo/internal/config"
	"susanoo/internal/event"
	"susanoo/internal/sign"
)

// Mode はルールの扱い。
type Mode string

const (
	ModeEnforce Mode = "enforce" // 検知結果を作り、危険度に加える
	ModeMonitor Mode = "monitor" // 検知結果を作るが、危険度には加えない（誤検知を確かめるため）
	ModeOff     Mode = "off"     // 使わない
)

// 上限。条件が大きすぎると評価に時間がかかるため。
const (
	maxRules      = 1000
	maxExceptions = 1000
	maxDepth      = 8
	maxConds      = 64
	maxIDLen      = 63
)

// Set は検知ルールの一式。
type Set struct {
	Version    int             `json:"version"` // 1 から始まり、配布のたびに増やす
	Name       string          `json:"name"`
	IssuedAt   time.Time       `json:"issued_at"`
	Scoring    Scoring         `json:"scoring,omitzero"`
	Behavior   behavior.Config `json:"behavior,omitzero"` // 振る舞いの検知（G6）の設定
	Rules      []Rule          `json:"rules"`
	Exceptions []Exception     `json:"exceptions,omitempty"`
}

// Scoring は危険度の計算の設定。
type Scoring struct {
	HalfLife config.Duration `json:"half_life,omitempty"` // 点が半分になる時間。既定 24h
}

// DefaultHalfLife は危険度の点が半分になる既定の時間。
const DefaultHalfLife = 24 * time.Hour

// Rule は 1 つの検知ルール。
type Rule struct {
	ID          string         `json:"id"` // 英小文字、数字、「-」
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Mode        Mode           `json:"mode"`
	Score       int            `json:"score"`              // 危険度に加える点（0 から 1000）
	Severity    event.Severity `json:"severity,omitempty"` // 条件のルールが作る検知結果の重大度。既定は medium
	Finding     string         `json:"finding,omitempty"`  // 検知結果のルール：検知結果の種類（honeytoken など）
	Class       string         `json:"class,omitempty"`    // 条件のルール：対象のイベントの種類（file、process、network、dns、dhcp、finding か番号）
	Match       *Cond          `json:"match,omitempty"`    // 条件のルール：イベントの条件
	Threshold   *Threshold     `json:"threshold,omitempty"`
	Groups      []string       `json:"groups,omitempty"` // このグループの端末と機器だけに使う（段階配布）。省略するとすべて

	classUID event.ClassUID
}

// Threshold は、同じ端末（by の項目の値）で window の間に count 回以上当てはまったら検知する、という条件。
type Threshold struct {
	Count  int             `json:"count"`
	Window config.Duration `json:"window"`
	By     string          `json:"by,omitempty"` // 数える単位にする項目。既定は端末（device.uid、なければ device.ip）
}

// Exception は誤検知の例外。指定した項目のすべてに当てはまる検知を、なかったことにする。
type Exception struct {
	Rules   []string  `json:"rules"`             // ルールの ID（「*」ですべて）
	Devices []string  `json:"devices,omitempty"` // 端末 ID、MAC アドレス、アドレス
	Groups  []string  `json:"groups,omitempty"`
	Match   *Cond     `json:"match,omitempty"` // 元のイベントの条件
	Until   time.Time `json:"until,omitzero"`  // この時刻まで（なければ期限なし）
	Reason  string    `json:"reason"`          // 例外にした理由（必須。監査のため）
}

// Defaults は既定のルール。フェーズ1の検知と同じ動き（どれも 100 点で、既定のしきい値で隔離する）にする。
// 名前は隔離の理由として台帳に載る。
var Defaults = []Rule{
	{ID: "honeytoken", Name: "おとりへの接触", Finding: event.FindingTypeHoneytoken, Mode: ModeEnforce, Score: 100},
	{ID: "mass-change", Name: "短時間の大量変更", Finding: event.FindingTypeMassChange, Mode: ModeEnforce, Score: 100},
	{ID: "gateway-spoofing", Name: "ゲートウェイのなりすまし", Finding: event.FindingTypeGatewaySpoofing, Mode: ModeEnforce, Score: 100},
	{ID: "ip-spoofing", Name: "アドレスのなりすまし", Finding: event.FindingTypeIPSpoofing, Mode: ModeEnforce, Score: 100},
	{ID: "heartbeat-lost", Name: "ハートビートの途絶", Finding: event.FindingTypeHeartbeatLost, Mode: ModeEnforce, Score: 100},
	{ID: "tamper", Name: "防御の仕組みの改ざん", Finding: event.FindingTypeTamper, Mode: ModeEnforce, Score: 0}, // 記録して警告する
	// 振る舞いの検知（G6）は誤検知が出やすいため、試験運用から始める。
	{ID: "beacon", Name: "周期的な通信", Finding: event.FindingTypeBeacon, Mode: ModeMonitor, Score: 40},
	{ID: "large-upload", Name: "大量の送信", Finding: event.FindingTypeLargeUpload, Mode: ModeMonitor, Score: 50},
	{ID: "internal-scan", Name: "LAN 内のスキャン", Finding: event.FindingTypeInternalScan, Mode: ModeMonitor, Score: 60},
	{ID: "new-destinations", Name: "新しい宛先の急増", Finding: event.FindingTypeNewDestinations, Mode: ModeMonitor, Score: 30},
	{ID: "off-hours", Name: "時間外の通信", Finding: event.FindingTypeOffHours, Mode: ModeMonitor, Score: 20},
	// 脅威情報（G7）。遮断の一覧は GW が止めるので、危険度による隔離は、一覧の質を確かめてから有効にする。
	{ID: "threat-intel", Name: "脅威情報に当てはまる通信", Finding: event.FindingTypeThreatIntel, Mode: ModeMonitor, Score: 50},
}

// Parse は検知ルールを読んで検証する。知らない項目は書き間違いとみなして拒否する。
func Parse(data []byte) (*Set, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var s Set
	if err := d.Decode(&s); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("rules: JSON の後ろに余分なデータがあります")
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// ParseSigned は署名（sign.PurposeRules）を検証してから検知ルールを読む。
func ParseSigned(v *sign.Verifier, env sign.Envelope) (*Set, error) {
	payload, err := v.Verify(sign.PurposeRules, env)
	if err != nil {
		return nil, err
	}
	return Parse(payload)
}

// Validate はルールの内容を確かめ、評価の準備（正規表現の組み立てなど）をする。問題をまとめて返す。
func (s *Set) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf("rules: "+format, args...)) }
	if s.Version < 1 {
		add("version は 1 以上にしてください")
	}
	if s.IssuedAt.IsZero() {
		add("issued_at がありません")
	}
	if s.Scoring.HalfLife < 0 {
		add("scoring.half_life は正の値にしてください")
	}
	if err := s.Behavior.Validate(); err != nil {
		errs = append(errs, err)
	}
	if len(s.Rules) > maxRules || len(s.Exceptions) > maxExceptions {
		add("ルールは %d 個、例外は %d 個までです", maxRules, maxExceptions)
	}
	seen := map[string]bool{}
	for i := range s.Rules {
		r := &s.Rules[i]
		where := fmt.Sprintf("rules[%d]（%s）", i, r.ID)
		if !validID(r.ID) {
			add("%s: id は英小文字、数字、「-」で %d 文字までにしてください", where, maxIDLen)
		} else if seen[r.ID] {
			add("%s: id が重複しています", where)
		}
		seen[r.ID] = true
		if err := r.prepare(); err != nil {
			add("%s: %v", where, err)
		}
	}
	for i := range s.Exceptions {
		x := &s.Exceptions[i]
		where := fmt.Sprintf("exceptions[%d]", i)
		if len(x.Rules) == 0 {
			add("%s: rules に例外にするルールの ID（すべてなら「*」）を書いてください", where)
		}
		if strings.TrimSpace(x.Reason) == "" {
			add("%s: reason に例外にした理由を書いてください", where)
		}
		if slices.Contains(x.Devices, "") || slices.Contains(x.Groups, "") || slices.Contains(x.Rules, "") {
			add("%s: rules、devices、groups に空の値は書けません", where)
		}
		if x.Match != nil {
			if err := x.Match.prepare(0, new(int)); err != nil {
				add("%s.match: %v", where, err)
			}
		}
	}
	return errors.Join(errs...)
}

func validID(id string) bool {
	if id == "" || len(id) > maxIDLen {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// classes はイベントの種類の名前。api.EventClasses と同じ。
var classes = map[string]event.ClassUID{
	"file": event.ClassFileSystemActivity, "process": event.ClassProcessActivity, "finding": event.ClassDetectionFinding,
	"network": event.ClassNetworkActivity, "dns": event.ClassDNSActivity, "dhcp": event.ClassDHCPActivity,
}

// prepare はルールを確かめ、評価の準備をする。
func (r *Rule) prepare() error {
	if r.Name == "" {
		return errors.New("name がありません")
	}
	switch r.Mode {
	case ModeEnforce, ModeMonitor, ModeOff:
	default:
		return fmt.Errorf("mode %q は enforce、monitor、off のどれかにしてください", r.Mode)
	}
	for _, g := range r.Groups {
		if g == "" || strings.Contains(g, "~") {
			return fmt.Errorf("groups のグループ名 %q が不正です", g)
		}
	}
	if r.Score < 0 || r.Score > 1000 {
		return errors.New("score は 0 から 1000 にしてください")
	}
	if r.Severity != 0 && (r.Severity < event.SeverityInformational || r.Severity > event.SeverityFatal) {
		return fmt.Errorf("severity %d は 1 から 6 にしてください", r.Severity)
	}
	switch {
	case r.Finding != "" && (r.Match != nil || r.Class != "" || r.Threshold != nil):
		return errors.New("finding と match は一緒に使えません")
	case r.Finding == event.FindingTypeRule:
		return fmt.Errorf("finding に %q は使えません（条件のルールが作る検知結果のため）", r.Finding)
	case r.Finding != "":
		return nil
	case r.Match == nil || r.Class == "":
		return errors.New("finding か、class と match のどちらかを書いてください")
	}
	if c, ok := classes[r.Class]; ok {
		r.classUID = c
	} else {
		return fmt.Errorf("class %q は file、process、network、dns、dhcp、finding のどれかにしてください", r.Class)
	}
	if t := r.Threshold; t != nil {
		if t.Count < 2 || t.Count > 10000 {
			return errors.New("threshold.count は 2 から 10000 にしてください")
		}
		if t.Window.Or(0) < time.Second || t.Window.Or(0) > 24*time.Hour {
			return errors.New("threshold.window は 1 秒から 24 時間にしてください")
		}
	}
	return r.Match.prepare(0, new(int))
}

// FindingSeverity は条件のルールが作る検知結果の重大度を返す（既定は medium）。
func (r *Rule) FindingSeverity() event.Severity {
	if r.Severity == 0 {
		return event.SeverityMedium
	}
	return r.Severity
}

// Merge は既定のルールに、配布したルールを重ねたものを返す（同じ ID は置き換え、ない既定のルールは残す）。
func Merge(s *Set) []Rule {
	out := slices.Clone(Defaults)
	for i := range out {
		out[i].prepare()
	}
	if s == nil {
		return out
	}
	for _, r := range s.Rules {
		if i := slices.IndexFunc(out, func(d Rule) bool { return d.ID == r.ID }); i >= 0 {
			out[i] = r
		} else {
			out = append(out, r)
		}
	}
	return out
}

// Cond はイベントの条件。All、Any、Not か、項目（Field）と比べ方（Op）と値のどれか 1 つを書く。
//
// Field は OCSF の JSON の項目を「.」でつないだもの（process.cmd_line、dst_endpoint.ip など）。途中に配列があれば、
// どれか 1 つの要素が当てはまれば当てはまる。Op は eq、ne、contains、prefix、suffix、regex、in（Values のどれか）、
// cidr（アドレスが Value の範囲にある）、gt、gte、lt、lte（数）、exists。CaseInsensitive で大文字と小文字を区別しない。
type Cond struct {
	All             []Cond   `json:"all,omitempty"`
	Any             []Cond   `json:"any,omitempty"`
	Not             *Cond    `json:"not,omitempty"`
	Field           string   `json:"field,omitempty"`
	Op              string   `json:"op,omitempty"`
	Value           any      `json:"value,omitempty"`
	Values          []string `json:"values,omitempty"`
	CaseInsensitive bool     `json:"case_insensitive,omitempty"`

	path   []string
	lower  []string // CaseInsensitive のときの、小文字にした Values
	re     *regexp.Regexp
	prefix netip.Prefix
	num    float64
	str    string
}

var ops = []string{"eq", "ne", "contains", "prefix", "suffix", "regex", "in", "cidr", "gt", "gte", "lt", "lte", "exists"}

func (c *Cond) prepare(depth int, count *int) error {
	*count++
	if depth > maxDepth || *count > maxConds {
		return fmt.Errorf("条件は入れ子が %d 段、合計 %d 個までです", maxDepth, maxConds)
	}
	kinds := 0
	for _, used := range []bool{len(c.All) > 0, len(c.Any) > 0, c.Not != nil, c.Field != ""} {
		if used {
			kinds++
		}
	}
	if kinds != 1 {
		return errors.New("条件には all、any、not、field のどれか 1 つを書いてください")
	}
	for i := range c.All {
		if err := c.All[i].prepare(depth+1, count); err != nil {
			return err
		}
	}
	for i := range c.Any {
		if err := c.Any[i].prepare(depth+1, count); err != nil {
			return err
		}
	}
	if c.Not != nil {
		return c.Not.prepare(depth+1, count)
	}
	if c.Field == "" {
		return nil
	}
	c.path = strings.Split(c.Field, ".")
	if !slices.Contains(ops, c.Op) {
		return fmt.Errorf("op %q は %s のどれかにしてください", c.Op, strings.Join(ops, "、"))
	}
	switch c.Op {
	case "exists":
		return nil
	case "in":
		if len(c.Values) == 0 {
			return errors.New("in には values を書いてください")
		}
		c.lower = c.Values
		if c.CaseInsensitive {
			c.lower = make([]string, len(c.Values))
			for i, v := range c.Values {
				c.lower[i] = strings.ToLower(v)
			}
		}
		return nil
	case "gt", "gte", "lt", "lte":
		n, ok := c.Value.(float64)
		if !ok {
			return fmt.Errorf("%s の value は数にしてください", c.Op)
		}
		c.num = n
		return nil
	}
	s, ok := c.Value.(string)
	if !ok {
		if n, isNum := c.Value.(float64); isNum && (c.Op == "eq" || c.Op == "ne") {
			c.num, c.str = n, fmt.Sprint(n)
			return nil
		}
		return fmt.Errorf("%s の value は文字列にしてください", c.Op)
	}
	if c.CaseInsensitive {
		s = strings.ToLower(s)
	}
	c.str = s
	switch c.Op {
	case "regex":
		pattern := s
		if c.CaseInsensitive {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("regex %q: %v", s, err)
		}
		c.re = re
	case "cidr":
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("cidr %q: %v", s, err)
		}
		c.prefix = p.Masked()
	}
	return nil
}

// Doc は評価に使うイベントの JSON。
type Doc map[string]any

// NewDoc はイベントを評価できる形にする。
func NewDoc(e *event.Event) (Doc, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	var d Doc
	return d, json.Unmarshal(data, &d)
}

// values はドキュメントの項目の値（配列なら要素ごと）を返す。
func (d Doc) values(path []string) []any {
	cur := []any{map[string]any(d)}
	for _, key := range path {
		var next []any
		for _, v := range cur {
			switch x := v.(type) {
			case map[string]any:
				if child, ok := x[key]; ok {
					next = append(next, child)
				}
			case []any:
				for _, el := range x {
					if m, ok := el.(map[string]any); ok {
						if child, ok := m[key]; ok {
							next = append(next, child)
						}
					}
				}
			}
		}
		cur = next
	}
	var out []any
	for _, v := range cur {
		if arr, ok := v.([]any); ok {
			out = append(out, arr...)
		} else {
			out = append(out, v)
		}
	}
	return out
}

// Get は項目の最初の値を文字列で返す（しきい値の単位などに使う）。
func (d Doc) Get(field string) string {
	vs := d.values(strings.Split(field, "."))
	if len(vs) == 0 || vs[0] == nil {
		return ""
	}
	return fmt.Sprint(vs[0])
}

// Eval は条件に当てはまるかを返す。
func (c *Cond) Eval(d Doc) bool {
	switch {
	case len(c.All) > 0:
		for i := range c.All {
			if !c.All[i].Eval(d) {
				return false
			}
		}
		return true
	case len(c.Any) > 0:
		for i := range c.Any {
			if c.Any[i].Eval(d) {
				return true
			}
		}
		return false
	case c.Not != nil:
		return !c.Not.Eval(d)
	}
	vs := d.values(c.path)
	if c.Op == "exists" {
		return len(vs) > 0
	}
	if c.Op == "ne" {
		for _, v := range vs {
			if c.match("eq", v) {
				return false
			}
		}
		return true
	}
	for _, v := range vs {
		if c.match(c.Op, v) {
			return true
		}
	}
	return false
}

func (c *Cond) match(op string, v any) bool {
	switch op {
	case "gt", "gte", "lt", "lte":
		n, ok := v.(float64)
		if !ok {
			return false
		}
		switch op {
		case "gt":
			return n > c.num
		case "gte":
			return n >= c.num
		case "lt":
			return n < c.num
		}
		return n <= c.num
	}
	var s string
	switch x := v.(type) {
	case string:
		s = x
	case float64, bool:
		s = fmt.Sprint(x)
	default:
		return false
	}
	if c.CaseInsensitive && op != "regex" {
		s = strings.ToLower(s)
	}
	switch op {
	case "eq":
		return s == c.str
	case "contains":
		return strings.Contains(s, c.str)
	case "prefix":
		return strings.HasPrefix(s, c.str)
	case "suffix":
		return strings.HasSuffix(s, c.str)
	case "regex":
		return c.re.MatchString(s)
	case "in":
		return slices.Contains(c.lower, s)
	case "cidr":
		a, err := netip.ParseAddr(s)
		return err == nil && c.prefix.Contains(a.Unmap())
	}
	return false
}
