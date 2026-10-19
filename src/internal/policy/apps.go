package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
)

// プロセス単位の通信の制御（C7）。グループごとに、端末の CLIENT が、どのプロセスがどの宛先に接続してよいかを決める。
// GW を通らない別の回線（テザリングなど）でも、端末の上で働く。AI エージェント（C9 の帰属）の配下のプロセスの
// 通信先も、このルールで制限する。

// AppMode は制御の扱い。
type AppMode string

const (
	AppMonitor AppMode = "monitor" // 拒否に当たる接続も通し、記録だけする（試験運用）
	AppEnforce AppMode = "enforce" // 拒否に当たる接続を拒否する
)

// AppAction は接続の扱い。
type AppAction string

const (
	AppAllow AppAction = "allow"
	AppDeny  AppAction = "deny"
)

// 上限（ルールが大きすぎると、接続のたびの判断に時間がかかるため）。
const (
	maxAppRules   = 500
	maxAppEntries = 100
)

// AppControl はプロセス単位の通信の制御の設定（ポリシーのグループの apps）。
type AppControl struct {
	Mode    AppMode   `json:"mode"`    // monitor か enforce
	Default AppAction `json:"default"` // どのルールにも当てはまらない接続の扱い（allow か deny）
	Rules   []AppRule `json:"rules,omitempty"`
}

// AppRule はルール。上から順に比べ、最初に当てはまったルールの扱いに従う。
//
// プロセスの条件（exe、names、agents）は、書いたものがすべて当てはまるときに当てはまる（それぞれの一覧の中は、どれか 1 つ）。
// どれも書かなければ、すべてのプロセスに当てはまる。宛先（dst）を書かなければ、すべての宛先に当てはまる。
type AppRule struct {
	Name   string        `json:"name"`
	Exe    []string      `json:"exe,omitempty"`    // 実行ファイルのパス。「/」で終われば、そのディレクトリの下のすべて
	Names  []string      `json:"names,omitempty"`  // プロセスの名前（実行ファイルの名前か、起動したときの名前）
	Agents []string      `json:"agents,omitempty"` // AI エージェントの名前（プロセスかその祖先がそのエージェント）。「*」ですべてのエージェント
	Dst    []Destination `json:"dst,omitempty"`    // 宛先。ドメインは CLIENT が名前を引いて得たアドレスで比べる（「*.」は使えない）
	Action AppAction     `json:"action"`
}

// validate は設定を確かめる。
func (a *AppControl) validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	switch a.Mode {
	case AppMonitor, AppEnforce:
	default:
		add("apps.mode %q は monitor か enforce にしてください", a.Mode)
	}
	switch a.Default {
	case AppAllow, AppDeny:
	default:
		add("apps.default %q は allow か deny にしてください", a.Default)
	}
	if len(a.Rules) > maxAppRules {
		add("apps.rules は %d 個までです", maxAppRules)
	}
	for i, r := range a.Rules {
		where := fmt.Sprintf("apps.rules[%d]（%s）", i, r.Name)
		if strings.TrimSpace(r.Name) == "" {
			add("%s: name がありません", where)
		}
		switch r.Action {
		case AppAllow, AppDeny:
		default:
			add("%s: action %q は allow か deny にしてください", where, r.Action)
		}
		if len(r.Exe) > maxAppEntries || len(r.Names) > maxAppEntries || len(r.Agents) > maxAppEntries || len(r.Dst) > maxAppEntries {
			add("%s: exe、names、agents、dst はそれぞれ %d 個までです", where, maxAppEntries)
		}
		for _, e := range r.Exe {
			if !filepath.IsAbs(e) || (filepath.Clean(e) != e && filepath.Clean(e)+"/" != e) {
				add("%s: exe %q は正規化した絶対パスで書いてください", where, e)
			}
		}
		for _, n := range slices.Concat(r.Names, r.Agents) {
			if n == "" || strings.ContainsAny(n, "/ \t") {
				add("%s: names、agents の %q が不正です", where, n)
			}
		}
		for j, d := range r.Dst {
			if strings.HasPrefix(d.Domain, "*.") {
				add("%s.dst[%d]: CLIENT は名前を引いてアドレスで比べるので、「*.」のドメインは使えません", where, j)
				continue
			}
			if err := d.validate(); err != nil {
				add("%s.dst[%d]: %v", where, j, err)
			}
		}
	}
	return errors.Join(errs...)
}

// Domains はルールに書いたドメインを返す（CLIENT が名前を引くため）。
func (a *AppControl) Domains() []string {
	if a == nil {
		return nil
	}
	var out []string
	for _, r := range a.Rules {
		for _, d := range r.Dst {
			if d.Domain != "" && !slices.Contains(out, d.Domain) {
				out = append(out, d.Domain)
			}
		}
	}
	return out
}

// AppConn は判断する接続。
type AppConn struct {
	Exe   string     // 実行ファイルのパス（分からなければ空）
	Name  string     // プロセスの名前（分からなければ空）
	Agent string     // プロセスかその祖先の AI エージェントの名前（なければ空）
	Dst   netip.Addr // 宛先
	Port  uint16     // 宛先のポート
	Proto string     // tcp か udp
}

// Decide は接続の扱いと、当てはまったルール（どれにも当てはまらなければ nil）を返す。resolve はドメインのアドレスを返す。
func (a *AppControl) Decide(c AppConn, resolve func(domain string) []netip.Addr) (AppAction, *AppRule) {
	for i := range a.Rules {
		r := &a.Rules[i]
		if r.matchProcess(c) && r.matchDst(c, resolve) {
			return r.Action, r
		}
	}
	return a.Default, nil
}

func (r *AppRule) matchProcess(c AppConn) bool {
	if len(r.Exe) > 0 && !slices.ContainsFunc(r.Exe, func(e string) bool {
		return c.Exe != "" && (e == c.Exe || strings.HasSuffix(e, "/") && strings.HasPrefix(c.Exe, e))
	}) {
		return false
	}
	if len(r.Names) > 0 && !slices.ContainsFunc(r.Names, func(n string) bool {
		return n == c.Name || (c.Exe != "" && n == filepath.Base(c.Exe))
	}) {
		return false
	}
	if len(r.Agents) > 0 && !slices.ContainsFunc(r.Agents, func(n string) bool { return c.Agent != "" && (n == "*" || n == c.Agent) }) {
		return false
	}
	return true
}

func (r *AppRule) matchDst(c AppConn, resolve func(string) []netip.Addr) bool {
	if len(r.Dst) == 0 {
		return true
	}
	dst := c.Dst.Unmap()
	for _, d := range r.Dst {
		if len(d.Ports) > 0 && !slices.Contains(d.Ports, c.Port) {
			continue
		}
		if d.Protocol != "" && d.Protocol != c.Proto {
			continue
		}
		switch {
		case d.CIDR != "":
			if p, err := netip.ParsePrefix(d.CIDR); err == nil && p.Contains(dst) {
				return true
			}
		case d.Domain != "" && resolve != nil:
			if slices.ContainsFunc(resolve(d.Domain), func(a netip.Addr) bool { return a.Unmap() == dst }) {
				return true
			}
		}
	}
	return false
}
