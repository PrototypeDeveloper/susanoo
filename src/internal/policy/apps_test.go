package policy

import (
	"net/netip"
	"strings"
	"testing"
)

func appControl() *AppControl {
	return &AppControl{Mode: AppEnforce, Default: AppAllow, Rules: []AppRule{
		{Name: "AI エージェントは API だけ", Agents: []string{"claude"}, Dst: []Destination{{Domain: "api.anthropic.com", Ports: []uint16{443}}}, Action: AppAllow},
		{Name: "AI エージェントのほかの通信", Agents: []string{"*"}, Action: AppDeny},
		{Name: "curl は社内だけ", Names: []string{"curl"}, Dst: []Destination{{CIDR: "192.168.10.0/24"}}, Action: AppAllow},
		{Name: "curl のほか", Names: []string{"curl"}, Action: AppDeny},
		{Name: "/opt の下のアプリ", Exe: []string{"/opt/"}, Dst: []Destination{{CIDR: "203.0.113.0/24", Protocol: "udp"}}, Action: AppDeny},
	}}
}

func TestAppDecide(t *testing.T) {
	a := appControl()
	resolve := func(d string) []netip.Addr {
		if d == "api.anthropic.com" {
			return []netip.Addr{netip.MustParseAddr("198.51.100.7")}
		}
		return nil
	}
	ip := netip.MustParseAddr
	for name, tc := range map[string]struct {
		c    AppConn
		want AppAction
		rule string
	}{
		"エージェントの API":        {AppConn{Exe: "/usr/bin/node", Agent: "claude", Dst: ip("198.51.100.7"), Port: 443, Proto: "tcp"}, AppAllow, "AI エージェントは API だけ"},
		"エージェントの API（別のポート）": {AppConn{Exe: "/usr/bin/node", Agent: "claude", Dst: ip("198.51.100.7"), Port: 80, Proto: "tcp"}, AppDeny, "AI エージェントのほかの通信"},
		"ほかのエージェント":          {AppConn{Exe: "/usr/bin/curl", Name: "curl", Agent: "codex", Dst: ip("198.51.100.7"), Port: 443, Proto: "tcp"}, AppDeny, "AI エージェントのほかの通信"},
		"curl の社内":           {AppConn{Exe: "/usr/bin/curl", Name: "curl", Dst: ip("192.168.10.5"), Port: 443, Proto: "tcp"}, AppAllow, "curl は社内だけ"},
		"curl の外":            {AppConn{Exe: "/usr/bin/curl", Name: "curl", Dst: ip("203.0.113.5"), Port: 443, Proto: "tcp"}, AppDeny, "curl のほか"},
		"名前は実行ファイルからも":       {AppConn{Exe: "/usr/bin/curl", Dst: ip("203.0.113.5"), Port: 443, Proto: "tcp"}, AppDeny, "curl のほか"},
		"/opt の下の UDP":       {AppConn{Exe: "/opt/x/bin/app", Dst: ip("203.0.113.9"), Port: 53, Proto: "udp"}, AppDeny, "/opt の下のアプリ"},
		"/opt の下の TCP":       {AppConn{Exe: "/opt/x/bin/app", Dst: ip("203.0.113.9"), Port: 53, Proto: "tcp"}, AppAllow, ""},
		"/opt を名前に含むだけ":      {AppConn{Exe: "/optional/app", Dst: ip("203.0.113.9"), Port: 53, Proto: "udp"}, AppAllow, ""},
		"分からないプロセス":          {AppConn{Dst: ip("203.0.113.9"), Port: 443, Proto: "tcp"}, AppAllow, ""},
		"IPv4 射影アドレス":        {AppConn{Name: "curl", Dst: ip("::ffff:192.168.10.5"), Port: 443, Proto: "tcp"}, AppAllow, "curl は社内だけ"},
	} {
		got, rule := a.Decide(tc.c, resolve)
		ruleName := ""
		if rule != nil {
			ruleName = rule.Name
		}
		if got != tc.want || ruleName != tc.rule {
			t.Errorf("%s = %s（%q）, 期待値 %s（%q）", name, got, ruleName, tc.want, tc.rule)
		}
	}
	// 既定が拒否なら、どれにも当てはまらない接続を拒否する。
	a.Default = AppDeny
	if got, rule := a.Decide(AppConn{Exe: "/usr/bin/firefox", Dst: ip("203.0.113.1"), Port: 443, Proto: "tcp"}, resolve); got != AppDeny || rule != nil {
		t.Errorf("既定の拒否 = %s %v", got, rule)
	}
	if d := a.Domains(); len(d) != 1 || d[0] != "api.anthropic.com" {
		t.Errorf("ドメイン = %v", d)
	}
}

func TestAppValidate(t *testing.T) {
	if err := appControl().validate(); err != nil {
		t.Fatalf("正しい設定 = %v", err)
	}
	for name, tc := range map[string]struct {
		a    AppControl
		want string
	}{
		"扱いが不正":     {AppControl{Mode: "block", Default: AppAllow}, "apps.mode"},
		"既定が不正":     {AppControl{Mode: AppMonitor, Default: "learn"}, "apps.default"},
		"名前がない":     {AppControl{Mode: AppMonitor, Default: AppAllow, Rules: []AppRule{{Action: AppDeny}}}, "name"},
		"ルールの扱い":    {AppControl{Mode: AppMonitor, Default: AppAllow, Rules: []AppRule{{Name: "x", Action: "drop"}}}, "action"},
		"相対パス":      {AppControl{Mode: AppMonitor, Default: AppAllow, Rules: []AppRule{{Name: "x", Exe: []string{"bin/curl"}, Action: AppDeny}}}, "exe"},
		"正規化していない":  {AppControl{Mode: AppMonitor, Default: AppAllow, Rules: []AppRule{{Name: "x", Exe: []string{"/usr/../bin/sh"}, Action: AppDeny}}}, "exe"},
		"名前に空白":     {AppControl{Mode: AppMonitor, Default: AppAllow, Rules: []AppRule{{Name: "x", Names: []string{"my app"}, Action: AppDeny}}}, "names"},
		"「*.」のドメイン": {AppControl{Mode: AppMonitor, Default: AppAllow, Rules: []AppRule{{Name: "x", Dst: []Destination{{Domain: "*.example.jp"}}, Action: AppDeny}}}, "「*.」"},
		"宛先が不正":     {AppControl{Mode: AppMonitor, Default: AppAllow, Rules: []AppRule{{Name: "x", Dst: []Destination{{CIDR: "10.0.0.1/8"}}, Action: AppDeny}}}, "cidr"},
	} {
		if err := tc.a.validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s = %v（%q を含むはず）", name, err, tc.want)
		}
	}
}
