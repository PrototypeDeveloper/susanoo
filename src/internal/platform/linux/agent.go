//go:build linux

package linux

import (
	"path/filepath"
	"strings"

	"susanoo/internal/event"
)

// AI エージェントの帰属（C9）。端末の上で動く AI エージェント（コーディングエージェントなど）が起動したコマンドと
// 通信を見分けられるよう、プロセスの祖先に設定したエージェントがあれば、イベントに unmapped.agent（名前と PID）を付ける。
// 検知ルールは unmapped.agent.name で、エージェントの操作（権限の操作、永続化の場所の変更、認証情報の読み取りなど）に
// 条件を付けられる。通信の制限は 2e（C7）で行う。

// AgentSpec は設定ファイルに書く AI エージェントの指定。
type AgentSpec struct {
	Name  string   `json:"name"`  // イベントに付ける名前
	Match []string `json:"match"` // プロセスの名前（comm、実行ファイルかコマンドラインの先頭の名前）か、「/」を含むならコマンドラインに含まれる文字列
}

// DefaultAgents は既定で見分ける AI エージェント。CLI のコーディングエージェントのうち、よく使われるもの。
func DefaultAgents() []AgentSpec {
	return []AgentSpec{
		{Name: "claude", Match: []string{"claude", "@anthropic-ai/claude-code/"}},
		{Name: "codex", Match: []string{"codex", "@openai/codex/"}},
		{Name: "gemini", Match: []string{"gemini", "@google/gemini-cli/"}},
		{Name: "copilot", Match: []string{"copilot", "@github/copilot/"}},
		{Name: "aider", Match: []string{"aider"}},
		{Name: "goose", Match: []string{"goose"}},
		{Name: "opencode", Match: []string{"opencode"}},
		{Name: "cursor", Match: []string{"cursor-agent"}},
	}
}

// agentMatcher はプロセスがどのエージェントかを見分ける。
type agentMatcher struct {
	specs []AgentSpec
}

func newAgentMatcher(specs []AgentSpec) *agentMatcher {
	m := &agentMatcher{}
	for _, s := range specs {
		if s.Name == "" || len(s.Match) == 0 {
			continue
		}
		m.specs = append(m.specs, s)
	}
	return m
}

// agentTag はイベントに付けるエージェントの情報。
type agentTag struct {
	Name string `json:"name"`
	PID  int    `json:"pid"`
}

// of は、プロセス p かその祖先 anc のうち、最も近いエージェントを返す。なければ false。
func (m *agentMatcher) of(p *event.Process, anc []ancestor) (agentTag, bool) {
	if m == nil || len(m.specs) == 0 {
		return agentTag{}, false
	}
	if p != nil {
		a := ancestor{pid: p.PID, name: p.Name, argv: p.CmdLine}
		if p.File != nil {
			a.exe = p.File.Path
		}
		if name, ok := m.match(a); ok {
			return agentTag{Name: name, PID: p.PID}, true
		}
	}
	for _, a := range anc {
		if name, ok := m.match(a); ok {
			return agentTag{Name: name, PID: a.pid}, true
		}
	}
	return agentTag{}, false
}

func (m *agentMatcher) match(a ancestor) (string, bool) {
	argv0, _, _ := strings.Cut(a.argv, " ")
	names := []string{a.name, filepath.Base(a.exe), filepath.Base(argv0)}
	for _, s := range m.specs {
		for _, pat := range s.Match {
			if strings.Contains(pat, "/") {
				if strings.Contains(a.argv, pat) {
					return s.Name, true
				}
				continue
			}
			for _, n := range names {
				if n != "" && n != "." && n == pat {
					return s.Name, true
				}
			}
		}
	}
	return "", false
}

// annotate は、プロセス p（かその祖先）がエージェントの配下なら、イベント e に unmapped.agent を付ける。
func (m *agentMatcher) annotate(e *event.Event, p *event.Process, anc []ancestor) {
	tag, ok := m.of(p, anc)
	if !ok {
		return
	}
	if e.Unmapped == nil {
		e.Unmapped = map[string]any{}
	}
	e.Unmapped["agent"] = tag
}
