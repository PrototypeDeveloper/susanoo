package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"susanoo/internal/api"
	"susanoo/internal/policy"
)

func TestSuggestedPolicy(t *testing.T) {
	current, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "policy.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := api.AllowSuggestion{Group: "default", Allow: []api.SuggestedDestination{{Domain: "*.example.jp"}, {Domain: "example.jp"}, {Domain: "*.example.jp"}}}
	data, added, err := suggestedPolicy(current, s)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Parse(data)
	if err != nil {
		t.Fatalf("案のポリシーが読めない: %v", err)
	}
	g := p.Group("default")
	if g.Egress.Default != policy.EgressDeny || g.Egress.LearnPeriod != 0 || added != 2 || !strings.Contains(p.Name, "default を原則拒否に") {
		t.Errorf("案 = %+v（加えた件数 %d、名前 %q）", g.Egress, added, p.Name)
	}
	if n := len(g.Egress.Allow); n != 2 {
		t.Errorf("許可リスト = %+v", g.Egress.Allow)
	}
	// ほかのグループは変えない。
	if p.Group("server").Egress.Default != policy.EgressDeny || len(p.Group("server").Egress.Allow) != 2 {
		t.Errorf("server = %+v", p.Group("server").Egress)
	}
	if _, _, err := suggestedPolicy(current, api.AllowSuggestion{Group: "nothing"}); err == nil {
		t.Error("ないグループの案を作った")
	}
}
