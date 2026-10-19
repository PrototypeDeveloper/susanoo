package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
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

// 直接指定したアドレスは、プロトコルとポートつきの CIDR の許可にする（同じものは二重に加えない）。
func TestSuggestedPolicyAddresses(t *testing.T) {
	current, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "policy.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := api.AllowSuggestion{Group: "default", Allow: []api.SuggestedDestination{
		{CIDR: "203.0.113.7/32", Protocol: "tcp", Ports: []int{22, 8443}}, {CIDR: "203.0.113.8/32", Protocol: "udp", Ports: []int{123}},
		{CIDR: "203.0.113.7/32", Protocol: "tcp", Ports: []int{22, 8443}}, {CIDR: "203.0.113.9/32"},
	}}
	data, added, err := suggestedPolicy(current, s)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range p.Group("default").Egress.Allow {
		if d.CIDR != "" {
			got = append(got, fmt.Sprint(d.CIDR, " ", d.Protocol, " ", d.Ports))
		}
	}
	want := []string{"203.0.113.7/32 tcp [22 8443]", "203.0.113.8/32 udp [123]", "203.0.113.9/32  []"}
	if added != 3 || !slices.Equal(got, want) {
		t.Errorf("CIDR の許可 = %q（加えた件数 %d）", got, added)
	}
}
