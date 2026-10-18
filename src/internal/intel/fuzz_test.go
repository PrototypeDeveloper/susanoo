package intel

import (
	"bytes"
	"net/netip"
	"testing"
)

func FuzzParseFeed(f *testing.F) {
	f.Add([]byte(feedText))
	f.Add([]byte("0.0.0.0 a.example b.example\n||c.example^\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		feed, err := ParseFeed(bytes.NewReader(data))
		if err != nil {
			return
		}
		// 取り出したものは、そのまま一覧として検証に通る。
		s := &Set{Version: 1, IssuedAt: now, Lists: []List{{Name: "f", Action: ActionBlock, Domains: feed.Domains, CIDRs: feed.CIDRs}}}
		if len(feed.Domains) <= MaxDomains && len(feed.CIDRs) <= MaxCIDRs {
			if err := s.Validate(); err != nil {
				t.Fatalf("取り込んだ一覧が検証に通らない: %v", err)
			}
		}
		m := NewMatcher(s)
		for _, d := range feed.Domains {
			if len(m.Domain(d)) == 0 {
				t.Fatalf("取り込んだドメイン %q に当てはまらない", d)
			}
		}
		for _, c := range feed.CIDRs {
			if len(m.Addr(netip.MustParsePrefix(c).Addr())) == 0 {
				t.Fatalf("取り込んだ範囲 %q に当てはまらない", c)
			}
		}
	})
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"version": 1, "issued_at": "2026-10-19T00:00:00Z", "lists": [{"name": "a", "action": "block", "updated": "2026-10-19T00:00:00Z", "domains": ["a.example"], "cidrs": ["203.0.113.0/24"]}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := Parse(data)
		if err != nil {
			return
		}
		m := NewMatcher(s)
		m.Domain("a.example")
		m.Addr(netip.MustParseAddr("203.0.113.1"))
		s.BlockedPrefixes()
		s.Blocklist().Matcher()
	})
}
