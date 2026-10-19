package egress

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"susanoo/internal/dns"
)

// 許可に加える前に、特別な用途、LAN、私的なアドレスを断り、短い間の大量の追加を断る。断ったアドレスと加えたアドレスを知らせる。
func TestLearnGuard(t *testing.T) {
	r := &recorder{}
	e, err := New(Config{Policy: testPolicy, LAN: "lan0", NFT: r, LANPrefixes: []netip.Prefix{netip.MustParsePrefix("10.77.0.0/24")},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var reports []LearnReport
	e.OnLearned(func(lr LearnReport) { mu.Lock(); reports = append(reports, lr); mu.Unlock() })
	e.SetMembership(context.Background(), membership())
	learn := func(name string, ips ...string) LearnReport {
		t.Helper()
		var addrs []netip.Addr
		for _, s := range ips {
			addrs = append(addrs, netip.MustParseAddr(s))
		}
		mu.Lock()
		before := len(reports)
		mu.Unlock()
		v := e.Decide(pcStrict, dns.Question{Name: name, Type: dns.TypeA})
		if err := v.Learn(context.Background(), addrs, time.Minute); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(reports) == before {
			return LearnReport{}
		}
		return reports[len(reports)-1]
	}

	got := learn("a.cdn.test", "192.0.2.10", "0.0.0.0", "127.0.0.1", "224.0.0.1", "169.254.1.1", "255.255.255.255",
		"10.77.0.5", "192.168.77.1", "172.16.0.1", "100.64.0.1", "fd00::1", "2001:db8::10")
	if got.Group != "strict" || !slices.Equal(got.Added, []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}) {
		t.Fatalf("加えたアドレス = %+v", got)
	}
	want := map[string]string{"127.0.0.1": RefuseSpecial, "224.0.0.1": RefuseSpecial, "169.254.1.1": RefuseSpecial, "255.255.255.255": RefuseSpecial,
		"10.77.0.5": RefuseLAN, "192.168.77.1": RefusePrivate, "172.16.0.1": RefusePrivate, "100.64.0.1": RefusePrivate, "fd00::1": RefusePrivate}
	if len(got.Refused) != len(want) {
		t.Errorf("断ったアドレス = %+v", got.Refused)
	}
	for _, a := range got.Refused {
		if want[a.Addr.String()] != a.Reason {
			t.Errorf("%s を断った理由 = %q（%q のはず）", a.Addr, a.Reason, want[a.Addr.String()])
		}
	}
	last := r.all()[len(r.all())-1]
	for _, bad := range []string{"192.168.77.1", "10.77.0.5", "127.0.0.1", "0.0.0.0"} {
		if strings.Contains(last, bad) {
			t.Errorf("断ったアドレス %s を集合に加えました:\n%s", bad, last)
		}
	}
	// 未指定のアドレスだけなら、何も知らせない（遮断の代わりに返す DNS もある）。
	if got := learn("a.cdn.test", "0.0.0.0"); got.Group != "" {
		t.Errorf("未指定のアドレスだけで知らせました: %+v", got)
	}

	// 1 分間に新しく加えるアドレスは maxNewPerMinute まで。すでに加えたアドレスの期限を延ばすのは数えない。
	var many []string
	for i := range maxNewPerMinute + 10 {
		many = append(many, netip.AddrFrom4([4]byte{198, 51, byte(i / 256), byte(i % 256)}).String())
	}
	got = learn("b.cdn.test", many...)
	if len(got.Added) != maxNewPerMinute-2 || len(got.Refused) != 12 || got.Refused[0].Reason != RefuseRate { // 先に加えた 2 個の分だけ少ない
		t.Errorf("大量の追加 = 加えた %d、断った %d", len(got.Added), len(got.Refused))
	}
	if got := learn("c.cdn.test", "192.0.2.10"); len(got.Added) != 1 {
		t.Errorf("加えたアドレスの期限を延ばせません: %+v", got)
	}
}

// グループの bypass.allow_private_dns では、私的なアドレスも許可に加える（LAN と特別な用途のアドレスは加えない）。
func TestLearnAllowPrivate(t *testing.T) {
	p := *testPolicy
	p.Groups = slices.Clone(testPolicy.Groups)
	p.Groups[0].Bypass.AllowPrivateDNS = true
	r := &recorder{}
	e, err := New(Config{Policy: &p, LAN: "lan0", NFT: r, LANPrefixes: []netip.Prefix{netip.MustParsePrefix("10.77.0.0/24")},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	var got LearnReport
	e.OnLearned(func(lr LearnReport) { got = lr })
	e.SetMembership(context.Background(), membership())
	v := e.Decide(pcStrict, dns.Question{Name: "allowed.test", Type: dns.TypeA})
	v.Learn(context.Background(), []netip.Addr{netip.MustParseAddr("192.168.77.10"), netip.MustParseAddr("10.77.0.9")}, time.Minute)
	if !slices.Equal(got.Added, []netip.Addr{netip.MustParseAddr("192.168.77.10")}) || len(got.Refused) != 1 || got.Refused[0].Reason != RefuseLAN {
		t.Errorf("私的なアドレスを許したときの結果 = %+v", got)
	}
	// 隔離中の更新サーバーにはグループの例外を使わない。
	v = e.Decide(pcIsolated, dns.Question{Name: "updates.test", Type: dns.TypeA})
	v.Learn(context.Background(), []netip.Addr{netip.MustParseAddr("192.168.77.11")}, time.Minute)
	if !got.Updates || len(got.Added) != 0 || len(got.Refused) != 1 {
		t.Errorf("更新サーバーの結果 = %+v", got)
	}
}
