package egress

import (
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 許可への追加の検査（2m-2）。執行部は、DNS で得たアドレスを許可に加える前に、加えてよいアドレスかを確かめる。
// LAN 側の処理（DNS のリゾルバ）が乗っ取られても、DNS の応答を改ざんされても（DNS リバインディング）、
// 特別な用途のアドレス、LAN のアドレス、私的なアドレスを許可に加えさせず、短い間に大量のアドレスを加えさせない。
// 断ったアドレスと加えたアドレスは CONTROLLER に知らせる（加えたアドレスは、DNS の応答の記録と突き合わせる）。

// maxNewPerMinute は、1 つの集合に 1 分間に新しく加えるアドレスの上限。
const maxNewPerMinute = 256

// 断った理由。
const (
	RefuseSpecial = "特別な用途のアドレス"
	RefuseLAN     = "LAN のアドレス"
	RefusePrivate = "私的なアドレス（DNS リバインディングの疑い）"
	RefuseRate    = "短い間に多すぎる追加"
)

// LearnReport は、DNS で得たアドレスを許可に加えた結果（執行部が CONTROLLER に知らせる）。
type LearnReport struct {
	Time    time.Time     `json:"time"`
	Group   string        `json:"group,omitempty"` // グループの名前（更新サーバーなら空）
	Updates bool          `json:"updates,omitempty"`
	Added   []netip.Addr  `json:"added,omitempty"`
	Refused []RefusedAddr `json:"refused,omitempty"`
}

// RefusedAddr は許可に加えなかったアドレスと理由。
type RefusedAddr struct {
	Addr   netip.Addr `json:"addr"`
	Reason string     `json:"reason"`
}

var (
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	reserved4   = netip.MustParsePrefix("240.0.0.0/4") // 255.255.255.255 を含む
	sharedCGNAT = netip.MustParsePrefix("100.64.0.0/10")
)

// refuseReason は、DNS で得たアドレス ip を許可に加えない理由を返す（加えてよければ空）。
func (e *Engine) refuseReason(ip netip.Addr, allowPrivate bool) string {
	switch {
	case ip.IsLoopback(), ip.IsMulticast(), ip.IsLinkLocalUnicast(), thisNetwork.Contains(ip), reserved4.Contains(ip):
		return RefuseSpecial
	}
	for _, p := range e.cfg.LANPrefixes {
		if p.Contains(ip) {
			return RefuseLAN
		}
	}
	if !allowPrivate && (ip.IsPrivate() || sharedCGNAT.Contains(ip)) {
		return RefusePrivate
	}
	return ""
}

// learnRate は 1 つの集合に加えたアドレスと、1 分間に新しく加えた数。
type learnRate struct {
	seen        map[netip.Addr]time.Time // 加えた（期限を延ばした）時刻
	windowStart time.Time
	count       int
}

// learnGuard は集合ごとの追加の数を数える。
type learnGuard struct {
	mu   sync.Mutex
	sets map[string]*learnRate
}

// allow は、集合 key に ip を加えてよいかを返す。すでに加えたアドレス（期限を延ばすだけ）は数えない。
func (g *learnGuard) allow(key string, ip netip.Addr, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sets == nil {
		g.sets = map[string]*learnRate{}
	}
	r := g.sets[key]
	if r == nil {
		r = &learnRate{seen: map[netip.Addr]time.Time{}}
		g.sets[key] = r
	}
	alive := maxLearnTTL + learnGrace
	if t, ok := r.seen[ip]; ok && now.Sub(t) < alive {
		r.seen[ip] = now
		return true
	}
	if now.Sub(r.windowStart) >= time.Minute {
		r.windowStart, r.count = now, 0
		for a, t := range r.seen { // 集合から消えたアドレスを忘れる
			if now.Sub(t) >= alive {
				delete(r.seen, a)
			}
		}
	}
	if r.count >= maxNewPerMinute {
		return false
	}
	r.count++
	r.seen[ip] = now
	return true
}

// targetKey は Target の集合の識別。
func targetKey(t Target) string {
	if t.Updates {
		return "updates"
	}
	var b strings.Builder
	b.WriteString(strconv.Itoa(t.Group))
	for _, s := range t.Specs {
		b.WriteString("/" + strconv.Itoa(s))
	}
	return b.String()
}

// OnLearned は、DNS で得たアドレスを許可に加えた結果を知らせる関数を設定する（執行部の Engine で使う）。
func (e *Engine) OnLearned(f func(LearnReport)) { e.onLearned.Store(&f) }

func (e *Engine) reportLearned(r LearnReport) {
	if f := e.onLearned.Load(); f != nil && (len(r.Added) > 0 || len(r.Refused) > 0) {
		(*f)(r)
	}
}
