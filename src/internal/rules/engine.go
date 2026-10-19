package rules

import (
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"susanoo/internal/behavior"
	"susanoo/internal/event"
)

// Engine は、既定のルールに配布したルールを重ねたものを評価する。作った後は変更しないので、ロックなしで共有できる。
type Engine struct {
	Set      *Set   // 配布したルール（なければ nil）
	Rules    []Rule // 評価に使うルール（既定のルールを含む）
	HalfLife time.Duration

	byFinding  map[string][]*Rule
	byClass    map[event.ClassUID][]*Rule
	exceptions []Exception
}

// NewEngine は検知ルール s（nil なら既定のルールだけ）を評価する Engine を作る。s は Parse で検証済みのもの。
func NewEngine(s *Set) *Engine {
	e := &Engine{Set: s, Rules: Merge(s), HalfLife: DefaultHalfLife, byFinding: map[string][]*Rule{}, byClass: map[event.ClassUID][]*Rule{}}
	if s != nil {
		e.HalfLife = s.Scoring.HalfLife.Or(DefaultHalfLife)
		e.exceptions = s.Exceptions
	}
	for i := range e.Rules {
		r := &e.Rules[i]
		switch {
		case r.Mode == ModeOff:
		case r.Finding != "":
			e.byFinding[r.Finding] = append(e.byFinding[r.Finding], r)
		default:
			e.byClass[r.classUID] = append(e.byClass[r.classUID], r)
		}
	}
	return e
}

// Version は配布したルールの版数を返す（既定のルールだけなら 0）。
func (e *Engine) Version() int {
	if e.Set == nil {
		return 0
	}
	return e.Set.Version
}

// Watches は、検知結果の種類 findingType に、使っている（off でない）ルールがあるかを返す。
// 振る舞いの検知は、使っているルールがある種類だけを行う。
func (e *Engine) Watches(findingType string) bool { return len(e.byFinding[findingType]) > 0 }

// Behavior は振る舞いの検知の設定を返す。
func (e *Engine) Behavior() behavior.Config {
	if e.Set == nil {
		return behavior.Config{}
	}
	return e.Set.Behavior
}

// Classes は、評価する種類（条件のルールのある種類と、検知結果のルールがあれば検知結果）を返す。
// 保存したイベントを評価し直すとき、解析する前に行を絞り込むのに使う。
func (e *Engine) Classes() []event.ClassUID {
	var out []event.ClassUID
	for c, rs := range e.byClass {
		if len(rs) > 0 {
			out = append(out, c)
		}
	}
	if len(e.byFinding) > 0 && !slices.Contains(out, event.ClassDetectionFinding) {
		out = append(out, event.ClassDetectionFinding)
	}
	slices.Sort(out)
	return out
}

// Relevant は、イベントに関係しうるルールがあるかを返す（なければ評価を省く）。
func (e *Engine) Relevant(ev *event.Event) bool {
	if len(e.byClass[ev.ClassUID]) > 0 {
		return true
	}
	if ev.ClassUID == event.ClassDetectionFinding && ev.FindingInfo != nil {
		for _, t := range ev.FindingInfo.Types {
			if len(e.byFinding[t]) > 0 {
				return true
			}
		}
	}
	return false
}

func (e *Engine) candidates(ev *event.Event) []*Rule {
	var out []*Rule
	if ev.ClassUID == event.ClassDetectionFinding && ev.FindingInfo != nil {
		for _, t := range ev.FindingInfo.Types {
			for _, r := range e.byFinding[t] {
				if !slices.Contains(out, r) {
					out = append(out, r)
				}
			}
		}
	}
	return append(out, e.byClass[ev.ClassUID]...)
}

// Subject は評価の対象（端末か機器）。
type Subject struct {
	Key   string   // 危険度としきい値を数える単位（device:端末 ID、host:MAC アドレス）。分からなければ空
	Group string   // グループ（ルールの groups と例外の groups と比べる）
	IDs   []string // 端末 ID、MAC アドレス、アドレス（例外の devices と比べる）
}

// Hit はルールに当てはまった結果。
type Hit struct {
	Rule     *Rule
	Excepted *Exception // 誤検知の例外に当てはまったら、その例外
}

// Evaluate はイベント ev が当てはまるルールを返す。例外に当てはまったものも Excepted を付けて返す（数えるため）。
// しきい値のあるルールは counter で数え、回数に届いたときだけ返す。
func (e *Engine) Evaluate(ev *event.Event, sub Subject, counter *Counter, now time.Time) []Hit {
	cands := e.candidates(ev)
	if len(cands) == 0 {
		return nil
	}
	var doc Doc
	getDoc := func() Doc {
		if doc == nil {
			if d, err := NewDoc(ev); err == nil && d != nil {
				doc = d
			} else {
				doc = Doc{}
			}
		}
		return doc
	}
	var hits []Hit
	for _, r := range cands {
		if len(r.Groups) > 0 && !slices.Contains(r.Groups, sub.Group) {
			continue
		}
		if r.Match != nil && !r.Match.Eval(getDoc()) {
			continue
		}
		hit := Hit{Rule: r}
		for i := range e.exceptions {
			if e.exceptions[i].applies(r.ID, sub, getDoc, now) {
				hit.Excepted = &e.exceptions[i]
				break
			}
		}
		if t := r.Threshold; t != nil && hit.Excepted == nil {
			key := sub.Key
			if t.By != "" {
				key = getDoc().Get(t.By)
			}
			if key == "" || !counter.Add(r.ID+"\x00"+key, t.Count, t.Window.Or(0), now) {
				continue
			}
		}
		hits = append(hits, hit)
	}
	return hits
}

// applies は、ルール ruleID の対象 sub への検知が、例外に当てはまるかを返す。
func (x *Exception) applies(ruleID string, sub Subject, doc func() Doc, now time.Time) bool {
	switch {
	case !x.Until.IsZero() && now.After(x.Until),
		!slices.Contains(x.Rules, "*") && !slices.Contains(x.Rules, ruleID),
		len(x.Groups) > 0 && !slices.Contains(x.Groups, sub.Group):
		return false
	}
	if len(x.Devices) > 0 && !slices.ContainsFunc(x.Devices, func(d string) bool {
		return slices.ContainsFunc(sub.IDs, func(id string) bool { return strings.EqualFold(id, d) })
	}) {
		return false
	}
	return x.Match == nil || x.Match.Eval(doc())
}

// Counter は、しきい値のあるルールに当てはまった回数を、ルールと単位ごとに数える。
// 回数は、今の区間と 1 つ前の区間の回数から見積もる（スライディングウィンドウの近似。記憶する量を一定にするため）。
type Counter struct {
	mu sync.Mutex
	m  map[string]*window
}

type window struct {
	start     time.Time
	length    time.Duration
	cur, prev int
}

// maxCounterKeys は数える単位の上限。超えたら古いものから捨てる。
const maxCounterKeys = 10000

// Add は key の回数を 1 増やし、length の間に count 回に届いたら true を返して数え直す。
func (c *Counter) Add(key string, count int, length time.Duration, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*window{}
	}
	w := c.m[key]
	if w == nil {
		if len(c.m) >= maxCounterKeys {
			c.pruneLocked(now)
		}
		w = &window{start: now, length: length}
		c.m[key] = w
	}
	switch elapsed := now.Sub(w.start); {
	case elapsed >= 2*w.length || elapsed < 0:
		w.start, w.cur, w.prev = now, 0, 0
	case elapsed >= w.length:
		w.start, w.prev, w.cur = w.start.Add(w.length), w.cur, 0
	}
	w.cur++
	rest := 1 - float64(now.Sub(w.start))/float64(w.length)
	if float64(w.prev)*max(rest, 0)+float64(w.cur) >= float64(count) {
		delete(c.m, key)
		return true
	}
	return false
}

// pruneLocked は、区間が終わった単位を捨てる。それでも上限なら、どれか 1 つを捨てる。
func (c *Counter) pruneLocked(now time.Time) {
	for k, w := range c.m {
		if now.Sub(w.start) >= 2*w.length {
			delete(c.m, k)
		}
	}
	for k := range c.m {
		if len(c.m) < maxCounterKeys {
			break
		}
		delete(c.m, k)
	}
}

// Decay は、elapsed が経った危険度の点 v を、半減期 halfLife で減らした値を返す。
func Decay(v float64, elapsed, halfLife time.Duration) float64 {
	if elapsed <= 0 || halfLife <= 0 {
		return v
	}
	return v * math.Exp2(-float64(elapsed)/float64(halfLife))
}
