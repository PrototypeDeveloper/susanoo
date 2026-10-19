package controller

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/pki"
	"susanoo/internal/policy"
	"susanoo/internal/rules"
	"susanoo/internal/store"
)

// 学習モードの試行の評価（2o）。フェーズ2のゲート「学習モードで誤検知が許容範囲に収まる」を判断するため、
//
//   - 対応の方式が監視か警告のときに隔離しなかった判断を、検知結果（would_isolate）として記録する
//   - 期間に保存したイベントを、今の検知ルールと例外で評価し直し、端末と機器ごとに隔離していた回数を数える。
//     試験運用のルールもすべて加点にしたらどうなるかも数える（加点に移してよいルールを選ぶため）
//
// 評価し直しは記録したイベントだけを使う。端末のグループと結び付きは今の台帳のものを使う。

const (
	defaultTrialPeriod     = 14 * 24 * time.Hour
	defaultTrialMaxPerWeek = 0.5 // 端末か機器ごとに、2 週間に 1 回まで
	maxTrialIsolations     = 1000
	trialTopTargets        = 5
	suppressRealert        = time.Hour // 同じ対象、同じ理由の隔離しなかった判断を続けて記録しない時間
	// trialCooldown は、評価し直して隔離していたとき、その後の検知を同じ件として数える時間（実際には隔離していて、
	// 管理者が確かめて解除するまでの間）。過ぎたら危険度を 0 から数え直す。
	trialCooldown = time.Hour
)

// recordSuppressedLocked は、対応の方式のために隔離しなかった判断を記録する（同じ対象と理由は suppressRealert に 1 回）。
// ルールでは評価しない（記録だけ）。c.mu を持って呼ぶ。
func (c *Controller) recordSuppressedLocked(target, reason string, response policy.Response, level policy.IsolationLevel) {
	now := c.now()
	key := target + "\x00" + reason
	if c.suppressed == nil {
		c.suppressed = map[string]time.Time{}
	}
	if t, ok := c.suppressed[key]; ok && now.Sub(t) < suppressRealert {
		return
	}
	c.suppressed[key] = now
	if len(c.suppressed) > 10000 {
		for k, t := range c.suppressed {
			if now.Sub(t) >= suppressRealert {
				delete(c.suppressed, k)
			}
		}
	}
	dev := &event.Device{UID: target}
	if strings.Count(target, ":") == 5 {
		dev = &event.Device{MAC: target}
	}
	msg := fmt.Sprintf("%s は隔離が必要な検知（%s）に当たりましたが、ポリシーの対応の方式が %s のため隔離しませんでした", target, reason, response)
	e := c.finding(event.FindingTypeWouldIsolate, "隔離しなかった判断", msg, event.SeverityMedium, dev)
	e.Unmapped = map[string]any{"would_isolate": map[string]any{"reason": reason, "response": string(response), "level": string(level)}}
	c.record(e)
}

// trialReport は学習モードの試行の評価を返す。
func (c *Controller) trialReport(w http.ResponseWriter, r *http.Request, _ pki.Identity) {
	now := c.now()
	q := r.URL.Query()
	until, since := now, now.Add(-defaultTrialPeriod)
	var err error
	if s := q.Get("until"); s != "" {
		if until, err = time.Parse(time.RFC3339, s); err != nil {
			writeError(w, http.StatusBadRequest, "until は RFC 3339 の時刻にしてください")
			return
		}
	}
	if s := q.Get("since"); s != "" {
		if since, err = time.Parse(time.RFC3339, s); err != nil {
			writeError(w, http.StatusBadRequest, "since は RFC 3339 の時刻にしてください")
			return
		}
	} else {
		since = until.Add(-defaultTrialPeriod)
	}
	if !since.Before(until) {
		writeError(w, http.StatusBadRequest, "since は until より前にしてください")
		return
	}
	maxPerWeek := defaultTrialMaxPerWeek
	if s := q.Get("max_per_week"); s != "" {
		if maxPerWeek, err = strconv.ParseFloat(s, 64); err != nil || maxPerWeek < 0 || maxPerWeek > 1000 || math.IsNaN(maxPerWeek) {
			writeError(w, http.StatusBadRequest, "max_per_week は 0 以上の数にしてください")
			return
		}
	}
	rep, err := c.replay(since, until, maxPerWeek)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// trialState は評価し直しのときの、端末か機器ごとの危険度。
type trialState struct {
	target, group string
	threshold     int
	risk, ifRisk  float64
	at, ifAt      time.Time
	ruleIDs       []string // 最近危険度を上げたルール
	ifRuleIDs     []string
	hits          map[string]int
	isolations    int
	ifEnforced    int
	isolatedAt    time.Time // 最後に隔離していた時刻（trialCooldown の間は数えない）
	ifIsolatedAt  time.Time
}

// eventSubject は保存したイベントから、検知の対象を探す手がかりを取り出す。
func eventSubject(e *event.Event) subject {
	var s subject
	if d := e.Device; d != nil {
		s.device, s.mac = d.UID, d.MAC
		s.ip, _ = netip.ParseAddr(d.IP)
	}
	if src := e.SrcEndpoint; src != nil && !s.ip.IsValid() {
		s.ip, _ = netip.ParseAddr(src.IP)
	}
	return s
}

// replayTargetLocked は、保存したイベントの対象を今の台帳で解決する（端末、機器、アドレスの順に試す）。
func (c *Controller) replayTargetLocked(s subject) target {
	for _, try := range []subject{{device: s.device}, {mac: s.mac}, {ip: s.ip}} {
		if try.device == "" && try.mac == "" && !try.ip.IsValid() {
			continue
		}
		if t := c.resolveLocked(try); t.key != "" {
			return t
		}
	}
	return target{}
}

// replay は期間 [since, until] に保存したイベントを今の検知ルールと例外で評価し直す。
func (c *Controller) replay(since, until time.Time, maxPerWeek float64) (api.TrialReport, error) {
	eng := c.engine.Load()
	rep := api.TrialReport{Since: since, Until: until, Rules: c.rulesVersion(), Isolations: []api.TrialIsolation{}, IfEnforced: []api.TrialIsolation{},
		ByRule: []api.TrialRule{}, ByTarget: []api.TrialTarget{}}
	c.mu.Lock()
	rep.Response = c.pol.Response
	c.mu.Unlock()
	var prefilter [][]byte
	for _, cl := range eng.Classes() {
		prefilter = append(prefilter, []byte(`"class_uid":`+strconv.Itoa(int(cl))+`,`))
	}
	wouldTag := []byte(`"` + event.FindingTypeWouldIsolate + `"`)
	from, to := since.UnixMilli(), until.UnixMilli()
	var counter rules.Counter
	targets := map[string]*trialState{}
	resolved := map[subject]target{}
	type ruleAgg struct {
		hits, excepted int
		targets        map[string]int
	}
	byRule := map[string]*ruleAgg{}

	isolate := func(st *trialState, at time.Time, score float64, ids []string, list *[]api.TrialIsolation) {
		if len(*list) < maxTrialIsolations {
			*list = append(*list, api.TrialIsolation{Time: at, Target: st.target, Group: st.group, Score: roundScore(score), Threshold: st.threshold, Rules: slices.Clone(ids)})
		}
	}
	addRecent := func(ids []string, add []string) []string {
		out := slices.Clone(add)
		for _, id := range ids {
			if !slices.Contains(out, id) && len(out) < riskRecent {
				out = append(out, id)
			}
		}
		return out
	}
	err := c.events.Scan(store.Filter{Since: since, Until: until}, func(line []byte) bool {
		if bytes.Contains(line, wouldTag) {
			var e event.Event
			if json.Unmarshal(line, &e) == nil && e.Time >= from && e.Time <= to && e.FindingInfo.HasType(event.FindingTypeWouldIsolate) {
				rep.Suppressed++
			}
			return true
		}
		if !slices.ContainsFunc(prefilter, func(p []byte) bool { return bytes.Contains(line, p) }) {
			return true
		}
		var e event.Event
		if json.Unmarshal(line, &e) != nil || e.Time < from || e.Time > to {
			return true
		}
		at := time.UnixMilli(e.Time)
		if rep.Oldest.IsZero() || at.Before(rep.Oldest) {
			rep.Oldest = at
		}
		rep.Events++
		if !eng.Relevant(&e) {
			return true
		}
		s := eventSubject(&e)
		t, ok := resolved[s]
		if !ok {
			c.mu.Lock()
			t = c.replayTargetLocked(s)
			c.mu.Unlock()
			resolved[s] = t
		}
		hits := eng.Evaluate(&e, rules.Subject{Key: t.key, Group: t.group, IDs: t.ids}, &counter, at)
		if len(hits) == 0 {
			return true
		}
		var st *trialState
		if t.key != "" {
			if st = targets[t.key]; st == nil {
				c.mu.Lock()
				th := c.groupLocked(t.group, t.canary).Threshold()
				c.mu.Unlock()
				st = &trialState{target: t.name(), group: t.group, threshold: th, hits: map[string]int{}}
				targets[t.key] = st
			}
		}
		points, ifPoints := 0, 0
		var ids, ifIDs []string
		enforced, ifEnforced := false, false
		for _, h := range hits {
			r := h.Rule
			agg := byRule[r.ID]
			if agg == nil {
				agg = &ruleAgg{targets: map[string]int{}}
				byRule[r.ID] = agg
			}
			if h.Excepted != nil {
				agg.excepted++
				continue
			}
			agg.hits++
			if st != nil {
				agg.targets[st.target]++
				st.hits[r.ID]++
			}
			ifEnforced = true
			ifPoints += r.Score
			ifIDs = append(ifIDs, r.ID)
			if r.Mode != rules.ModeMonitor {
				enforced = true
				points += r.Score
				ids = append(ids, r.ID)
			}
		}
		if st == nil {
			return true
		}
		cooling := func(last time.Time) bool { return !last.IsZero() && at.Sub(last) < trialCooldown }
		if enforced && !cooling(st.isolatedAt) {
			st.risk = rules.Decay(st.risk, at.Sub(st.at), eng.HalfLife) + float64(points)
			st.at = at
			st.ruleIDs = addRecent(st.ruleIDs, ids)
			if roundScore(st.risk) >= st.threshold {
				st.isolations++
				isolate(st, at, st.risk, st.ruleIDs, &rep.Isolations)
				st.risk, st.ruleIDs, st.isolatedAt = 0, nil, at // 隔離して、確かめて解除したものとみなして数え直す
			}
		}
		if ifEnforced && !cooling(st.ifIsolatedAt) {
			st.ifRisk = rules.Decay(st.ifRisk, at.Sub(st.ifAt), eng.HalfLife) + float64(ifPoints)
			st.ifAt = at
			st.ifRuleIDs = addRecent(st.ifRuleIDs, ifIDs)
			if roundScore(st.ifRisk) >= st.threshold {
				st.ifEnforced++
				isolate(st, at, st.ifRisk, st.ifRuleIDs, &rep.IfEnforced)
				st.ifRisk, st.ifRuleIDs, st.ifIsolatedAt = 0, nil, at
			}
		}
		return true
	})
	if err != nil {
		return rep, err
	}

	for i := range eng.Rules {
		r := &eng.Rules[i]
		agg := byRule[r.ID]
		if agg == nil {
			continue
		}
		tr := api.TrialRule{ID: r.ID, Name: r.Name, Mode: string(cmp.Or(r.Mode, rules.ModeEnforce)), Score: r.Score, Hits: agg.hits, Excepted: agg.excepted, Targets: len(agg.targets)}
		tr.Top = topCounts(agg.targets, trialTopTargets)
		rep.ByRule = append(rep.ByRule, tr)
	}
	slices.SortFunc(rep.ByRule, func(a, b api.TrialRule) int { return cmp.Or(b.Hits-a.Hits, strings.Compare(a.ID, b.ID)) })
	for _, st := range targets {
		rep.ByTarget = append(rep.ByTarget, api.TrialTarget{Target: st.target, Group: st.group, Hits: sumCounts(st.hits), Isolations: st.isolations,
			IfEnforced: st.ifEnforced, Rules: topCounts(st.hits, len(st.hits))})
	}
	slices.SortFunc(rep.ByTarget, func(a, b api.TrialTarget) int {
		return cmp.Or(b.Isolations-a.Isolations, b.IfEnforced-a.IfEnforced, b.Hits-a.Hits, strings.Compare(a.Target, b.Target))
	})

	g := api.TrialGate{MaxPerWeek: maxPerWeek, Weeks: math.Round(until.Sub(since).Hours()/(24*7)*100) / 100}
	g.Allowed = maxPerWeek * until.Sub(since).Hours() / (24 * 7)
	for _, t := range rep.ByTarget {
		if float64(t.Isolations) > g.Allowed {
			g.Over = append(g.Over, t.Target)
		}
		if float64(t.IfEnforced) > g.Allowed {
			g.IfEnforcedOver = append(g.IfEnforcedOver, t.Target)
		}
	}
	g.Allowed = math.Round(g.Allowed*100) / 100
	g.Pass, g.IfEnforcedPass = len(g.Over) == 0, len(g.IfEnforcedOver) == 0
	rep.Gate = g
	return rep, nil
}

// topCounts は回数の多い順に n 件まで返す。
func topCounts(m map[string]int, n int) []api.TrialCount {
	out := make([]api.TrialCount, 0, len(m))
	for k, v := range m {
		out = append(out, api.TrialCount{Target: k, Count: v})
	}
	slices.SortFunc(out, func(a, b api.TrialCount) int { return cmp.Or(b.Count-a.Count, strings.Compare(a.Target, b.Target)) })
	return out[:min(len(out), n)]
}

func sumCounts(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}
