package controller

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/pki"
	"susanoo/internal/policy"
	"susanoo/internal/rules"
)

// 検知ルールの評価と危険度（M3、M5）。
//
// CONTROLLER に集まるイベント（CLIENT のイベント、GW の DNS、通信、DHCP、CONTROLLER 自身の検知）は、すべて検知ルールで
// 評価する。当てはまったルールの点を、端末（CLIENT のない機器は MAC アドレス）ごとの危険度に加え、危険度がグループの
// しきい値（policy.Group.Threshold）以上になったら、ポリシーの対応の方式に従って隔離する。危険度は半減期で減り、
// 隔離を解除すると 0 に戻す。ルールの配布（署名の確認と版の保存）は rules.Store が行う。

const (
	ActionRulesApply = "rules.apply"
	rulesDir         = "rules"
	riskFile         = "risk.json"
	riskRecent       = 5  // 危険度に覚えておく最近のルールの数
	riskyLimit       = 10 // 全体の状態に載せる、危険度の高い端末と機器の数
	// hitLogInterval の間は、同じルールと対象の当てはまりのログを 1 回にまとめる（よく当たるルールでログがあふれないように）。
	hitLogInterval = time.Minute
	maxHitLogKeys  = 4096
)

// hitLog は当てはまりのログをまとめるための記録。
type hitLog struct {
	at         time.Time
	suppressed int
}

// subject は検知の対象。CLIENT のイベントは証明書の端末 ID で、GW のイベントは MAC アドレスかアドレスで指定する。
type subject struct {
	device string
	mac    string
	ip     netip.Addr
}

// target は、検知の対象を台帳で解決したもの。
type target struct {
	key    string // 危険度の単位。分からなければ空
	device string // 端末 ID（CLIENT のない機器なら空）
	mac    string // CLIENT のない機器の MAC アドレス
	group  string
	canary bool
	ids    []string
}

func (t target) name() string { return cmp.Or(t.device, t.mac, "-") }

// riskScore は危険度。Value は At の時点の値で、半減期で減らして使う。
type riskScore struct {
	Value float64   `json:"value"`
	At    time.Time `json:"at"`
	Rules []string  `json:"rules,omitempty"` // 最近加えたルールの ID（新しい順）
}

// ruleStat はルールに当てはまった回数。
type ruleStat struct {
	Hits      int64     `json:"hits"`
	Monitored int64     `json:"monitored"`
	Excepted  int64     `json:"excepted"`
	Last      time.Time `json:"last,omitzero"`
}

type riskState struct {
	Scores map[string]*riskScore `json:"scores"`
	Stats  map[string]*ruleStat  `json:"stats"`
}

// initRules は検知ルールの保存先と、危険度の記録を開く。
func (c *Controller) initRules() error {
	var set *rules.Set
	if c.cfg.RulesKey != nil {
		store, err := rules.OpenStore(filepath.Join(c.cfg.Dir, rulesDir), c.cfg.RulesKey)
		if err != nil {
			return err
		}
		c.ruleStore, set = store, store.Current()
	}
	c.engine.Store(rules.NewEngine(set))
	c.risk = riskState{Scores: map[string]*riskScore{}, Stats: map[string]*ruleStat{}}
	data, err := os.ReadFile(filepath.Join(c.cfg.Dir, riskFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &c.risk); err != nil {
		return fmt.Errorf("controller: %s を解析できません: %w", riskFile, err)
	}
	if c.risk.Scores == nil {
		c.risk.Scores = map[string]*riskScore{}
	}
	if c.risk.Stats == nil {
		c.risk.Stats = map[string]*ruleStat{}
	}
	return nil
}

// saveRiskLocked は危険度と、ルールに当てはまった回数を保存する。ほとんど 0 に戻った危険度は捨てる。
func (c *Controller) saveRiskLocked() {
	now := c.now()
	hl := c.engine.Load().HalfLife
	for k, r := range c.risk.Scores {
		if rules.Decay(r.Value, now.Sub(r.At), hl) < 0.5 {
			delete(c.risk.Scores, k)
		}
	}
	if err := saveJSON(filepath.Join(c.cfg.Dir, riskFile), c.risk); err != nil {
		c.log.Error("危険度を保存できません", "エラー", err)
		return
	}
	c.riskDirty = false
}

// observe はイベントを保存し、検知ルールで評価する。
func (c *Controller) observe(e *event.Event, s subject) {
	c.record(e)
	c.analyze(e, s)
}

// resolveLocked は検知の対象を台帳で解決する。端末に結び付いた機器は端末として扱う。
func (c *Controller) resolveLocked(s subject) target {
	if s.device == "" && s.mac == "" && s.ip.IsValid() {
		if id := c.deviceByAddrLocked(s.ip); id != "" {
			s.device = id
		} else if h := c.hostByIPLocked(s.ip); h != nil {
			s.mac = h.MAC
		}
	}
	if s.device == "" && s.mac != "" {
		h := c.hosts[s.mac]
		if h == nil {
			return target{}
		}
		if h.DeviceID == "" || c.devices[h.DeviceID] == nil {
			t := target{key: "host:" + h.MAC, mac: h.MAC, group: c.hostGroupLocked(h), canary: c.hostCanaryLocked(h), ids: []string{h.MAC}}
			if h.IP.IsValid() {
				t.ids = append(t.ids, h.IP.String())
			}
			return t
		}
		s.device = h.DeviceID
	}
	d := c.devices[s.device]
	if d == nil {
		return target{}
	}
	t := target{key: "device:" + d.ID, device: d.ID, group: cmp.Or(d.Group, policy.DefaultGroup), canary: c.deviceCanaryLocked(d), ids: []string{d.ID}}
	if d.Addr.IsValid() {
		t.ids = append(t.ids, d.Addr.String())
	}
	t.ids = append(t.ids, c.linkedMACsLocked(d.ID)...)
	return t
}

// hostByIPLocked は、アドレス ip を最後に使った機器を返す。
func (c *Controller) hostByIPLocked(ip netip.Addr) *host {
	var found *host
	for _, h := range c.hosts {
		if h.IP == ip && (found == nil || h.LastSeen.After(found.LastSeen)) {
			found = h
		}
	}
	return found
}

// analyze はイベントを検知ルールで評価し、当てはまったルールの点を危険度に加える。
// 危険度がしきい値以上になったら、ポリシーに従って隔離する。条件のルールに当てはまったら、検知結果を作る。
func (c *Controller) analyze(e *event.Event, s subject) {
	eng := c.engine.Load()
	if !eng.Relevant(e) {
		return
	}
	now := c.now()
	c.mu.Lock()
	t := c.resolveLocked(s)
	c.mu.Unlock()
	hits := eng.Evaluate(e, rules.Subject{Key: t.key, Group: t.group, IDs: t.ids}, &c.counter, now)
	if len(hits) == 0 {
		return
	}

	var (
		reason    string
		fire      bool
		score, th int
		notifySev event.Severity
	)
	c.mu.Lock()
	points, top := 0, (*rules.Rule)(nil)
	var ids []string
	for _, h := range hits {
		r := h.Rule
		st := c.risk.Stats[r.ID]
		if st == nil {
			st = &ruleStat{}
			c.risk.Stats[r.ID] = st
		}
		st.Last = now
		c.riskDirty = true
		switch {
		case h.Excepted != nil:
			st.Excepted++
			if n, ok := c.logHitLocked("excepted", r.ID, t, now); ok {
				c.log.Info("誤検知の例外に当てはまるため、危険度に加えません", "ルール", r.ID, "対象", t.name(), "例外の理由", h.Excepted.Reason, "まとめた回数", n)
			}
		case r.Mode == rules.ModeMonitor:
			st.Monitored++
			if n, ok := c.logHitLocked("monitor", r.ID, t, now); ok {
				c.log.Info("試験運用のルールに当てはまりました（危険度に加えません）", "ルール", r.ID, "対象", t.name(), "内容", describe(e), "まとめた回数", n)
			}
		default:
			st.Hits++
			points += r.Score
			ids = append(ids, r.ID)
			if top == nil || r.Score > top.Score {
				top = r
			}
			sev := e.SeverityID
			if r.Finding == "" {
				sev = r.FindingSeverity()
			}
			notifySev = max(notifySev, sev)
		}
	}
	if top != nil {
		th = c.groupLocked(t.group, t.canary).Threshold()
		if t.key != "" {
			score = roundScore(c.addRiskLocked(t.key, points, ids, now, eng.HalfLife))
		}
		if n, ok := c.logHitLocked("enforce", top.ID, t, now); ok || score >= th {
			c.log.Warn("検知ルールに当てはまりました", "ルール", top.ID, "名前", top.Name, "対象", t.name(), "点", points, "危険度", score, "しきい値", th, "内容", describe(e), "まとめた回数", n)
		}
		if t.key != "" && score >= th {
			fire = true
			reason = top.Name
			if top.Score < th {
				reason = fmt.Sprintf("危険度 %d（%s など）", score, c.ruleNames(eng, c.risk.Scores[t.key].Rules))
			}
		}
	}
	c.mu.Unlock()

	for _, h := range hits {
		if h.Rule.Finding == "" && h.Excepted == nil {
			c.record(c.ruleFinding(h.Rule, e, t))
		}
	}
	if !fire {
		if top != nil {
			c.notifyFinding(t, top.Name, notifySev, e, score, th)
		}
		return
	}
	if t.device != "" {
		c.trigger(t.device, reason)
	} else {
		c.triggerHost(t.mac, reason)
	}
}

// logHitLocked は、当てはまりをログに書くかを返す。同じルールと対象では hitLogInterval に 1 回だけ書き、
// 書かなかった回数を次に書くときに返す（1 回目は 0）。
func (c *Controller) logHitLocked(kind, rule string, t target, now time.Time) (int, bool) {
	key := kind + "\x00" + rule + "\x00" + t.key
	if c.hitLogs == nil {
		c.hitLogs = map[string]*hitLog{}
	}
	l := c.hitLogs[key]
	if l != nil && now.Sub(l.at) < hitLogInterval && now.Sub(l.at) >= 0 {
		l.suppressed++
		return 0, false
	}
	if l == nil {
		if len(c.hitLogs) >= maxHitLogKeys {
			for k, v := range c.hitLogs {
				if now.Sub(v.at) >= hitLogInterval {
					delete(c.hitLogs, k)
				}
			}
			if len(c.hitLogs) >= maxHitLogKeys {
				return 0, false
			}
		}
		l = &hitLog{}
		c.hitLogs[key] = l
	}
	n := l.suppressed
	l.at, l.suppressed = now, 0
	return n, true
}

// addRiskLocked は危険度に点を加え、加えた後の値を返す。
func (c *Controller) addRiskLocked(key string, points int, ids []string, now time.Time, halfLife time.Duration) float64 {
	r := c.risk.Scores[key]
	if r == nil {
		r = &riskScore{}
		c.risk.Scores[key] = r
	}
	r.Value = rules.Decay(r.Value, now.Sub(r.At), halfLife) + float64(points)
	r.At = now
	recent := slices.Clone(ids)
	for _, id := range r.Rules {
		if !slices.Contains(recent, id) && len(recent) < riskRecent {
			recent = append(recent, id)
		}
	}
	r.Rules = recent
	c.riskDirty = true
	return r.Value
}

// riskLocked は今の危険度を返す。
func (c *Controller) riskLocked(key string) int {
	r := c.risk.Scores[key]
	if r == nil {
		return 0
	}
	return roundScore(rules.Decay(r.Value, c.now().Sub(r.At), c.engine.Load().HalfLife))
}

// roundScore は危険度を整数に丸める（表示としきい値との比較に使う）。
func roundScore(v float64) int { return int(math.Round(v)) }

// resetRiskLocked は危険度を 0 に戻す（隔離を解除したとき）。
func (c *Controller) resetRiskLocked(key string) {
	if _, ok := c.risk.Scores[key]; ok {
		delete(c.risk.Scores, key)
		c.riskDirty = true
	}
}

func (c *Controller) ruleNames(eng *rules.Engine, ids []string) string {
	var names []string
	for _, id := range ids {
		name := id
		for i := range eng.Rules {
			if eng.Rules[i].ID == id {
				name = eng.Rules[i].Name
			}
		}
		names = append(names, name)
	}
	return strings.Join(names, "、")
}

// ruleFinding は、条件のルールに当てはまったイベント src から検知結果を作る。
func (c *Controller) ruleFinding(r *rules.Rule, src *event.Event, t target) *event.Event {
	title := r.Name
	if r.Mode == rules.ModeMonitor {
		title += "（試験運用）"
	}
	msg := fmt.Sprintf("検知ルール %s に当てはまりました: %s", r.ID, describe(src))
	dev := &event.Device{}
	if src.Device != nil {
		*dev = *src.Device
	}
	dev.UID = cmp.Or(t.device, dev.UID)
	if t.mac != "" {
		dev.MAC = t.mac
	}
	e := c.finding(event.FindingTypeRule, title, msg, r.FindingSeverity(), dev)
	e.FindingInfo.Analytic = &event.Analytic{UID: r.ID, Name: r.Name, TypeID: event.AnalyticRule}
	if r.Description != "" {
		e.FindingInfo.Desc = r.Description
	}
	e.Metadata.CorrelationUID = src.Metadata.UID
	return e
}

// describe はイベントの要点を短く返す（ログと検知結果の説明に使う）。
func describe(e *event.Event) string {
	switch {
	case e.FindingInfo != nil:
		return cmp.Or(e.Message, e.FindingInfo.Title)
	case e.Query != nil:
		return "DNS の問い合わせ " + e.Query.Hostname + " " + e.Query.Type
	case e.ClassUID == event.ClassNetworkActivity && e.DstEndpoint != nil:
		s := "通信 " + net.JoinHostPort(e.DstEndpoint.IP, strconv.Itoa(e.DstEndpoint.Port))
		if e.DstEndpoint.Hostname != "" {
			s += "（" + e.DstEndpoint.Hostname + "）"
		}
		return s
	case e.Process != nil:
		return "プロセス " + cmp.Or(e.Process.CmdLine, e.Process.Name)
	case e.File != nil:
		return "ファイル " + cmp.Or(e.File.Path, e.File.Name)
	case e.ClassUID == event.ClassDHCPActivity && e.DstEndpoint != nil:
		return "DHCP " + e.DstEndpoint.MAC + " " + e.DstEndpoint.IP
	}
	return e.Message
}

// risky は危険度の高い端末と機器を、高い順に返す。
func (c *Controller) riskyLocked() []api.Risk {
	var out []api.Risk
	for key, r := range c.risk.Scores {
		score := c.riskLocked(key)
		if score < 1 {
			continue
		}
		kind, id, _ := strings.Cut(key, ":")
		v := api.Risk{Target: id, Host: kind == "host", Score: score, Rules: slices.Clone(r.Rules)}
		if d := c.devices[id]; kind == "device" && d != nil {
			v.Threshold = c.groupLocked(d.Group, c.deviceCanaryLocked(d)).Threshold()
		} else if h := c.hosts[id]; kind == "host" && h != nil {
			v.Threshold = c.groupLocked(c.hostGroupLocked(h), c.hostCanaryLocked(h)).Threshold()
		} else {
			continue
		}
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b api.Risk) int { return cmp.Or(b.Score-a.Score, strings.Compare(a.Target, b.Target)) })
	if len(out) > riskyLimit {
		out = out[:riskyLimit]
	}
	return out
}

// rulesVersion は検知ルールの今の版の概要を返す。
func (c *Controller) rulesVersion() api.RulesVersion {
	eng := c.engine.Load()
	if eng.Set == nil {
		return api.RulesVersion{Name: "既定のルール"}
	}
	v := api.RulesVersion{Version: eng.Set.Version, Name: eng.Set.Name, IssuedAt: eng.Set.IssuedAt}
	if c.ruleStore != nil {
		for _, r := range c.ruleStore.Versions() {
			if r.Version == v.Version {
				v.AppliedAt = r.AppliedAt
			}
		}
	}
	return v
}

func (c *Controller) getRules(w http.ResponseWriter, _ *http.Request, _ pki.Identity) {
	writeJSON(w, http.StatusOK, c.rulesInfo())
}

func (c *Controller) rulesInfo() api.RulesInfo {
	eng := c.engine.Load()
	info := api.RulesInfo{Current: c.rulesVersion(), Versions: []api.RulesVersion{}, HalfLife: eng.HalfLife.String()}
	if eng.Set != nil {
		info.Exceptions = len(eng.Set.Exceptions)
	}
	if c.ruleStore != nil {
		for _, r := range c.ruleStore.Versions() {
			info.Versions = append(info.Versions, api.RulesVersion(r))
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range eng.Rules {
		v := api.RuleStatus{ID: r.ID, Name: r.Name, Mode: string(r.Mode), Score: r.Score, Groups: r.Groups, Target: r.Class}
		if r.Finding != "" {
			v.Target = "finding:" + r.Finding
		}
		v.Default = slices.ContainsFunc(rules.Defaults, func(d rules.Rule) bool { return d.ID == r.ID }) &&
			(eng.Set == nil || !slices.ContainsFunc(eng.Set.Rules, func(d rules.Rule) bool { return d.ID == r.ID }))
		if st := c.risk.Stats[r.ID]; st != nil {
			v.Hits, v.Monitored, v.Excepted, v.Last = st.Hits, st.Monitored, st.Excepted, st.Last
		}
		info.Rules = append(info.Rules, v)
	}
	return info
}

func (c *Controller) getRulesVersion(w http.ResponseWriter, r *http.Request, _ pki.Identity) {
	v, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || v < 1 {
		writeError(w, http.StatusBadRequest, "版数が不正です")
		return
	}
	if c.ruleStore == nil {
		writeError(w, http.StatusNotFound, "その版はありません")
		return
	}
	data, err := c.ruleStore.Payload(v)
	if err != nil {
		writeError(w, http.StatusNotFound, "その版はありません")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// pushRules は署名付きの検知ルールを受け取り、確かめて保存し、評価に使う。定義を変えたルールは、当てはまった回数を数え直す。
func (c *Controller) pushRules(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	var req api.RulesPush
	if !decode(w, r, &req) {
		return
	}
	if c.ruleStore == nil {
		writeError(w, http.StatusServiceUnavailable, "この CONTROLLER では検知ルールを配布できません")
		return
	}
	set, err := c.ruleStore.Apply(req.Envelope, c.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, "検知ルールを適用できません: "+err.Error())
		return
	}
	next := rules.NewEngine(set)
	prev := c.engine.Swap(next)
	c.detector.Configure(next.Behavior(), next.Watches)
	c.mu.Lock()
	for _, r := range next.Rules {
		if i := slices.IndexFunc(prev.Rules, func(p rules.Rule) bool { return p.ID == r.ID }); i < 0 || !sameRule(prev.Rules[i], r) {
			delete(c.risk.Stats, r.ID)
			c.riskDirty = true
		}
	}
	actor := "admin/" + admin.ID
	c.auditLocked(actor, ActionRulesApply, strconv.Itoa(set.Version), netip.Addr{}, map[string]any{"name": set.Name, "rules": len(set.Rules), "exceptions": len(set.Exceptions)})
	c.mu.Unlock()
	c.log.Warn("検知ルールを適用しました", "版数", set.Version, "名前", set.Name, "ルール", len(set.Rules), "例外", len(set.Exceptions), "操作", actor)
	writeJSON(w, http.StatusOK, c.rulesInfo())
}

func sameRule(a, b rules.Rule) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}

// deviceViewLocked は ctl に返す端末の状態を作る。
func (c *Controller) deviceViewLocked(d *device) api.Device {
	v := d.view(c.linkedMACsLocked(d.ID))
	v.Risk = c.riskLocked("device:" + d.ID)
	return v
}

// hostViewLocked は ctl に返す機器の状態を作る。端末に結び付いた機器は、端末の危険度を載せる。
func (c *Controller) hostViewLocked(h *host) api.Host {
	v := h.view(c.hostGroupLocked(h))
	if c.devices[h.DeviceID] != nil {
		v.Risk = c.riskLocked("device:" + h.DeviceID)
	} else {
		v.Risk = c.riskLocked("host:" + h.MAC)
	}
	return v
}
