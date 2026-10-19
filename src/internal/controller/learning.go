package controller

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/behavior"
	"susanoo/internal/event"
	"susanoo/internal/notify"
	"susanoo/internal/pki"
	"susanoo/internal/policy"
)

// 学習モードの期間と、原則拒否への移行（G2）。
//
// 外部通信の制御の default が learn のグループは、通した名前を学習する（learnedLog）。CONTROLLER は、グループが学習モードに
// なった時刻を覚え、期間（ポリシーの egress.learn_period。既定 14 日）が終わったら管理者に知らせる。自動では原則拒否に移らない。
// 管理者は、学習した名前から作った許可リストの案（ctl learned suggest）を確かめ、ポリシーとして先行適用から配布する（承認）。

const (
	learningFile        = "learning.json"
	defaultSuggestMin   = 2 // 案に入れる名前の、問い合わせの回数の下限
	wildcardMinNames    = 3 // 同じ登録できる単位の下に、これ以上の名前を学習したら「*.」にまとめる
	maxSuggestExamples  = 3 // まとめた名前の例の数
	maxSuggestedEntries = 2000
)

// learningState は学習モードのグループの記録。
type learningState struct {
	Started  time.Time `json:"started"`
	Notified bool      `json:"notified,omitempty"` // 期間が終わったことを知らせた
}

// initLearning は学習モードの記録を読み、今のポリシーに合わせる。
func (c *Controller) initLearning() error {
	c.learning = map[string]*learningState{}
	data, err := os.ReadFile(filepath.Join(c.cfg.Dir, learningFile))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err == nil {
		if err := json.Unmarshal(data, &c.learning); err != nil {
			return fmt.Errorf("controller: %s を解析できません: %w", learningFile, err)
		}
	}
	c.syncLearningLocked()
	return nil
}

func (c *Controller) saveLearningLocked() {
	if err := saveJSON(filepath.Join(c.cfg.Dir, learningFile), c.learning); err != nil {
		c.log.Error("学習モードの記録を保存できません", "エラー", err)
	}
}

// learnGroupLocked は、今のポリシーのグループ name（既定のグループに置き換えない）を返す。
func (c *Controller) learnGroupLocked(name string) *policy.Group {
	for i := range c.pol.Groups {
		if c.pol.Groups[i].Name == name {
			return &c.pol.Groups[i]
		}
	}
	return nil
}

// syncLearningLocked は、今のポリシーで学習モードのグループを数え始め、学習モードでなくなったグループの記録を消す。
// ポリシーを切り替えるたびに呼ぶ。
func (c *Controller) syncLearningLocked() {
	now := c.now()
	changed := false
	for _, g := range c.pol.Groups {
		if g.Egress.Default == policy.EgressLearn && c.learning[g.Name] == nil {
			c.learning[g.Name] = &learningState{Started: now.UTC()}
			changed = true
			c.log.Info("学習モードの期間を数え始めました", "グループ", g.Name, "期間", g.Egress.LearnPeriodOr())
		}
	}
	for name := range c.learning {
		if g := c.learnGroupLocked(name); g == nil || g.Egress.Default != policy.EgressLearn {
			delete(c.learning, name)
			changed = true
			c.log.Info("学習モードを終えました", "グループ", name)
		}
	}
	if changed {
		c.saveLearningLocked()
	}
}

// checkLearning は、期間が終わった学習モードのグループを、1 回だけ管理者に知らせる。期間が延びたら、また知らせる。
func (c *Controller) checkLearning() {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	changed := false
	for name, st := range c.learning {
		g := c.learnGroupLocked(name)
		if g == nil {
			continue
		}
		ends := st.Started.Add(g.Egress.LearnPeriodOr())
		switch {
		case now.Before(ends) && st.Notified:
			st.Notified, changed = false, true
		case !now.Before(ends) && !st.Notified:
			st.Notified, changed = true, true
			learned, _ := c.learnedCounts(name)
			title := fmt.Sprintf("グループ %s の学習モードの期間が終わりました", name)
			c.log.Warn(title, "学習した名前", learned)
			c.cfg.Notifier.Notify(notify.Message{Kind: notify.KindLearning, Severity: event.SeverityInformational, Title: title, Target: name, Time: now,
				Body:   "学習した名前から許可リストの案を作り、内容を確かめてから原則拒否に移るかを決めてください。自動では移りません。",
				Fields: map[string]string{"グループ": name, "対処": fmt.Sprintf("susanoo ctl learned suggest -group %s -out policy.json で案を作り、susanoo ctl policy push policy.json -canary <端末> で一部から適用します（学習した名前 %d）", name, learned)}})
		}
	}
	if changed {
		c.saveLearningLocked()
	}
}

// learnedCounts はグループ（先行適用の版のグループを含む）で学習した名前と、遮断した名前の数を返す。
func (c *Controller) learnedCounts(group string) (learned, blocked int) {
	c.learned.mu.Lock()
	defer c.learned.mu.Unlock()
	for k := range c.learned.entries {
		if k.group == group || k.group == group+policy.CanarySuffix {
			if k.blocked {
				blocked++
			} else {
				learned++
			}
		}
	}
	return learned, blocked
}

// learningViewLocked は全体の状態に載せる、学習モードのグループの状態を返す。
func (c *Controller) learningViewLocked() []api.LearningGroup {
	now := c.now()
	var out []api.LearningGroup
	for name, st := range c.learning {
		g := c.learnGroupLocked(name)
		if g == nil {
			continue
		}
		ends := st.Started.Add(g.Egress.LearnPeriodOr())
		learned, blocked := c.learnedCounts(name)
		out = append(out, api.LearningGroup{Group: name, Started: st.Started, Ends: ends, Due: !now.Before(ends), Learned: learned, Blocked: blocked})
	}
	slices.SortFunc(out, func(a, b api.LearningGroup) int { return strings.Compare(a.Group, b.Group) })
	return out
}

// suggestAllow は、学習した名前から許可リストの案を作る。回数が min 未満の名前、名前の形でないもの、脅威情報の一覧に載っている
// 名前は入れない。同じ登録できる単位（example.co.jp など）の下に wildcardMinNames 以上の名前があれば、「*.」にまとめる。
func (c *Controller) suggestAllow(w http.ResponseWriter, r *http.Request, _ pki.Identity) {
	group := r.URL.Query().Get("group")
	minCount := defaultSuggestMin
	if s := r.URL.Query().Get("min"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 1000000 {
			writeError(w, http.StatusBadRequest, "min は 1 以上の数にしてください")
			return
		}
		minCount = n
	}
	c.mu.Lock()
	g := c.learnGroupLocked(group)
	var started time.Time
	if st := c.learning[group]; st != nil {
		started = st.Started
	}
	c.mu.Unlock()
	if g == nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("今のポリシーにグループ %q はありません", group))
		return
	}
	counts := map[string]int{}
	c.learned.mu.Lock()
	for k, e := range c.learned.entries {
		if !k.blocked && (k.group == group || k.group == group+policy.CanarySuffix) {
			counts[k.domain] += e.Count
		}
	}
	c.learned.mu.Unlock()

	out := api.AllowSuggestion{Group: group, Started: started, MinCount: minCount, Allow: []api.SuggestedDestination{}}
	matcher := c.intelM.Load()
	byBase := map[string][]string{}
	for name, n := range counts {
		switch {
		case n < minCount:
			continue
		case policy.ValidateDomain(name) != nil:
			out.Excluded = append(out.Excluded, api.ExcludedName{Domain: name, Reason: "許可リストに書けない名前の形"})
			continue
		}
		if ms := matcher.Domain(name); len(ms) > 0 {
			var lists []string
			for _, m := range ms {
				lists = append(lists, m.List)
			}
			out.Excluded = append(out.Excluded, api.ExcludedName{Domain: name, Reason: "脅威情報（" + strings.Join(slices.Compact(lists), "、") + "）"})
			continue
		}
		base := cmp.Or(behavior.BaseDomain(name), name)
		byBase[base] = append(byBase[base], name)
	}
	for base, names := range byBase {
		slices.Sort(names)
		if len(names) >= wildcardMinNames && policy.ValidateDomain("*."+base) == nil {
			s := api.SuggestedDestination{Domain: "*." + base, Names: len(names), Examples: names[:min(len(names), maxSuggestExamples)]}
			for _, n := range names {
				s.Count += counts[n]
			}
			out.Allow = append(out.Allow, s)
			if slices.Contains(names, base) { // 「*.」は登録できる単位そのものには当たらない
				out.Allow = append(out.Allow, api.SuggestedDestination{Domain: base, Count: counts[base], Names: 1})
			}
			continue
		}
		for _, n := range names {
			out.Allow = append(out.Allow, api.SuggestedDestination{Domain: n, Count: counts[n], Names: 1})
		}
	}
	slices.SortFunc(out.Allow, func(a, b api.SuggestedDestination) int {
		return cmp.Or(b.Count-a.Count, strings.Compare(a.Domain, b.Domain))
	})
	if len(out.Allow) > maxSuggestedEntries {
		out.Allow = out.Allow[:maxSuggestedEntries]
	}
	slices.SortFunc(out.Excluded, func(a, b api.ExcludedName) int { return strings.Compare(a.Domain, b.Domain) })
	writeJSON(w, http.StatusOK, out)
}
