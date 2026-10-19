package controller

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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
	"susanoo/internal/audit"
	"susanoo/internal/event"
	"susanoo/internal/notify"
	"susanoo/internal/pki"
)

// インシデント対応の支援（M9）。
//
//   - 端末か機器を隔離すると、その対象の開いたインシデントがなければ自動で開く（管理者も ctl incident open で開ける）
//   - 対応の手順をチェックリストで持つ。切り離し、証拠の保全、復旧は、台帳と証拠の状態から自動で済みにする
//   - 個人情報の漏えい等のおそれがあれば、個人情報保護委員会への速報と確報の期限の目安を計算し、近づいたら通知する
//   - 時系列を、保存したイベント、監査ログ、証拠から自動で作る（ctl incident timeline、report）
//
// 期限は個人情報保護委員会のガイドライン（通則編）の目安（速報は事態を知ってから概ね 3〜5 日以内、確報は 30 日以内。
// 不正の目的をもって行われたおそれがある場合は 60 日以内）に基づく。報告の要否と期限は、最新のガイドラインで確かめる。

const (
	incidentsFile         = "incidents.json"
	maxIncidents          = 1000
	maxTimelineEvents     = 5000
	maxTimelineBefore     = 30 * 24 * time.Hour
	defaultTimelineBefore = 24 * time.Hour
	evidenceSlack         = 5 * time.Minute // 証拠の保全の判断で、インシデントを開く少し前に受け取った証拠も数える
	ActionIncidentOpen    = "incident.open"
	ActionIncidentUpdate  = "incident.update"
	ActionIncidentStep    = "incident.step"
)

// 報告の期限の目安。
const (
	prelimFrom        = 3 * 24 * time.Hour
	prelimDue         = 5 * 24 * time.Hour
	finalDue          = 30 * 24 * time.Hour
	finalDueMalicious = 60 * 24 * time.Hour
	finalRemind       = 3 * 24 * time.Hour // 確報は期限の 3 日前に知らせる
)

// incident は保存するインシデント。手順の名前と説明は保存せず、incidentSteps から付ける。
type incident struct {
	ID             string                   `json:"id"`
	Title          string                   `json:"title"`
	Devices        []string                 `json:"devices"`
	Status         string                   `json:"status"`
	Opened         time.Time                `json:"opened"`
	OpenedBy       string                   `json:"opened_by"`
	KnownAt        time.Time                `json:"known_at"`
	Closed         time.Time                `json:"closed,omitzero"`
	PersonalData   bool                     `json:"personal_data,omitempty"`
	Malicious      bool                     `json:"malicious,omitempty"`
	PrelimReported time.Time                `json:"prelim_reported,omitzero"`
	FinalReported  time.Time                `json:"final_reported,omitzero"`
	Steps          map[string]*incidentStep `json:"steps,omitempty"`
	Notes          []api.IncidentNote       `json:"notes,omitempty"`
	Reminded       []string                 `json:"reminded,omitempty"` // 送った期限の知らせ（速報-soon など）
}

type incidentStep struct {
	Status string    `json:"status"`
	By     string    `json:"by,omitempty"`
	At     time.Time `json:"at,omitzero"`
	Note   string    `json:"note,omitempty"`
}

// stepDef は対応の手順の定義。
type stepDef struct {
	id, title, guide string
	auto             bool
}

// incidentSteps は対応の手順（行う順）。
var incidentSteps = []stepDef{
	{"isolate", "切り離し", "対象の端末と機器を隔離して、外部や LAN のほかの機器と通信できないようにする。自動対応で隔離されていなければ susanoo ctl isolate <端末> で隔離する。" +
		"ケーブルを抜くより隔離のほうが、証拠の保全と調査を続けられる。電源は切らない（メモリの中の痕跡が消えるため）。", true},
	{"evidence", "証拠の保全", "隔離した端末の CLIENT が集めた証拠（プロセス、接続、ログ）が届いていることを susanoo ctl evidence list で確かめる。" +
		"必要なら susanoo ctl evidence collect <端末> で集め直し、susanoo ctl evidence show <端末> <ID> -out <ファイル> で署名付きのまま別の場所に保管する。" +
		"CLIENT のない機器は、画面やログを写真や書き出しで残す。", true},
	{"scope", "影響範囲の確認", "時系列（susanoo ctl incident timeline <ID>）で、最初の兆候、通信先、触られたファイルを確かめる。" +
		"同じ通信先や同じ検知がほかの端末にないかを susanoo ctl events -q <通信先> で探し、あれば隔離してこのインシデントに加える。" +
		"端末にあった情報（個人情報、取引先の情報、認証情報）と、端末から使えたサービスを洗い出す。", false},
	{"communication", "関係者への連絡", "責任者と、必要に応じて取引先、委託先、保険会社、警察、セキュリティの専門家に連絡する。連絡と指示は、あらかじめ決めた連絡先と手段で行う。" +
		"送金、認証情報の変更、隔離の解除などの依頼は、声や映像が本人らしくても、登録済みの連絡先への折り返しで確かめ、複数人で承認してから行う（ディープフェイクによるなりすまし対策）。", false},
	{"credentials", "認証情報の変更", "乗っ取られた端末で使っていたパスワード、API キー（AI サービスの鍵を含む）、SSH の鍵、ブラウザーに保存したログインとセッションを、" +
		"乗っ取られていない別の端末から変更、失効させる。重要なサービスには多要素認証（できればパスキー）を設定する。" +
		"端末の証明書は susanoo ctl revoke <端末> で失効させ、作り直した鍵に発行し直す。", false},
	{"personal_data", "個人情報の漏えい等の確認", "漏えい、滅失、毀損のおそれがある個人データがあるかを確かめる。要配慮個人情報、財産的な被害が生じるおそれのあるもの、" +
		"不正の目的によるおそれのあるもの（不正アクセスやランサムウェアなど）、本人が 1,000 人を超えるものは、個人情報保護委員会への報告と本人への通知が必要になる。" +
		"おそれがあれば susanoo ctl incident update <ID> -personal-data true で報告の期限の目安を管理する（不正の目的によるおそれがあれば -malicious true）。" +
		"期限は目安なので、報告の要否と期限は最新のガイドラインで確かめる。", false},
	{"reinstall", "再インストール", "必要なデータを書き出し（実行ファイルやマクロを含めない）、乗っ取られていない端末で検査する。OS を信頼できる媒体から入れ直して更新を当て、" +
		"susanoo client keygen で端末の鍵を作り直し、susanoo ctl issue で証明書を発行し直す。バックアップから戻すときは、侵入の時期より前のものを使う。", false},
	{"release", "復旧（隔離の解除）", "再インストールや駆除が終わり、認証情報を変えたことを確かめてから、susanoo ctl release <端末> で隔離を解除する。" +
		"解除した後もしばらくは、時系列と危険度で再発がないかを見る。", true},
	{"lessons", "再発防止", "侵入の経路（メール、脆弱性、正規ツール、AI エージェントなど）と、検知や対応で遅れたところを振り返り、ポリシー、検知ルール、例外、手順を見直す。" +
		"終わったら susanoo ctl incident update <ID> -close でインシデントを閉じる。", false},
}

func stepByID(id string) (stepDef, bool) {
	i := slices.IndexFunc(incidentSteps, func(s stepDef) bool { return s.id == id })
	if i < 0 {
		return stepDef{}, false
	}
	return incidentSteps[i], true
}

// initIncidents はインシデントを読む。
func (c *Controller) initIncidents() error {
	data, err := os.ReadFile(filepath.Join(c.cfg.Dir, incidentsFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &c.incidents); err != nil {
		return fmt.Errorf("controller: %s を解析できません: %w", incidentsFile, err)
	}
	return nil
}

func (c *Controller) saveIncidentsLocked() {
	if err := saveJSON(filepath.Join(c.cfg.Dir, incidentsFile), c.incidents); err != nil {
		c.log.Error("インシデントを保存できません", "エラー", err)
	}
}

func (c *Controller) incidentLocked(id string) *incident {
	for _, inc := range c.incidents {
		if inc.ID == id {
			return inc
		}
	}
	return nil
}

// newIncidentLocked はインシデントを作る。ID は「INC-日付-通し番号」。
func (c *Controller) newIncidentLocked(title string, devices []string, known time.Time, actor string) *incident {
	now := c.now()
	day := now.Local().Format("20060102")
	n := 1
	for _, inc := range c.incidents {
		if strings.HasPrefix(inc.ID, "INC-"+day+"-") {
			n++
		}
	}
	inc := &incident{ID: fmt.Sprintf("INC-%s-%03d", day, n), Title: title, Devices: devices, Status: api.IncidentOpen, Opened: now.UTC(),
		OpenedBy: actor, KnownAt: cmp.Or(known, now).UTC(), Steps: map[string]*incidentStep{}}
	c.incidents = append(c.incidents, inc)
	// 閉じたものから古い順に、上限を超えた分を捨てる。
	for len(c.incidents) > maxIncidents {
		i := slices.IndexFunc(c.incidents, func(x *incident) bool { return x.Status == api.IncidentClosed })
		if i < 0 {
			break
		}
		c.incidents = slices.Delete(c.incidents, i, i+1)
	}
	return inc
}

// openIncidentForLocked は、対象 target（端末 ID か MAC アドレス）を隔離したときに呼ぶ。対象の開いたインシデントがあればその ID を、
// なければ新しく開いて ID を返す。
func (c *Controller) openIncidentForLocked(target, name, reason, actor string) string {
	for _, inc := range c.incidents {
		if inc.Status == api.IncidentOpen && slices.Contains(inc.Devices, target) {
			c.refreshIncidentLocked(inc)
			c.saveIncidentsLocked()
			return inc.ID
		}
	}
	inc := c.newIncidentLocked(fmt.Sprintf("%s の隔離（%s）", name, reason), []string{target}, time.Time{}, actor)
	inc.Notes = append(inc.Notes, api.IncidentNote{At: inc.Opened, By: actorSystem, Text: fmt.Sprintf("%s を隔離したため、インシデントを開きました（理由 %s、操作 %s）", name, reason, actorLabel(actor))})
	c.refreshIncidentLocked(inc)
	c.saveIncidentsLocked()
	c.auditLocked(actorSystem, ActionIncidentOpen, inc.ID, netip.Addr{}, map[string]any{"devices": inc.Devices, "title": inc.Title})
	c.log.Warn("インシデントを開きました", "ID", inc.ID, "対象", target)
	return inc.ID
}

// isolatedLocked は対象が隔離中か（承認待ちは含まない）を返す。
func (c *Controller) isolatedLocked(target string) bool {
	if d := c.devices[target]; d != nil {
		return d.Isolation != ""
	}
	if h := c.hosts[target]; h != nil {
		return h.Isolation != ""
	}
	return false
}

// refreshIncidentLocked は、自動の手順（切り離し、証拠の保全、復旧）を台帳と証拠の状態で済みにする。変えたら true を返す。
// 一度済みにした手順は、状態が戻っても済みのまま（隔離を解除しても切り離しは済み）。
func (c *Controller) refreshIncidentLocked(inc *incident) bool {
	if inc.Status != api.IncidentOpen {
		return false
	}
	now := c.now().UTC()
	done := func(id string) bool { s := inc.Steps[id]; return s != nil && s.Status != api.StepTodo }
	mark := func(id string) {
		inc.Steps[id] = &incidentStep{Status: api.StepDone, By: actorSystem, At: now}
	}
	changed := false
	if inc.Steps == nil {
		inc.Steps = map[string]*incidentStep{}
	}
	if !done("isolate") && len(inc.Devices) > 0 && !slices.ContainsFunc(inc.Devices, func(t string) bool { return !c.isolatedLocked(t) }) {
		mark("isolate")
		changed = true
	}
	if !done("evidence") {
		var clients []string
		for _, t := range inc.Devices {
			if c.devices[t] != nil {
				clients = append(clients, t)
			}
		}
		c.evidenceMu.Lock()
		all := len(clients) > 0 && !slices.ContainsFunc(clients, func(t string) bool {
			return !slices.ContainsFunc(c.evidence, func(x api.EvidenceInfo) bool {
				return x.Device == t && !x.Received.Before(inc.Opened.Add(-evidenceSlack))
			})
		})
		c.evidenceMu.Unlock()
		if all {
			mark("evidence")
			changed = true
		}
	}
	if done("isolate") && !done("release") && !slices.ContainsFunc(inc.Devices, c.isolatedLocked) {
		mark("release")
		changed = true
	}
	return changed
}

// refreshIncidentsLocked は開いているすべてのインシデントの自動の手順を確かめ、変えたら保存する。
func (c *Controller) refreshIncidentsLocked() {
	changed := false
	for _, inc := range c.incidents {
		if c.refreshIncidentLocked(inc) {
			changed = true
		}
	}
	if changed {
		c.saveIncidentsLocked()
	}
}

// deadlines は報告の期限の目安を返す（個人情報の漏えい等のおそれがあるときだけ）。
func (inc *incident) deadlines() []api.Deadline {
	if !inc.PersonalData {
		return nil
	}
	final := finalDue
	if inc.Malicious {
		final = finalDueMalicious
	}
	return []api.Deadline{
		{Name: "速報", From: inc.KnownAt.Add(prelimFrom), Due: inc.KnownAt.Add(prelimDue), Done: inc.PrelimReported},
		{Name: "確報", Due: inc.KnownAt.Add(final), Done: inc.FinalReported},
	}
}

func (inc *incident) view() api.Incident {
	v := api.Incident{ID: inc.ID, Title: inc.Title, Devices: slices.Clone(inc.Devices), Status: inc.Status, Opened: inc.Opened, OpenedBy: inc.OpenedBy,
		KnownAt: inc.KnownAt, Closed: inc.Closed, PersonalData: inc.PersonalData, Malicious: inc.Malicious,
		PrelimReported: inc.PrelimReported, FinalReported: inc.FinalReported, Deadlines: inc.deadlines(), Notes: slices.Clone(inc.Notes)}
	for _, d := range incidentSteps {
		s := api.IncidentStep{ID: d.id, Title: d.title, Guide: d.guide, Status: api.StepTodo, Auto: d.auto}
		if st := inc.Steps[d.id]; st != nil {
			s.Status, s.By, s.At, s.Note = st.Status, st.By, st.At, st.Note
		}
		v.Steps = append(v.Steps, s)
	}
	return v
}

// checkIncidentDeadlines は、報告していない期限が近づいたら（速報は目安の期間に入ったら、確報は 3 日前から）、
// また過ぎたら、1 回ずつ通知する。
func (c *Controller) checkIncidentDeadlines() {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	changed := false
	for _, inc := range c.incidents {
		if inc.Status != api.IncidentOpen {
			continue
		}
		for _, d := range inc.deadlines() {
			if !d.Done.IsZero() {
				continue
			}
			remind := cmp.Or(d.From, d.Due.Add(-finalRemind))
			var key, title string
			switch {
			case now.After(d.Due):
				key, title = d.Name+"-over", fmt.Sprintf("インシデント %s の%sの期限の目安（%s）を過ぎました", inc.ID, d.Name, d.Due.Local().Format("2006-01-02 15:04"))
			case !now.Before(remind):
				key, title = d.Name+"-soon", fmt.Sprintf("インシデント %s の%sの期限の目安（%s）が近づいています", inc.ID, d.Name, d.Due.Local().Format("2006-01-02 15:04"))
			default:
				continue
			}
			if slices.Contains(inc.Reminded, key) {
				continue
			}
			inc.Reminded = append(inc.Reminded, key)
			changed = true
			c.log.Warn(title, "インシデント", inc.ID)
			c.cfg.Notifier.Notify(notify.Message{Kind: notify.KindIncident, Severity: event.SeverityHigh, Title: title, Target: inc.ID, Time: now,
				Body:   "個人情報保護委員会への報告の期限の目安です。報告したら susanoo ctl incident update " + inc.ID + " -prelim-reported now（確報は -final-reported now）で記録してください。期限は目安なので、最新のガイドラインで確かめてください。",
				Fields: map[string]string{"対象": strings.Join(inc.Devices, "、"), "理由": inc.Title}})
		}
	}
	if changed {
		c.saveIncidentsLocked()
	}
}

// incidentCountsLocked は全体の状態に載せる、開いているインシデントの数と、最も近い報告していない期限を返す。
func (c *Controller) incidentCountsLocked() api.IncidentCounts {
	var n api.IncidentCounts
	for _, inc := range c.incidents {
		if inc.Status != api.IncidentOpen {
			continue
		}
		n.Open++
		for _, d := range inc.deadlines() {
			if d.Done.IsZero() && (n.Next == nil || d.Due.Before(n.Next.Due)) {
				n.Next = &api.IncidentDeadline{Incident: inc.ID, Name: d.Name, Due: d.Due}
			}
		}
	}
	return n
}

// listIncidents はインシデントの一覧を返す（新しい順。?all=1 でなければ開いているものだけ）。
func (c *Controller) listIncidents(w http.ResponseWriter, r *http.Request, _ pki.Identity) {
	all := r.URL.Query().Get("all") == "1"
	c.mu.Lock()
	c.refreshIncidentsLocked()
	out := []api.Incident{}
	for _, inc := range slices.Backward(c.incidents) {
		if all || inc.Status == api.IncidentOpen {
			out = append(out, inc.view())
		}
	}
	c.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

func (c *Controller) getIncident(w http.ResponseWriter, r *http.Request, _ pki.Identity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	inc := c.incidentLocked(r.PathValue("id"))
	if inc == nil {
		writeError(w, http.StatusNotFound, "そのインシデントはありません")
		return
	}
	if c.refreshIncidentLocked(inc) {
		c.saveIncidentsLocked()
	}
	writeJSON(w, http.StatusOK, inc.view())
}

// openIncident は管理者がインシデントを開く。対象は台帳にある端末 ID か機器の MAC アドレス。
func (c *Controller) openIncident(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	var req api.IncidentOpenRequest
	if !decode(w, r, &req) {
		return
	}
	req.Title = strings.TrimSpace(req.Title)
	if req.Title == "" || len(req.Title) > 200 || len(req.Devices) == 0 || len(req.Devices) > 250 {
		writeError(w, http.StatusBadRequest, "題名（200 バイトまで）と、対象の端末か機器（250 台まで）を指定してください")
		return
	}
	actor := "admin/" + admin.ID
	c.mu.Lock()
	defer c.mu.Unlock()
	var devices []string
	for _, d := range req.Devices {
		if hw, err := net.ParseMAC(d); err == nil && len(hw) == 6 {
			d = hw.String()
		}
		if c.devices[d] == nil && c.hosts[d] == nil {
			writeError(w, http.StatusNotFound, fmt.Sprintf("端末か機器 %q は台帳にありません", d))
			return
		}
		if !slices.Contains(devices, d) {
			devices = append(devices, d)
		}
	}
	if !req.KnownAt.IsZero() && req.KnownAt.After(c.now().Add(time.Minute)) {
		writeError(w, http.StatusBadRequest, "事態を知った時刻が未来です")
		return
	}
	inc := c.newIncidentLocked(req.Title, devices, req.KnownAt, actor)
	inc.PersonalData, inc.Malicious = req.PersonalData, req.Malicious
	if n := strings.TrimSpace(req.Note); n != "" {
		inc.Notes = append(inc.Notes, api.IncidentNote{At: inc.Opened, By: actor, Text: n})
	}
	c.refreshIncidentLocked(inc)
	c.saveIncidentsLocked()
	c.auditLocked(actor, ActionIncidentOpen, inc.ID, netip.Addr{}, map[string]any{"devices": devices, "title": inc.Title, "known_at": inc.KnownAt, "personal_data": inc.PersonalData})
	c.log.Warn("インシデントを開きました", "ID", inc.ID, "対象", devices, "操作", actor)
	writeJSON(w, http.StatusOK, inc.view())
}

// updateIncident はインシデントの項目を変える。変えた項目は監査ログに残す。
func (c *Controller) updateIncident(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	var req api.IncidentUpdate
	if !decode(w, r, &req) {
		return
	}
	actor := "admin/" + admin.ID
	c.mu.Lock()
	defer c.mu.Unlock()
	inc := c.incidentLocked(r.PathValue("id"))
	if inc == nil {
		writeError(w, http.StatusNotFound, "そのインシデントはありません")
		return
	}
	now := c.now()
	detail := map[string]any{}
	if req.Title != nil {
		t := strings.TrimSpace(*req.Title)
		if t == "" || len(t) > 200 {
			writeError(w, http.StatusBadRequest, "題名は 200 バイトまでで、空にはできません")
			return
		}
		inc.Title, detail["title"] = t, t
	}
	if req.KnownAt != nil {
		if req.KnownAt.IsZero() || req.KnownAt.After(now.Add(time.Minute)) {
			writeError(w, http.StatusBadRequest, "事態を知った時刻が不正です")
			return
		}
		inc.KnownAt, detail["known_at"] = req.KnownAt.UTC(), req.KnownAt.UTC()
		inc.Reminded = nil // 期限が変わるので、知らせ直す
	}
	if req.PersonalData != nil {
		inc.PersonalData, detail["personal_data"] = *req.PersonalData, *req.PersonalData
	}
	if req.Malicious != nil {
		inc.Malicious, detail["malicious"] = *req.Malicious, *req.Malicious
		inc.Reminded = slices.DeleteFunc(inc.Reminded, func(k string) bool { return strings.HasPrefix(k, "確報") })
	}
	if req.PrelimReported != nil {
		inc.PrelimReported, detail["prelim_reported"] = req.PrelimReported.UTC(), req.PrelimReported.UTC()
	}
	if req.FinalReported != nil {
		inc.FinalReported, detail["final_reported"] = req.FinalReported.UTC(), req.FinalReported.UTC()
	}
	if n := strings.TrimSpace(req.Note); n != "" {
		if len(n) > 4000 {
			writeError(w, http.StatusBadRequest, "記録は 4000 バイトまでです")
			return
		}
		inc.Notes = append(inc.Notes, api.IncidentNote{At: now.UTC(), By: actor, Text: n})
		detail["note"] = n
	}
	switch req.Status {
	case "":
	case api.IncidentClosed:
		if inc.Status != api.IncidentClosed {
			inc.Status, inc.Closed, detail["status"] = api.IncidentClosed, now.UTC(), api.IncidentClosed
		}
	case api.IncidentOpen:
		if inc.Status != api.IncidentOpen {
			inc.Status, inc.Closed, detail["status"] = api.IncidentOpen, time.Time{}, api.IncidentOpen
		}
	default:
		writeError(w, http.StatusBadRequest, "status は open か closed にしてください")
		return
	}
	if len(detail) > 0 {
		c.saveIncidentsLocked()
		c.auditLocked(actor, ActionIncidentUpdate, inc.ID, netip.Addr{}, detail)
	}
	writeJSON(w, http.StatusOK, inc.view())
}

// updateStep は手順の状態を変える。
func (c *Controller) updateStep(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	var req api.StepUpdate
	if !decode(w, r, &req) {
		return
	}
	if _, ok := stepByID(r.PathValue("step")); !ok {
		writeError(w, http.StatusNotFound, "その手順はありません")
		return
	}
	switch req.Status {
	case api.StepTodo, api.StepDone, api.StepSkipped:
	default:
		writeError(w, http.StatusBadRequest, "status は todo、done、skipped のどれかにしてください")
		return
	}
	if len(req.Note) > 4000 {
		writeError(w, http.StatusBadRequest, "記録は 4000 バイトまでです")
		return
	}
	actor := "admin/" + admin.ID
	c.mu.Lock()
	defer c.mu.Unlock()
	inc := c.incidentLocked(r.PathValue("id"))
	if inc == nil {
		writeError(w, http.StatusNotFound, "そのインシデントはありません")
		return
	}
	if inc.Steps == nil {
		inc.Steps = map[string]*incidentStep{}
	}
	step := r.PathValue("step")
	inc.Steps[step] = &incidentStep{Status: req.Status, By: actor, At: c.now().UTC(), Note: strings.TrimSpace(req.Note)}
	c.saveIncidentsLocked()
	c.auditLocked(actor, ActionIncidentStep, inc.ID, netip.Addr{}, map[string]any{"step": step, "status": req.Status, "note": req.Note})
	writeJSON(w, http.StatusOK, inc.view())
}

// auditLabels は時系列に載せる監査ログの操作の表し方。
var auditLabels = map[string]string{
	ActionRegister: "端末を台帳に載せた", ActionIsolate: "端末を隔離した", ActionIsolatePending: "隔離の承認待ち", ActionRelease: "端末の隔離を解除した",
	ActionHostIsolate: "機器を隔離した", ActionHostIsolatePending: "機器の隔離の承認待ち", ActionHostRelease: "機器の隔離を解除した",
	ActionEvidenceReceive: "証拠を受け取った", ActionEvidenceRequest: "証拠を求めた", ActionIncidentOpen: "インシデントを開いた",
	ActionIncidentUpdate: "インシデントを変えた", ActionIncidentStep: "手順の状態を変えた",
}

// incidentTimeline はインシデントの時系列を作る。対象の端末と機器のイベント（既定は検知結果だけ。?all=1 ならすべて）、
// 監査ログ（対象とインシデントへの操作）、証拠を、時刻の順に並べる。範囲は、インシデントを開いた時刻と事態を知った時刻の早いほうの
// before（既定 24 時間）前から、閉じた時刻（開いていれば今）まで。
func (c *Controller) incidentTimeline(w http.ResponseWriter, r *http.Request, _ pki.Identity) {
	q := r.URL.Query()
	all := q.Get("all") == "1"
	before := defaultTimelineBefore
	if s := q.Get("before"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d < 0 || d > maxTimelineBefore {
			writeError(w, http.StatusBadRequest, "before は 0 から 720h までの時間で書いてください")
			return
		}
		before = d
	}
	c.mu.Lock()
	inc := c.incidentLocked(r.PathValue("id"))
	var devices []string
	var since, until time.Time
	var incID string
	if inc != nil {
		devices, incID = slices.Clone(inc.Devices), inc.ID
		since = minTime(inc.Opened, inc.KnownAt).Add(-before)
		until = cmp.Or(inc.Closed, c.now())
	}
	c.mu.Unlock()
	if inc == nil {
		writeError(w, http.StatusNotFound, "そのインシデントはありません")
		return
	}
	entries, truncated, err := c.timeline(devices, incID, since, until, all)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if truncated {
		entries = append([]api.TimelineEntry{{Time: since, Source: "susanoo", Kind: "truncated",
			Summary: fmt.Sprintf("イベントが %d 件を超えたため、古いものを省きました（範囲を狭めるか、検知結果だけにしてください）", maxTimelineEvents)}}, entries...)
	}
	writeJSON(w, http.StatusOK, entries)
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// timeline は時系列の材料を集めて並べる。
func (c *Controller) timeline(devices []string, incID string, since, until time.Time, all bool) ([]api.TimelineEntry, bool, error) {
	var out []api.TimelineEntry
	findingFilter := []byte(`"class_uid":` + strconv.Itoa(int(event.ClassDetectionFinding)) + `,`)
	from, to := since.UnixMilli(), until.UnixMilli()
	match := func(line []byte) bool {
		if !all && !bytes.Contains(line, findingFilter) {
			return false
		}
		var e event.Event
		if json.Unmarshal(line, &e) != nil || e.Time < from || e.Time > to {
			return false
		}
		return slices.ContainsFunc(devices, func(d string) bool { return eventOf(&e, d) })
	}
	lines, err := c.events.Query(since, maxTimelineEvents+1, match)
	if err != nil {
		return nil, false, err
	}
	truncated := len(lines) > maxTimelineEvents
	if truncated {
		lines = lines[:maxTimelineEvents]
	}
	for _, line := range lines {
		var e event.Event
		if json.Unmarshal(line, &e) != nil {
			continue
		}
		dev := ""
		for _, d := range devices {
			if eventOf(&e, d) {
				dev = d
				break
			}
		}
		kind := map[event.ClassUID]string{event.ClassFileSystemActivity: "file", event.ClassProcessActivity: "process",
			event.ClassNetworkActivity: "network", event.ClassDNSActivity: "dns", event.ClassDHCPActivity: "dhcp", event.ClassAuthentication: "logon"}[e.ClassUID]
		summary := describe(&e)
		if f := e.FindingInfo; f != nil {
			kind = "finding"
			if len(f.Types) > 0 {
				kind += ":" + f.Types[0]
			}
			summary = f.Title + "：" + cmp.Or(e.Message, f.Desc)
		}
		out = append(out, api.TimelineEntry{Time: time.UnixMilli(e.Time).UTC(), Source: "event", Kind: kind, Device: dev, Severity: e.SeverityID, Summary: summary})
	}
	for _, rec := range c.auditRecords() {
		if rec.Time.Before(since) || rec.Time.After(until) || (rec.Target != incID && !slices.Contains(devices, rec.Target)) {
			continue
		}
		var detail map[string]any
		json.Unmarshal(rec.Detail, &detail)
		summary := cmp.Or(auditLabels[rec.Action], rec.Action) + "（" + actorLabel(rec.Actor) + "）"
		for _, k := range []string{"reason", "step", "status", "note", "id"} {
			if v, ok := detail[k]; ok && v != "" {
				summary += fmt.Sprintf(" %s=%v", k, v)
			}
		}
		dev := rec.Target
		if rec.Target == incID {
			dev = ""
		}
		out = append(out, api.TimelineEntry{Time: rec.Time.UTC(), Source: "audit", Kind: rec.Action, Device: dev, Summary: summary})
	}
	c.evidenceMu.Lock()
	for _, x := range c.evidence {
		if slices.Contains(devices, x.Device) && !x.Time.Before(since) && !x.Time.After(until) {
			out = append(out, api.TimelineEntry{Time: x.Time.UTC(), Source: "evidence", Kind: x.Reason, Device: x.Device,
				Summary: fmt.Sprintf("証拠 %s（プロセス %d、接続 %d、ログ %d、SHA-256 %s）", x.ID, x.Processes, x.Connections, x.Logs, x.SHA256)})
		}
	}
	c.evidenceMu.Unlock()
	slices.SortStableFunc(out, func(a, b api.TimelineEntry) int { return a.Time.Compare(b.Time) })
	return out, truncated, nil
}

// auditRecords は監査ログの記録を読む（書き込み中の最後の行など、読めない行は飛ばす）。
func (c *Controller) auditRecords() []audit.Record {
	f, err := os.Open(filepath.Join(c.cfg.Dir, "audit.log"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []audit.Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var r audit.Record
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			out = append(out, r)
		}
	}
	return out
}
