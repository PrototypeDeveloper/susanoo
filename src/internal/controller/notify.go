package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/notify"
	"susanoo/internal/pki"
	"susanoo/internal/policy"
)

// 管理者への通知（M7）。隔離、隔離の承認待ち、隔離が必要な検知（警告モード、監視モードで隔離しないとき）、隔離の解除と、
// 加点した検知結果のうち隔離に至らなかったもの（防御の仕組みの改ざんなど）を知らせる。試験運用（monitor）のルールの
// 当てはまりは知らせない（誤検知を確かめている段階のため）。送信は notify.Notifier が待たずに行うので、ロックを持ったまま呼んでよい。

// notifyTestTimeout は試験の通知の待ち時間（管理通信の応答の期限より短くする）。
const notifyTestTimeout = 25 * time.Second

// subjectName は通知の題名に使う対象の名前（「端末 pc-001」「機器 02:00:00:00:00:01」）。
func subjectName(device, mac string) string {
	if device != "" {
		return "端末 " + device
	}
	return "機器 " + mac
}

func actorLabel(actor string) string {
	if actor == actorSystem {
		return "自動対応"
	}
	return actor
}

// notifyIsolateLocked は隔離したことを知らせる。
func (c *Controller) notifyIsolateLocked(device, mac string, addr netip.Addr, group string, level policy.IsolationLevel, reason, actor string, risk int, incident string) {
	name := subjectName(device, mac)
	target := cmpOr(device, mac)
	body := "検知に基づいて自動で隔離しました。"
	if actor != actorSystem {
		body = "管理者が隔離しました。"
	}
	f := map[string]string{"対象": name, "理由": reason, "段階": string(level), "グループ": group, "操作": actorLabel(actor),
		"対処": fmt.Sprintf("susanoo ctl events -device %s -since 1h で経緯を確かめ、問題がなければ susanoo ctl release %s で解除します", target, target)}
	if addr.IsValid() {
		f["アドレス"] = addr.String()
	}
	if risk > 0 {
		f["危険度"] = fmt.Sprint(risk)
	}
	if device != "" {
		f["対処"] += "。証拠は susanoo ctl evidence list -device " + device + " で確かめられます"
	}
	if incident != "" {
		f["インシデント"] = incident
		f["対処"] += "。対応の手順は susanoo ctl incident show " + incident + " で確かめられます"
	}
	c.cfg.Notifier.Notify(notify.Message{Kind: notify.KindIsolate, Severity: event.SeverityHigh, Title: name + " を隔離しました",
		Body: body, Target: target, Time: c.now(), Fields: f})
}

// notifyPendingLocked は隔離の承認を待っていることを知らせる。
func (c *Controller) notifyPendingLocked(device, mac string, group, reason string) {
	name := subjectName(device, mac)
	target := cmpOr(device, mac)
	c.cfg.Notifier.Notify(notify.Message{Kind: notify.KindPending, Severity: event.SeverityHigh, Title: name + " の隔離の承認を待っています",
		Body: "このグループは隔離に人の承認が必要です。内容を確かめて、隔離するかを決めてください。", Target: target, Time: c.now(),
		Fields: map[string]string{"対象": name, "理由": reason, "グループ": group,
			"対処": fmt.Sprintf("隔離するなら susanoo ctl isolate %s、隔離しないなら susanoo ctl release %s（承認待ちを取り消す）", target, target)}})
}

// notifyAlertLocked は、隔離が必要な検知があったが、対応の方式（警告、監視）のため隔離しないことを知らせる。
func (c *Controller) notifyAlertLocked(target, reason string, response policy.Response) {
	mode := map[policy.Response]string{policy.ResponseAlert: "警告モード", policy.ResponseMonitor: "監視モード"}[response]
	name := "端末 " + target
	if strings.Count(target, ":") == 5 {
		name = "機器 " + target
	}
	c.cfg.Notifier.Notify(notify.Message{Kind: notify.KindAlert, Severity: event.SeverityHigh,
		Title:  fmt.Sprintf("%s に隔離が必要な検知がありました（%sのため隔離しません）", name, mode),
		Body:   "ポリシーの対応の方式が " + mode + " のため、自動では隔離しません。内容を確かめて、必要なら手動で隔離してください。",
		Target: target, Time: c.now(),
		Fields: map[string]string{"対象": name, "理由": reason, "対処": fmt.Sprintf("隔離するなら susanoo ctl isolate %s", target)}})
}

// notifyReleaseLocked は隔離を解除したことを知らせる。
func (c *Controller) notifyReleaseLocked(device, mac string, prev policy.IsolationLevel, actor string) {
	name := subjectName(device, mac)
	c.cfg.Notifier.Notify(notify.Message{Kind: notify.KindRelease, Severity: event.SeverityInformational, Title: name + " の隔離を解除しました",
		Target: cmpOr(device, mac), Time: c.now(), Fields: map[string]string{"対象": name, "段階": string(prev), "操作": actorLabel(actor)}})
}

// notifyFinding は、加点した検知結果のうち、隔離に至らなかったものを知らせる。
func (c *Controller) notifyFinding(t target, ruleName string, sev event.Severity, e *event.Event, score, threshold int) {
	if !c.cfg.Notifier.Enabled() {
		return
	}
	name := "検知の対象が分からない通信"
	if t.device != "" || t.mac != "" {
		name = subjectName(t.device, t.mac)
	}
	f := map[string]string{"対象": name, "理由": ruleName}
	if t.key != "" {
		f["危険度"] = fmt.Sprintf("%d / %d（しきい値に達すると自動で対応します）", score, threshold)
	}
	if t.group != "" {
		f["グループ"] = t.group
	}
	c.cfg.Notifier.Notify(notify.Message{Kind: notify.KindFinding, Severity: sev, Title: fmt.Sprintf("%s で「%s」を検知しました", name, ruleName),
		Body: describe(e), Target: cmpOr(t.device, t.mac), Time: c.now(), Fields: f})
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// testNotify は試験の通知をすべての宛先に送り、結果を返す（ctl notify test）。
func (c *Controller) testNotify(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	if !c.cfg.Notifier.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "通知の宛先が設定されていません（GW の設定ファイルの notify）")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), notifyTestTimeout)
	defer cancel()
	out := []api.NotifyResult{}
	for _, res := range c.cfg.Notifier.Test(ctx) {
		out = append(out, api.NotifyResult{Name: res.Name, Error: res.Error})
	}
	c.log.Info("試験の通知を送りました", "操作", "admin/"+admin.ID, "結果", out)
	writeJSON(w, http.StatusOK, out)
}

// notifyStatus は通知の宛先ごとの送信の状況を返す。
func (c *Controller) notifyStatus() []api.NotifyStatus {
	var out []api.NotifyStatus
	for _, s := range c.cfg.Notifier.Status() {
		out = append(out, api.NotifyStatus(s))
	}
	return out
}
