package main

import (
	"cmp"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/fsutil"
	"susanoo/internal/version"
)

// インシデント対応の支援（M9）の操作。

const ctlIncidentUsage = `使い方: susanoo ctl incident <操作> [オプション]

操作:
  list      インシデントの一覧（開いているもの。-all で閉じたものも）
  open      インシデントを開く（例: susanoo ctl incident open -title "不審なメールの添付を開いた" pc-001 pc-002）
  show      中身（対象、報告の期限の目安、手順、記録）を表示する（例: susanoo ctl incident show INC-20261019-001。-guide で手順の説明も）
  step      手順の状態を変える（例: susanoo ctl incident step INC-20261019-001 credentials done -note "パスワードを変更"）。状態は done、skip、todo
  update    項目を変える、記録を足す、閉じる（例: susanoo ctl incident update INC-20261019-001 -personal-data true -note "顧客の一覧が端末にあった"）
  timeline  時系列（検知結果、隔離などの操作、証拠）を表示する（-all ですべての種類のイベント、-before 72h で開く前のどこから並べるか）
  report    報告書（Markdown）を書き出す（例: susanoo ctl incident report INC-20261019-001 -out report.md）

端末か機器を隔離すると、インシデントは自動で開く。個人情報の漏えい等のおそれがあるときは -personal-data true にすると、
個人情報保護委員会への速報と確報の期限の目安を管理し、近づいたら通知する（期限は目安。最新のガイドラインで確かめる）。
`

func ctlIncident(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, ctlIncidentUsage)
		return exitUsage
	}
	switch args[0] {
	case "list":
		return ctlIncidentList(args[1:], stdout, stderr)
	case "open":
		return ctlIncidentOpen(args[1:], stdout, stderr)
	case "show":
		return ctlIncidentShow(args[1:], stdout, stderr)
	case "step":
		return ctlIncidentStep(args[1:], stdout, stderr)
	case "update":
		return ctlIncidentUpdate(args[1:], stdout, stderr)
	case "timeline":
		return ctlIncidentTimeline(args[1:], stdout, stderr)
	case "report":
		return ctlIncidentReport(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, ctlIncidentUsage)
		return exitOK
	}
	fmt.Fprintf(stderr, "susanoo: 不明な操作です: ctl incident %s\n\n%s", args[0], ctlIncidentUsage)
	return exitUsage
}

// leadingArgs はオプションの前に書いた引数を n 個まで取り出す。
func leadingArgs(args []string, n int) ([]string, []string) {
	var pos []string
	for len(args) > 0 && !strings.HasPrefix(args[0], "-") && len(pos) < n {
		pos, args = append(pos, args[0]), args[1:]
	}
	return pos, args
}

var stepLabels = map[string]string{api.StepTodo: "未", api.StepDone: "済", api.StepSkipped: "省略"}

func incidentPath(id string) string { return api.PathIncidents + "/" + url.PathEscape(id) }

func ctlIncidentList(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl incident list", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	all := flags.Bool("all", false, "閉じたものも表示する")
	asJSON := flags.Bool("json", false, "JSON で表示する")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	path := api.PathIncidents
	if *all {
		path += "?all=1"
	}
	var list []api.Incident
	if err := c.do(http.MethodGet, path, nil, &list); err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(list)
		return exitOK
	}
	if len(list) == 0 {
		fmt.Fprintln(stdout, "インシデントはありません。")
		return exitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\t状態\t開いた時刻\t対象\t手順\t次の期限\t題名")
	for _, inc := range list {
		done := 0
		for _, s := range inc.Steps {
			if s.Status != api.StepTodo {
				done++
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d / %d\t%s\t%s\n", inc.ID, map[string]string{api.IncidentOpen: "対応中", api.IncidentClosed: "終了"}[inc.Status],
			inc.Opened.Local().Format(timeFormat), strings.Join(inc.Devices, ","), done, len(inc.Steps), nextDeadline(inc, time.Now()), oneLine(inc.Title))
	}
	tw.Flush()
	return exitOK
}

// nextDeadline は報告していない最も近い期限を「確報 11-18（あと 29 日）」の形で返す。なければ「-」。
func nextDeadline(inc api.Incident, now time.Time) string {
	for _, d := range inc.Deadlines {
		if d.Done.IsZero() {
			return d.Name + " " + d.Due.Local().Format("01-02 15:04") + "（" + remaining(d.Due, now) + "）"
		}
	}
	return "-"
}

func remaining(due, now time.Time) string {
	d := due.Sub(now)
	if d < 0 {
		return fmt.Sprintf("%d 時間過ぎています", int(-d.Hours()))
	}
	if d < 48*time.Hour {
		return fmt.Sprintf("あと %d 時間", int(d.Hours()))
	}
	return fmt.Sprintf("あと %d 日", int(d.Hours()/24))
}

// parseMoment は「now」、「1h」のような今からの長さ（その長さだけ前）、「2026-10-18」、RFC 3339 の時刻を読む。
func parseMoment(s string) (time.Time, error) {
	if s == "now" {
		return time.Now(), nil
	}
	return parseWhen(s, time.Now())
}

func ctlIncidentOpen(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl incident open", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	var req api.IncidentOpenRequest
	flags.StringVar(&req.Title, "title", "", "題名（必須）")
	known := flags.String("known", "", "事態を知った時刻（報告の期限の起算点。「2026-10-18T09:30:00+09:00」や「3h」。省略すると今）")
	flags.BoolVar(&req.PersonalData, "personal-data", false, "個人情報の漏えい等のおそれがある")
	flags.BoolVar(&req.Malicious, "malicious", false, "不正の目的をもって行われたおそれがある（確報の期限が 60 日になる）")
	flags.StringVar(&req.Note, "note", "", "記録")
	devices, rest := leadingArgs(args, 250)
	if err := flags.Parse(rest); err != nil {
		return exitUsage
	}
	req.Devices = append(devices, flags.Args()...)
	if *known != "" {
		t, err := parseMoment(*known)
		if err != nil {
			return fail(stderr, fmt.Errorf("-known: %w", err))
		}
		req.KnownAt = t
	}
	if req.Title == "" || len(req.Devices) == 0 {
		return fail(stderr, errors.New("-title と、対象の端末 ID か MAC アドレスを指定してください"))
	}
	var inc api.Incident
	if err := c.do(http.MethodPost, api.PathIncidents, req, &inc); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "インシデント %s を開きました。\n\n", inc.ID)
	printIncident(stdout, inc, false)
	return exitOK
}

func ctlIncidentShow(args []string, stdout, stderr io.Writer) int {
	pos, rest := leadingArgs(args, 1)
	flags := flag.NewFlagSet("ctl incident show", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	guide := flags.Bool("guide", false, "手順の説明も表示する")
	asJSON := flags.Bool("json", false, "JSON で表示する")
	if err := flags.Parse(rest); err != nil {
		return exitUsage
	}
	if len(pos) == 0 {
		return fail(stderr, errors.New("インシデントの ID を指定してください（ctl incident list で確かめられます）"))
	}
	var inc api.Incident
	if err := c.do(http.MethodGet, incidentPath(pos[0]), nil, &inc); err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(inc)
		return exitOK
	}
	printIncident(stdout, inc, *guide)
	return exitOK
}

func printIncident(w io.Writer, inc api.Incident, guide bool) {
	fmt.Fprintf(w, "%s %s（%s）\n", inc.ID, inc.Title, map[string]string{api.IncidentOpen: "対応中", api.IncidentClosed: "終了"}[inc.Status])
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "対象\t%s\n", strings.Join(inc.Devices, "、"))
	fmt.Fprintf(tw, "開いた時刻\t%s（%s）\n", inc.Opened.Local().Format("2006-01-02 15:04"), inc.OpenedBy)
	fmt.Fprintf(tw, "事態を知った時刻\t%s\n", inc.KnownAt.Local().Format("2006-01-02 15:04"))
	if !inc.Closed.IsZero() {
		fmt.Fprintf(tw, "閉じた時刻\t%s\n", inc.Closed.Local().Format("2006-01-02 15:04"))
	}
	pd := "なし（-personal-data true で期限を管理します）"
	if inc.PersonalData {
		pd = "おそれあり"
		if inc.Malicious {
			pd += "（不正の目的によるおそれあり）"
		}
	}
	fmt.Fprintf(tw, "個人情報の漏えい等\t%s\n", pd)
	tw.Flush()
	if len(inc.Deadlines) > 0 {
		fmt.Fprintln(w, "\n個人情報保護委員会への報告の期限の目安（最新のガイドラインで確かめてください）:")
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, d := range inc.Deadlines {
			due := d.Due.Local().Format("2006-01-02 15:04")
			if !d.From.IsZero() {
				due = d.From.Local().Format("01-02 15:04") + " 〜 " + due
			}
			state := remaining(d.Due, time.Now())
			if !d.Done.IsZero() {
				state = "報告済み（" + d.Done.Local().Format("01-02 15:04") + "）"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", d.Name, due, state)
		}
		tw.Flush()
		fmt.Fprintln(w, "  本人への通知も、速やかに行います。")
	}
	fmt.Fprintln(w, "\n手順:")
	tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for i, s := range inc.Steps {
		by := ""
		if s.Status != api.StepTodo {
			by = fmt.Sprintf("%s %s", actorName(s.By), s.At.Local().Format("01-02 15:04"))
		}
		auto := ""
		if s.Auto {
			auto = "（自動）"
		}
		fmt.Fprintf(tw, "  %d. %s\t%s%s\t%s\t%s\n", i+1, s.ID, s.Title, auto, stepLabels[s.Status], by)
		if s.Note != "" {
			fmt.Fprintf(tw, "\t  %s\t\t\n", oneLine(s.Note))
		}
		if guide {
			fmt.Fprintf(tw, "\t  %s\t\t\n", s.Guide)
		}
	}
	tw.Flush()
	if len(inc.Notes) > 0 {
		fmt.Fprintln(w, "\n記録:")
		for _, n := range inc.Notes {
			fmt.Fprintf(w, "  %s %s: %s\n", n.At.Local().Format("01-02 15:04"), actorName(n.By), oneLine(n.Text))
		}
	}
	if !guide {
		fmt.Fprintf(w, "\n手順の説明は -guide で表示します。時系列は susanoo ctl incident timeline %s で確かめられます。\n", inc.ID)
	}
}

func actorName(a string) string {
	if a == "system" {
		return "自動"
	}
	return a
}

func ctlIncidentStep(args []string, stdout, stderr io.Writer) int {
	pos, rest := leadingArgs(args, 3)
	flags := flag.NewFlagSet("ctl incident step", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	note := flags.String("note", "", "記録")
	if err := flags.Parse(rest); err != nil {
		return exitUsage
	}
	if len(pos) != 3 {
		return fail(stderr, errors.New("インシデントの ID、手順（ctl incident show で確かめられます）、状態（done、skip、todo）を指定してください"))
	}
	status := map[string]string{"done": api.StepDone, "skip": api.StepSkipped, "skipped": api.StepSkipped, "todo": api.StepTodo}[pos[2]]
	if status == "" {
		return fail(stderr, fmt.Errorf("状態 %q は done、skip、todo のどれかにしてください", pos[2]))
	}
	var inc api.Incident
	if err := c.do(http.MethodPost, incidentPath(pos[0])+"/steps/"+url.PathEscape(pos[1]), api.StepUpdate{Status: status, Note: *note}, &inc); err != nil {
		return fail(stderr, err)
	}
	printIncident(stdout, inc, false)
	return exitOK
}

func ctlIncidentUpdate(args []string, stdout, stderr io.Writer) int {
	pos, rest := leadingArgs(args, 1)
	flags := flag.NewFlagSet("ctl incident update", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	var req api.IncidentUpdate
	boolFlag := func(name, usage string, dst **bool) {
		flags.Func(name, usage+"（true か false）", func(s string) error {
			b, err := strconv.ParseBool(s)
			if err != nil {
				return err
			}
			*dst = &b
			return nil
		})
	}
	timeFlag := func(name, usage string, dst **time.Time, allowCancel bool) {
		flags.Func(name, usage, func(s string) error {
			if allowCancel && s == "cancel" {
				*dst = &time.Time{}
				return nil
			}
			t, err := parseMoment(s)
			if err != nil {
				return err
			}
			*dst = &t
			return nil
		})
	}
	flags.Func("title", "題名", func(s string) error { req.Title = &s; return nil })
	timeFlag("known", "事態を知った時刻（「2026-10-18T09:30:00+09:00」、「3h」など）", &req.KnownAt, false)
	boolFlag("personal-data", "個人情報の漏えい等のおそれがある", &req.PersonalData)
	boolFlag("malicious", "不正の目的をもって行われたおそれがある（確報の期限が 60 日になる）", &req.Malicious)
	timeFlag("prelim-reported", "個人情報保護委員会に速報した時刻（now、時刻。cancel で取り消す）", &req.PrelimReported, true)
	timeFlag("final-reported", "確報した時刻（now、時刻。cancel で取り消す）", &req.FinalReported, true)
	flags.StringVar(&req.Note, "note", "", "記録を足す")
	closeIt := flags.Bool("close", false, "インシデントを閉じる")
	reopen := flags.Bool("reopen", false, "閉じたインシデントを開き直す")
	if err := flags.Parse(rest); err != nil {
		return exitUsage
	}
	if len(pos) == 0 {
		return fail(stderr, errors.New("インシデントの ID を指定してください"))
	}
	switch {
	case *closeIt && *reopen:
		return fail(stderr, errors.New("-close と -reopen は一緒に使えません"))
	case *closeIt:
		req.Status = api.IncidentClosed
	case *reopen:
		req.Status = api.IncidentOpen
	}
	var inc api.Incident
	if err := c.do(http.MethodPost, incidentPath(pos[0]), req, &inc); err != nil {
		return fail(stderr, err)
	}
	printIncident(stdout, inc, false)
	return exitOK
}

// fetchTimeline は時系列を取り出す。
func fetchTimeline(c *ctlFlags, id string, all bool, before string) ([]api.TimelineEntry, error) {
	q := url.Values{}
	if all {
		q.Set("all", "1")
	}
	if before != "" {
		q.Set("before", before)
	}
	path := incidentPath(id) + "/timeline"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var tl []api.TimelineEntry
	err := c.doLimit(http.MethodGet, path, nil, &tl, api.MaxEvidenceBytes, time.Minute)
	return tl, err
}

var sourceLabels = map[string]string{"event": "イベント", "audit": "操作", "evidence": "証拠", "susanoo": "注意"}

func ctlIncidentTimeline(args []string, stdout, stderr io.Writer) int {
	pos, rest := leadingArgs(args, 1)
	flags := flag.NewFlagSet("ctl incident timeline", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	all := flags.Bool("all", false, "すべての種類のイベント（プロセス、通信、ファイル、DNS）を並べる")
	before := flags.String("before", "", "開く前のどこから並べるか（既定 24h、720h まで）")
	asJSON := flags.Bool("json", false, "JSON で表示する")
	if err := flags.Parse(rest); err != nil {
		return exitUsage
	}
	if len(pos) == 0 {
		return fail(stderr, errors.New("インシデントの ID を指定してください"))
	}
	tl, err := fetchTimeline(&c, pos[0], *all, *before)
	if err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(tl)
		return exitOK
	}
	if len(tl) == 0 {
		fmt.Fprintln(stdout, "時系列に並べるものはありません。")
		return exitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "時刻\t種類\t対象\t内容")
	for _, e := range tl {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Time.Local().Format("01-02 15:04:05"), sourceLabels[e.Source]+" "+e.Kind, dash(e.Device), oneLine(e.Summary))
	}
	tw.Flush()
	return exitOK
}

func ctlIncidentReport(args []string, stdout, stderr io.Writer) int {
	pos, rest := leadingArgs(args, 1)
	flags := flag.NewFlagSet("ctl incident report", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	all := flags.Bool("all", false, "時系列にすべての種類のイベントを並べる")
	before := flags.String("before", "", "時系列を開く前のどこから並べるか（既定 24h）")
	out := flags.String("out", "", "書き出すファイル（省略すると画面に表示する）")
	if err := flags.Parse(rest); err != nil {
		return exitUsage
	}
	if len(pos) == 0 {
		return fail(stderr, errors.New("インシデントの ID を指定してください"))
	}
	var inc api.Incident
	if err := c.do(http.MethodGet, incidentPath(pos[0]), nil, &inc); err != nil {
		return fail(stderr, err)
	}
	tl, err := fetchTimeline(&c, inc.ID, *all, *before)
	if err != nil {
		return fail(stderr, err)
	}
	var evidence []api.EvidenceInfo
	for _, d := range inc.Devices {
		var list []api.EvidenceInfo
		if err := c.do(http.MethodGet, api.PathEvidence+"?device="+url.QueryEscape(d), nil, &list); err != nil {
			return fail(stderr, err)
		}
		for _, e := range list {
			if !e.Time.Before(inc.Opened.Add(-24 * time.Hour)) {
				evidence = append(evidence, e)
			}
		}
	}
	report := incidentReport(inc, tl, evidence, time.Now())
	if *out == "" {
		io.WriteString(stdout, report)
		return exitOK
	}
	if err := fsutil.WriteFileAtomic(*out, []byte(report), 0o600); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "報告書を %s に書き出しました。\n", *out)
	return exitOK
}

// mdCell は Markdown の表の 1 つの欄に入れられるよう、改行と「|」を置き換える。
func mdCell(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ", "\r", " ").Replace(s)
}

// incidentReport は報告書を Markdown で作る。
func incidentReport(inc api.Incident, tl []api.TimelineEntry, evidence []api.EvidenceInfo, now time.Time) string {
	var b strings.Builder
	t := func(x time.Time) string {
		if x.IsZero() {
			return "-"
		}
		return x.Local().Format("2006-01-02 15:04:05 MST")
	}
	fmt.Fprintf(&b, "# インシデント報告 %s\n\n", inc.ID)
	fmt.Fprintf(&b, "| 項目 | 内容 |\n|---|---|\n")
	fmt.Fprintf(&b, "| 題名 | %s |\n", mdCell(inc.Title))
	fmt.Fprintf(&b, "| 状態 | %s |\n", map[string]string{api.IncidentOpen: "対応中", api.IncidentClosed: "終了"}[inc.Status])
	fmt.Fprintf(&b, "| 対象 | %s |\n", mdCell(strings.Join(inc.Devices, "、")))
	fmt.Fprintf(&b, "| 開いた時刻 | %s（%s） |\n", t(inc.Opened), mdCell(actorName(inc.OpenedBy)))
	fmt.Fprintf(&b, "| 事態を知った時刻 | %s |\n", t(inc.KnownAt))
	fmt.Fprintf(&b, "| 閉じた時刻 | %s |\n", t(inc.Closed))
	pd := "なし"
	if inc.PersonalData {
		pd = "おそれあり"
		if inc.Malicious {
			pd += "（不正の目的によるおそれあり）"
		}
	}
	fmt.Fprintf(&b, "| 個人情報の漏えい等 | %s |\n\n", pd)

	if len(inc.Deadlines) > 0 {
		b.WriteString("## 個人情報保護委員会への報告\n\n")
		b.WriteString("| 報告 | 期限の目安 | 報告した時刻 |\n|---|---|---|\n")
		for _, d := range inc.Deadlines {
			due := t(d.Due)
			if !d.From.IsZero() {
				due = t(d.From) + " 〜 " + due
			}
			fmt.Fprintf(&b, "| %s | %s | %s |\n", d.Name, due, t(d.Done))
		}
		b.WriteString("\n期限は個人情報保護委員会のガイドライン（通則編）に基づく目安です。報告の要否と期限は、最新のガイドラインで確かめてください。本人への通知も速やかに行います。\n\n")
	}

	b.WriteString("## 対応の手順\n\n| # | 手順 | 状態 | 記録した人 | 時刻 | 記録 |\n|---|---|---|---|---|---|\n")
	for i, s := range inc.Steps {
		by, at := "-", "-"
		if s.Status != api.StepTodo {
			by, at = actorName(s.By), t(s.At)
		}
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | %s |\n", i+1, mdCell(s.Title), stepLabels[s.Status], mdCell(by), at, mdCell(cmp.Or(s.Note, "-")))
	}
	if len(inc.Notes) > 0 {
		b.WriteString("\n## 記録\n\n")
		for _, n := range inc.Notes {
			fmt.Fprintf(&b, "- %s %s: %s\n", t(n.At), mdCell(actorName(n.By)), mdCell(n.Text))
		}
	}
	b.WriteString("\n## 証拠\n\n")
	if len(evidence) == 0 {
		b.WriteString("保全した証拠はありません。\n")
	} else {
		b.WriteString("| 対象 | ID | 集めた時刻 | きっかけ | プロセス | 接続 | SHA-256 |\n|---|---|---|---|---|---|---|\n")
		for _, e := range evidence {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %d | %d | `%s` |\n", e.Device, e.ID, t(e.Time), evidenceReasons[e.Reason], e.Processes, e.Connections, e.SHA256)
		}
		b.WriteString("\n証拠のハッシュは CONTROLLER の監査ログ（evidence.receive）にも記録されています。\n")
	}
	b.WriteString("\n## 時系列\n\n")
	if len(tl) == 0 {
		b.WriteString("時系列に並べるものはありません。\n")
	} else {
		b.WriteString("| 時刻 | 種類 | 対象 | 内容 |\n|---|---|---|---|\n")
		for _, e := range tl {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", t(e.Time), mdCell(sourceLabels[e.Source]+" "+e.Kind), mdCell(dash(e.Device)), mdCell(e.Summary))
		}
	}
	fmt.Fprintf(&b, "\n---\nsusanoo %s が %s に作成。\n", version.Version, t(now))
	return b.String()
}
