package main

import (
	"cmp"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
)

// 全体の状態の表示とイベントの検索（M8）。

var classLabels = map[event.ClassUID]string{
	event.ClassFileSystemActivity: "ファイル",
	event.ClassProcessActivity:    "プロセス",
	event.ClassDetectionFinding:   "検知",
	event.ClassNetworkActivity:    "通信",
	event.ClassDNSActivity:        "DNS",
	event.ClassDHCPActivity:       "DHCP",
}

var severityLabels = map[event.Severity]string{
	event.SeverityInformational: "情報",
	event.SeverityLow:           "低",
	event.SeverityMedium:        "中",
	event.SeverityHigh:          "高",
	event.SeverityCritical:      "重大",
	event.SeverityFatal:         "致命的",
}

var fileActivities = map[int]string{
	event.FileCreate: "作成", event.FileRead: "読み込み", event.FileUpdate: "更新", event.FileDelete: "削除",
	event.FileRename: "名前の変更", event.FileSetAttributes: "属性の変更", event.FileOpen: "開く",
}

const timeFormat = "01-02 15:04:05"

func ctlStatus(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	asJSON := flags.Bool("json", false, "JSON で表示する")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	var st api.Status
	if err := c.do(http.MethodGet, api.PathStatus, nil, &st); err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(st)
		return exitOK
	}
	fmt.Fprintf(stdout, "susanoo %s（CONTROLLER の起動 %s、証明書の期限 %s）\n", st.Version, st.StartedAt.Local().Format(timeFormat), st.CertExpiry.Local().Format("2006-01-02"))
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "ポリシー\t版 %d「%s」（対応 %s）\n", st.Policy.Version, st.Policy.Name, st.Response)
	if p := st.Canary; p != nil {
		fmt.Fprintf(tw, "先行適用\t版 %d「%s」（端末 %s、グループ %s）\n", p.Version, p.Name, dash(strings.Join(p.Devices, ",")), dash(strings.Join(p.Groups, ",")))
	}
	d := st.Devices
	fmt.Fprintf(tw, "端末\t%d 台（接続中 %d、隔離中 %d、承認待ち %d、不在 %d、失効 %d）\n", d.Total, d.Online, d.Isolated, d.Pending, d.Away, d.Revoked)
	h := st.Hosts
	fmt.Fprintf(tw, "LAN の機器\t%d 台（CLIENT のない機器 %d、うち隔離中 %d、承認待ち %d）\n", h.Total, h.Unregistered, h.Isolated, h.Pending)
	fmt.Fprintf(tw, "検知ルール\t版 %d「%s」\n", st.Rules.Version, st.Rules.Name)
	if st.Intel.Version > 0 {
		var names []string
		for _, l := range st.Intel.Lists {
			names = append(names, fmt.Sprintf("%s（%s、%d 件）", l.Name, l.Action, l.Domains+l.CIDRs))
		}
		fmt.Fprintf(tw, "脅威情報\t版 %d %s\n", st.Intel.Version, strings.Join(names, "、"))
	} else {
		fmt.Fprintf(tw, "脅威情報\tなし\n")
	}
	if n := st.Incidents; n.Open > 0 {
		s := fmt.Sprintf("対応中 %d", n.Open)
		if n.Next != nil {
			s += fmt.Sprintf("（最も近い報告の期限の目安: %s の%s %s、%s）", n.Next.Incident, n.Next.Name, n.Next.Due.Local().Format("01-02 15:04"), remaining(n.Next.Due, time.Now()))
		}
		fmt.Fprintf(tw, "インシデント\t%s\n", s)
	} else {
		fmt.Fprintf(tw, "インシデント\tなし\n")
	}
	if len(st.Notify) > 0 {
		var parts []string
		for _, n := range st.Notify {
			s := fmt.Sprintf("%s（%s、送信 %d、失敗 %d", n.Name, n.Type, n.Sent, n.Failed)
			if n.Suppressed > 0 {
				s += fmt.Sprintf("、省略 %d", n.Suppressed)
			}
			if n.LastError != "" && n.LastFailed.After(n.LastSent) {
				s += "、最後の失敗: " + oneLine(n.LastError)
			}
			parts = append(parts, s+"）")
		}
		fmt.Fprintf(tw, "通知\t%s\n", strings.Join(parts, "、"))
	} else {
		fmt.Fprintf(tw, "通知\tなし\n")
	}
	tw.Flush()
	if len(st.Risky) > 0 {
		fmt.Fprintln(stdout, "\n危険度の高い端末と機器:")
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		for _, r := range st.Risky {
			fmt.Fprintf(tw, "  %s\t%d / %d\t%s\n", r.Target, r.Score, r.Threshold, strings.Join(r.Rules, ","))
		}
		tw.Flush()
	}
	if len(st.ExpiringCerts) > 0 {
		fmt.Fprintln(stdout, "\n証明書の期限が近い端末（更新が止まっている恐れがあります）:")
		for _, d := range st.ExpiringCerts {
			fmt.Fprintf(stdout, "  %s\t%s\n", d.ID, d.CertExpiry.Local().Format("2006-01-02 15:04"))
		}
	}
	if len(st.RecentFindings) > 0 {
		fmt.Fprintln(stdout, "\n最近の検知:")
		printEvents(stdout, st.RecentFindings)
	}
	return exitOK
}

func ctlEvents(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl events", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	var q api.EventQuery
	flags.StringVar(&q.Device, "device", "", "端末 ID、アドレス、MAC アドレス、ホスト名")
	flags.StringVar(&q.Class, "class", "", "種類（file、process、finding、network、dns、dhcp）")
	flags.StringVar(&q.Severity, "severity", "", "この重大度以上（info、low、medium、high、critical）")
	since := flags.String("since", "", "この時刻以降（「1h」のような今からの長さ、「2026-10-18」、RFC 3339 の時刻）")
	until := flags.String("until", "", "この時刻以前（書き方は -since と同じ）")
	flags.StringVar(&q.Text, "q", "", "含む文字列")
	flags.IntVar(&q.Limit, "limit", 50, fmt.Sprintf("新しいものからこの件数まで（%d まで）", api.MaxEventQuery))
	asJSON := flags.Bool("json", false, "OCSF の JSON で表示する")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	now := time.Now()
	var err error
	if q.Since, err = parseWhen(*since, now); err != nil {
		return fail(stderr, fmt.Errorf("-since: %w", err))
	}
	if q.Until, err = parseWhen(*until, now); err != nil {
		return fail(stderr, fmt.Errorf("-until: %w", err))
	}
	var raw []json.RawMessage
	if err := c.do(http.MethodGet, api.PathEvents+"?"+q.Values().Encode(), nil, &raw); err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		for _, r := range raw {
			fmt.Fprintln(stdout, string(r))
		}
		return exitOK
	}
	events := make([]event.Event, 0, len(raw))
	for _, r := range raw {
		var e event.Event
		if json.Unmarshal(r, &e) == nil {
			events = append(events, e)
		}
	}
	if len(events) == 0 {
		fmt.Fprintln(stdout, "条件に合うイベントはありません。")
		return exitOK
	}
	printEvents(stdout, events)
	return exitOK
}

// parseWhen は「1h」のような今からの長さ、「2026-10-18」、RFC 3339 の時刻を読む。空なら条件にしない。
func parseWhen(s string, now time.Time) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return now.Add(-d), nil
	}
	if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, errors.New("「1h」のような長さ、「2026-10-18」、RFC 3339 の時刻で書いてください")
}

func printEvents(w io.Writer, events []event.Event) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "時刻\t種類\t端末\t重大度\t内容")
	for _, e := range events {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", time.UnixMilli(e.Time).Local().Format(timeFormat),
			cmp.Or(classLabels[e.ClassUID], fmt.Sprint(e.ClassUID)), dash(eventDevice(e)),
			cmp.Or(severityLabels[e.SeverityID], "-"), oneLine(eventSummary(e)))
	}
	tw.Flush()
}

// eventDevice はイベントの端末（端末 ID、なければホスト名かアドレス）を返す。
func eventDevice(e event.Event) string {
	if d := e.Device; d != nil {
		if s := cmp.Or(d.UID, d.Hostname, d.IP, d.MAC); s != "" {
			return s
		}
	}
	if s := e.SrcEndpoint; s != nil {
		return cmp.Or(s.UID, s.IP)
	}
	return ""
}

// eventSummary はイベントの要点を 1 行で返す。
func eventSummary(e event.Event) string {
	switch e.ClassUID {
	case event.ClassDetectionFinding:
		if f := e.FindingInfo; f != nil {
			return f.Title + "：" + cmp.Or(e.Message, f.Desc)
		}
	case event.ClassProcessActivity:
		if p := e.Process; p != nil {
			act := map[int]string{event.ProcessLaunch: "起動", event.ProcessTerminate: "終了"}[e.ActivityID]
			target := p.CmdLine
			if target == "" && p.File != nil {
				target = p.File.Path
			}
			return fmt.Sprintf("%s %s（PID %d）", act, cmp.Or(target, p.Name), p.PID)
		}
	case event.ClassFileSystemActivity:
		if f := e.File; f != nil {
			s := cmp.Or(fileActivities[e.ActivityID], "操作") + " " + cmp.Or(f.Path, f.Name)
			if e.Actor != nil && e.Actor.Process != nil && e.Actor.Process.Name != "" {
				s += fmt.Sprintf("（%s、PID %d）", e.Actor.Process.Name, e.Actor.Process.PID)
			}
			return s
		}
	case event.ClassNetworkActivity:
		if dst := e.DstEndpoint; dst != nil {
			s := net.JoinHostPort(dst.IP, strconv.Itoa(dst.Port))
			if dst.Hostname != "" {
				s = dst.Hostname + "（" + s + "）"
			}
			if e.ActivityID == event.NetworkClose {
				s = "終わり " + s
				if t := e.Traffic; t != nil {
					s += fmt.Sprintf(" 送信 %d バイト、受信 %d バイト", t.BytesOut, t.BytesIn)
				}
			}
			if e.Actor != nil && e.Actor.Process != nil && e.Actor.Process.Name != "" {
				s += fmt.Sprintf("（%s、PID %d）", e.Actor.Process.Name, e.Actor.Process.PID)
			}
			return s
		}
	case event.ClassDNSActivity:
		if q := e.Query; q != nil {
			s := q.Hostname + " " + q.Type
			var answers []string
			for _, a := range e.Answers {
				answers = append(answers, a.Rdata)
			}
			if len(answers) > 0 {
				s += " → " + strings.Join(answers, ",")
			}
			if e.Message != "" {
				s += "（" + e.Message + "）"
			}
			return s
		}
	}
	return e.Message
}

// oneLine は改行とタブを空白にする（表が崩れないように）。
func oneLine(s string) string {
	return strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(s)
}
