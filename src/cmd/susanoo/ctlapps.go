package main

import (
	"cmp"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
)

// プロセス単位の通信の制御（C7）の操作。

const ctlAppsUsage = `使い方: susanoo ctl apps learned [オプション]

  learned  プロセス単位の通信の制御で拒否した（試験運用なら拒否に当たった）接続を、プログラムと宛先ごとにまとめて表示する
           （例: susanoo ctl apps learned -since 24h）。試験運用（monitor）で記録し、平常のものを許可のルールにしてから enforce にする

ルールはポリシーのグループの apps に書き、susanoo ctl policy push で配布する。
`

// appSummary はプログラムと宛先ごとのまとめ。
type appSummary struct {
	Exe     string    `json:"exe"`
	Agent   string    `json:"agent,omitempty"`
	Dst     string    `json:"dst"`
	Proto   string    `json:"proto"`
	Action  string    `json:"action"` // deny、would_deny
	Rule    string    `json:"rule"`
	Count   int       `json:"count"`
	Devices []string  `json:"devices"`
	Last    time.Time `json:"last"`
}

func ctlApps(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "learned" {
		fmt.Fprint(stderr, ctlAppsUsage)
		return exitUsage
	}
	flags := flag.NewFlagSet("ctl apps learned", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	since := flags.String("since", "24h", "この時刻以降（「24h」のような今からの長さ、「2026-10-18」、RFC 3339 の時刻）")
	device := flags.String("device", "", "端末 ID")
	asJSON := flags.Bool("json", false, "JSON で表示する")
	if err := flags.Parse(args[1:]); err != nil {
		return exitUsage
	}
	from, err := parseWhen(*since, time.Now())
	if err != nil {
		return fail(stderr, fmt.Errorf("-since: %w", err))
	}
	q := api.EventQuery{Class: "finding", Text: event.FindingTypeAppControl, Device: *device, Since: from, Limit: api.MaxEventQuery}
	var raw []json.RawMessage
	if err := c.doLimit(http.MethodGet, api.PathEvents+"?"+q.Values().Encode(), nil, &raw, api.MaxEvidenceBytes, time.Minute); err != nil {
		return fail(stderr, err)
	}
	list := summarizeApps(raw)
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(list)
		return exitOK
	}
	if len(list) == 0 {
		fmt.Fprintln(stdout, "拒否した、または拒否に当たった接続はありません。")
		return exitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "回数\t扱い\tプログラム\tエージェント\t宛先\tルール\t端末\t最後")
	for _, s := range list {
		action := map[string]string{"deny": "拒否", "would_deny": "拒否に当たる（試験運用）"}[s.Action]
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s/%s\t%s\t%s\t%s\n", s.Count, action, dash(s.Exe), dash(s.Agent), s.Dst, s.Proto, s.Rule,
			strings.Join(s.Devices, ","), s.Last.Local().Format(timeFormat))
	}
	tw.Flush()
	if len(raw) == api.MaxEventQuery {
		fmt.Fprintf(stdout, "\n検知結果が %d 件を超えたため、新しいものだけをまとめました（-since で範囲を狭めてください）。\n", api.MaxEventQuery)
	}
	fmt.Fprintln(stdout, "\n平常の接続は、ポリシーのグループの apps.rules に許可のルール（exe か names と dst、action: allow）として書いてください。")
	return exitOK
}

// summarizeApps はプロセス単位の通信の制御の検知結果を、プログラム、エージェント、宛先、扱いごとにまとめる（回数の多い順）。
func summarizeApps(raw []json.RawMessage) []appSummary {
	byKey := map[string]*appSummary{}
	for _, r := range raw {
		var e event.Event
		if json.Unmarshal(r, &e) != nil || !e.FindingInfo.HasType(event.FindingTypeAppControl) || e.DstEndpoint == nil {
			continue
		}
		ac, _ := e.Unmapped["app_control"].(map[string]any)
		agent, _ := e.Unmapped["agent"].(map[string]any)
		s := appSummary{Dst: net.JoinHostPort(e.DstEndpoint.IP, strconv.Itoa(e.DstEndpoint.Port)), Last: time.UnixMilli(e.Time)}
		s.Exe, _ = ac["exe"].(string)
		s.Action, _ = ac["action"].(string)
		s.Rule, _ = ac["rule"].(string)
		s.Agent, _ = agent["name"].(string)
		if e.Connection != nil {
			s.Proto = e.Connection.ProtocolName
		}
		key := strings.Join([]string{s.Exe, s.Agent, s.Dst, s.Proto, s.Action, s.Rule}, "\x00")
		x := byKey[key]
		if x == nil {
			x = &s
			byKey[key] = x
		}
		x.Count++
		if e.Device != nil && e.Device.UID != "" && !slices.Contains(x.Devices, e.Device.UID) {
			x.Devices = append(x.Devices, e.Device.UID)
		}
		if s.Last.After(x.Last) {
			x.Last = s.Last
		}
	}
	out := make([]appSummary, 0, len(byKey))
	for _, x := range byKey {
		slices.Sort(x.Devices)
		out = append(out, *x)
	}
	slices.SortFunc(out, func(a, b appSummary) int {
		return cmp.Or(b.Count-a.Count, strings.Compare(a.Exe, b.Exe), strings.Compare(a.Dst, b.Dst))
	})
	return out
}
