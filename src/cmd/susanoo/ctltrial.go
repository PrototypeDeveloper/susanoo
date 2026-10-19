package main

import (
	"encoding/json"
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
)

// 学習モードの試行の評価（2o）。フェーズ2のゲート「学習モードで誤検知が許容範囲に収まる」の判断に使う。

func ctlTrial(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl trial", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	since := flags.String("since", "14d", "期間の初め（「336h」のような今からの長さ、「14d」のような日数、「2026-10-05」、RFC 3339 の時刻）")
	until := flags.String("until", "", "期間の終わり（書き方は -since と同じ。省略すると今）")
	maxPerWeek := flags.Float64("max-per-week", 0.5, "基準：端末か機器ごとに、1 週間に隔離してよい回数（0.5 なら 2 週間に 1 回）")
	asJSON := flags.Bool("json", false, "JSON で表示する")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	now := time.Now()
	q := url.Values{"max_per_week": {strconv.FormatFloat(*maxPerWeek, 'f', -1, 64)}}
	for name, s := range map[string]string{"since": *since, "until": *until} {
		if s == "" {
			continue
		}
		t, err := parseTrialWhen(s, now)
		if err != nil {
			return fail(stderr, fmt.Errorf("-%s: %w", name, err))
		}
		q.Set(name, t.UTC().Format(time.RFC3339))
	}
	var rep api.TrialReport
	if err := c.doLimit(http.MethodGet, api.PathTrial+"?"+q.Encode(), nil, &rep, api.MaxBodyBytes, 5*time.Minute); err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(rep)
		return exitOK
	}
	printTrial(stdout, rep)
	return exitOK
}

// parseTrialWhen は parseWhen に加えて、「14d」のような日数を読む。
func parseTrialWhen(s string, now time.Time) (time.Time, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		if n, err := strconv.Atoi(days); err == nil && n > 0 {
			return now.AddDate(0, 0, -n), nil
		}
	}
	return parseWhen(s, now)
}

func printTrial(w io.Writer, rep api.TrialReport) {
	day := "2006-01-02 15:04"
	fmt.Fprintf(w, "学習モードの試行の評価（%s 〜 %s、%.1f 週）\n", rep.Since.Local().Format(day), rep.Until.Local().Format(day), rep.Gate.Weeks)
	fmt.Fprintf(w, "評価し直したイベント %d 件、検知ルール 版 %d「%s」、対応の方式 %s（期間中に隔離しなかった判断 %d 回）\n",
		rep.Events, rep.Rules.Version, rep.Rules.Name, rep.Response, rep.Suppressed)
	if !rep.Oldest.IsZero() && rep.Oldest.Sub(rep.Since) > 24*time.Hour {
		fmt.Fprintf(w, "注意：期間の初めのイベントが残っていません（最も古いもの %s）。保存の上限で消えた可能性があります。\n", rep.Oldest.Local().Format(day))
	}
	g := rep.Gate
	verdict := func(pass bool, over []string) string {
		if pass {
			return "合格"
		}
		return "不合格（基準を超えた端末と機器: " + strings.Join(over, "、") + "）"
	}
	fmt.Fprintf(w, "\n基準：端末か機器ごとに、隔離していた回数が 1 週間に %g 回まで（この期間で %g 回まで）\n", g.MaxPerWeek, g.Allowed)
	fmt.Fprintf(w, "  今のルールと例外: 隔離していた %d 回 … %s\n", len(rep.Isolations), verdict(g.Pass, g.Over))
	fmt.Fprintf(w, "  試験運用のルールもすべて加点にしたら: 隔離していた %d 回 … %s\n", len(rep.IfEnforced), verdict(g.IfEnforcedPass, g.IfEnforcedOver))

	if len(rep.ByTarget) > 0 {
		fmt.Fprintln(w, "\n端末と機器:")
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  対象\tグループ\t隔離\t加点にしたら\t当たった回数\t主なルール")
		for _, t := range rep.ByTarget {
			var top []string
			for _, r := range t.Rules[:min(len(t.Rules), 3)] {
				top = append(top, fmt.Sprintf("%s（%d）", r.Target, r.Count))
			}
			fmt.Fprintf(tw, "  %s\t%s\t%d\t%d\t%d\t%s\n", t.Target, t.Group, t.Isolations, t.IfEnforced, t.Hits, dash(strings.Join(top, "、")))
		}
		tw.Flush()
	}
	if len(rep.ByRule) > 0 {
		fmt.Fprintln(w, "\nルール:")
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  ID\t名前\t扱い\t点\t当たった\t例外で除いた\t対象の数\t多い対象")
		for _, r := range rep.ByRule {
			var top []string
			for _, t := range r.Top {
				top = append(top, fmt.Sprintf("%s（%d）", t.Target, t.Count))
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\n", r.ID, r.Name, r.Mode, r.Score, r.Hits, r.Excepted, r.Targets, dash(strings.Join(top, "、")))
		}
		tw.Flush()
	}
	if len(rep.Isolations) > 0 {
		fmt.Fprintln(w, "\n今のルールで隔離していた時刻:")
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, iso := range rep.Isolations {
			fmt.Fprintf(tw, "  %s\t%s\t危険度 %d / %d\t%s\n", iso.Time.Local().Format(timeFormat), iso.Target, iso.Score, iso.Threshold, strings.Join(iso.Rules, ","))
		}
		tw.Flush()
	}
	fmt.Fprintln(w, "\n誤検知と判断した当たりは、検知ルールの例外（exceptions）にして配布し、もう一度この評価で確かめてください。")
}
