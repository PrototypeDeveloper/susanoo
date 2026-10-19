package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"text/tabwriter"

	"susanoo/internal/api"
	"susanoo/internal/fsutil"
	"susanoo/internal/policy"
)

// 学習した名前から許可リストの案を作り、原則拒否のポリシーの案を書き出す（G2）。

func ctlLearnedSuggest(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl learned suggest", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	group := flags.String("group", policy.DefaultGroup, "グループ")
	minCount := flags.Int("min", 0, "案に入れる名前の、問い合わせの回数の下限（省略すると 2）")
	out := flags.String("out", "", "原則拒否にしたポリシーの案を書き出すファイル（省略すると画面に表示する）")
	asJSON := flags.Bool("json", false, "許可リストの案だけを JSON で表示する（ポリシーは作らない）")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	q := url.Values{"group": {*group}}
	if *minCount > 0 {
		q.Set("min", strconv.Itoa(*minCount))
	}
	var sug api.AllowSuggestion
	if err := c.do(http.MethodGet, api.PathLearnedSuggest+"?"+q.Encode(), nil, &sug); err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(sug)
		return exitOK
	}
	raw, err := fetchVersion(&c, 0)
	if err != nil {
		return fail(stderr, err)
	}
	next, added, err := suggestedPolicy(raw, sug)
	if err != nil {
		return fail(stderr, err)
	}
	summary := stdout
	if *out == "" {
		stdout.Write(next)
		summary = stderr
	} else if err := fsutil.WriteFileAtomic(*out, next, 0o600); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(summary, "グループ %s を原則拒否（egress.default: deny）にし、学習した名前から許可リストに %d 件を加えた案を作りました（回数 %d 回以上）。\n",
		sug.Group, added, sug.MinCount)
	if len(sug.Allow) > 0 {
		tw := tabwriter.NewWriter(summary, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  許可する名前\t回数\tまとめた名前")
		for _, a := range sug.Allow {
			fmt.Fprintf(tw, "  %s\t%d\t%d\n", a.Domain, a.Count, a.Names)
		}
		tw.Flush()
	}
	for _, x := range sug.Excluded {
		fmt.Fprintf(summary, "  入れなかった名前: %s（%s）\n", x.Domain, x.Reason)
	}
	if *out != "" {
		fmt.Fprintf(summary, "内容を確かめてから、susanoo ctl policy push %s -canary <端末> で一部の端末から適用し、問題がなければ susanoo ctl policy promote で全体に広げてください。\n", *out)
	}
	return exitOK
}

// suggestedPolicy は今のポリシー current の、グループ s.Group を原則拒否にし、許可リストの案を加えたポリシーを返す。
// 版数と発行の時刻は、配布するとき（ctl policy push）に付け直す。加えた件数も返す。
func suggestedPolicy(current []byte, s api.AllowSuggestion) ([]byte, int, error) {
	p, err := policy.Parse(current)
	if err != nil {
		return nil, 0, err
	}
	var g *policy.Group
	for i := range p.Groups {
		if p.Groups[i].Name == s.Group {
			g = &p.Groups[i]
		}
	}
	if g == nil {
		return nil, 0, fmt.Errorf("今のポリシーにグループ %q はありません", s.Group)
	}
	have := map[string]bool{}
	for _, d := range g.Egress.Allow {
		if d.Domain != "" {
			have[d.Domain] = true
		}
	}
	added := 0
	for _, a := range s.Allow {
		if !have[a.Domain] {
			g.Egress.Allow = append(g.Egress.Allow, policy.Destination{Domain: a.Domain})
			have[a.Domain] = true
			added++
		}
	}
	g.Egress.Default, g.Egress.LearnPeriod = policy.EgressDeny, 0
	p.Name = fmt.Sprintf("%s（%s を原則拒否に）", p.Name, s.Group)
	if err := p.Validate(); err != nil {
		return nil, 0, fmt.Errorf("案のポリシーが検証に通りません: %w", err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, 0, err
	}
	return append(data, '\n'), added, nil
}
