package main

import (
	"cmp"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/keys"
	"susanoo/internal/rules"
	"susanoo/internal/sign"
)

const ctlRulesUsage = `使い方: susanoo ctl rules <操作> [オプション]

操作:
  push      検知ルールのファイルに新しい版数を付け、ポリシーの署名の鍵で署名して配布する（例: susanoo ctl rules push rules.json）
  list      配布した版の一覧を表示する
  show      版の中身を表示する（例: susanoo ctl rules show 3。省略すると今の版）
  rollback  過去の版の中身に新しい版数を付けて、署名し直して配布する（例: susanoo ctl rules rollback 2）
  stats     ルールごとの設定と、当てはまった回数（危険度に加えた、試験運用、例外）を表示する
`

func ctlRules(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, ctlRulesUsage)
		return exitUsage
	}
	switch args[0] {
	case "push":
		return ctlRulesPush(args[1:], stdout, stderr)
	case "list":
		return ctlRulesList(args[1:], stdout, stderr)
	case "show":
		return ctlRulesShow(args[1:], stdout, stderr)
	case "rollback":
		return ctlRulesRollback(args[1:], stdout, stderr)
	case "stats":
		return ctlRulesStats(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, ctlRulesUsage)
		return exitOK
	}
	fmt.Fprintf(stderr, "susanoo: 不明な操作です: ctl rules %s\n\n%s", args[0], ctlRulesUsage)
	return exitUsage
}

// pushRules は s に新しい版数を付け、ポリシーの署名の鍵で署名して配布する。
func pushRules(c *ctlFlags, s *rules.Set) (api.RulesInfo, error) {
	var info api.RulesInfo
	if err := c.do(http.MethodGet, api.PathRules, nil, &info); err != nil {
		return info, err
	}
	priv, err := keys.LoadPrivate(filepath.Join(c.dir, filePolicyKey))
	if err != nil {
		return info, fmt.Errorf("%w（ctl policy keygen で作ってください）", err)
	}
	signer, err := sign.NewSigner(priv)
	if err != nil {
		return info, err
	}
	next := info.Current.Version
	for _, v := range info.Versions {
		next = max(next, v.Version)
	}
	s.Version, s.IssuedAt = next+1, time.Now().UTC().Truncate(time.Second)
	if err := s.Validate(); err != nil {
		return info, err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return info, err
	}
	err = c.do(http.MethodPost, api.PathRules, api.RulesPush{Envelope: signer.Sign(sign.PurposeRules, data)}, &info)
	return info, err
}

// parseRulesFile は検知ルールのファイルを読む。版数と発行時刻は配布のときに付けるので、なくてもよい。
func parseRulesFile(data []byte) (*rules.Set, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	if _, ok := probe["version"]; !ok {
		probe["version"] = json.RawMessage("1")
	}
	if _, ok := probe["issued_at"]; !ok {
		probe["issued_at"] = json.RawMessage(`"2000-01-01T00:00:00Z"`)
	}
	filled, err := json.Marshal(probe)
	if err != nil {
		return nil, err
	}
	return rules.Parse(filled)
}

func ctlRulesPush(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl rules push", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	file, args := splitArg(args)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	file = cmp.Or(file, flags.Arg(0))
	if file == "" {
		return fail(stderr, errors.New("検知ルールのファイルを指定してください"))
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return fail(stderr, err)
	}
	s, err := parseRulesFile(data)
	if err != nil {
		return fail(stderr, err)
	}
	info, err := pushRules(&c, s)
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "検知ルールの版 %d を適用しました（ルール %d、例外 %d）。当てはまった回数は ctl rules stats で確かめてください。\n",
		info.Current.Version, len(s.Rules), info.Exceptions)
	return exitOK
}

func ctlRulesList(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl rules list", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	asJSON := flags.Bool("json", false, "JSON で表示する")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	var info api.RulesInfo
	if err := c.do(http.MethodGet, api.PathRules, nil, &info); err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(info.Versions)
		return exitOK
	}
	if len(info.Versions) == 0 {
		fmt.Fprintln(stdout, "配布した版はありません（既定のルールを使っています）。")
		return exitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "版数\t名前\t発行\t受付\t状態")
	for _, r := range info.Versions {
		state := "-"
		if r.Version == info.Current.Version {
			state = "適用中"
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", r.Version, r.Name, r.IssuedAt.Local().Format(timeFormat), r.AppliedAt.Local().Format(timeFormat), state)
	}
	tw.Flush()
	return exitOK
}

// fetchRules は版 v の中身を取り出す。v が 0 なら今の版。
func fetchRules(c *ctlFlags, v int) (json.RawMessage, error) {
	if v == 0 {
		var info api.RulesInfo
		if err := c.do(http.MethodGet, api.PathRules, nil, &info); err != nil {
			return nil, err
		}
		if info.Current.Version == 0 {
			return nil, errors.New("配布した版はありません（既定のルールを使っています。ctl rules stats で一覧できます）")
		}
		v = info.Current.Version
	}
	var raw json.RawMessage
	err := c.do(http.MethodGet, api.PathRules+"/versions/"+strconv.Itoa(v), nil, &raw)
	return raw, err
}

func ctlRulesShow(args []string, stdout, stderr io.Writer) int {
	v, args, ok := versionArg(args, "表示", false, stderr)
	if !ok {
		return exitUsage
	}
	flags := flag.NewFlagSet("ctl rules show", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	raw, err := fetchRules(&c, v)
	if err != nil {
		return fail(stderr, err)
	}
	var out any
	json.Unmarshal(raw, &out)
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
	return exitOK
}

func ctlRulesRollback(args []string, stdout, stderr io.Writer) int {
	v, args, ok := versionArg(args, "戻", true, stderr)
	if !ok {
		return exitUsage
	}
	flags := flag.NewFlagSet("ctl rules rollback", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	raw, err := fetchRules(&c, v)
	if err != nil {
		return fail(stderr, err)
	}
	s, err := rules.Parse(raw)
	if err != nil {
		return fail(stderr, err)
	}
	info, err := pushRules(&c, s)
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "検知ルールの版 %d の中身を、版 %d として適用しました。\n", v, info.Current.Version)
	return exitOK
}

var modeLabels = map[string]string{"enforce": "加点", "monitor": "試験運用", "off": "停止"}

func ctlRulesStats(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl rules stats", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	asJSON := flags.Bool("json", false, "JSON で表示する")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	var info api.RulesInfo
	if err := c.do(http.MethodGet, api.PathRules, nil, &info); err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(info)
		return exitOK
	}
	fmt.Fprintf(stdout, "検知ルールの版 %d「%s」（例外 %d、危険度の半減期 %s）\n", info.Current.Version, info.Current.Name, info.Exceptions, info.HalfLife)
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\t名前\t扱い\t点\t対象\tグループ\t加点\t試験運用\t例外\t最後")
	for _, r := range info.Rules {
		name := r.Name
		if r.Default {
			name += "（既定）"
		}
		last := "-"
		if !r.Last.IsZero() {
			last = r.Last.Local().Format(timeFormat)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%d\t%d\t%d\t%s\n", r.ID, name, cmp.Or(modeLabels[r.Mode], r.Mode), r.Score, r.Target,
			dash(strings.Join(r.Groups, ",")), r.Hits, r.Monitored, r.Excepted, last)
	}
	tw.Flush()
	return exitOK
}
