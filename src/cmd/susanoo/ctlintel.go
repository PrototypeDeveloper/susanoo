package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/intel"
	"susanoo/internal/keys"
	"susanoo/internal/sign"
)

const ctlIntelUsage = `使い方: susanoo ctl intel <操作> [オプション]

操作:
  push    一覧のファイルを取り込み、名前を付けた一覧として署名して配布する。同じ名前の一覧は置き換える
          （例: susanoo ctl intel push -name phishing -action block phishing.txt）
          ファイルは 1 行に 1 つ（ドメイン、アドレス、アドレスの範囲、hosts の形式、URL、||ドメイン^）
  remove  一覧を消して配布する（例: susanoo ctl intel remove -name phishing）
  list    配布した一覧（扱い、件数、取り込んだ時刻、入手元）を表示する
  check   名前かアドレスが、どの一覧に当てはまるかを表示する（例: susanoo ctl intel check login.evil.example）

一覧の扱いは、block（GW の DNS で引かせず、アドレスへの通信を落とし、検知結果を残す）か、
alert（検知結果を残すだけ）。省略すると alert。一覧の取得（外部への接続）は行わないので、入手したファイルを取り込む。
`

// intelTimeout は脅威情報の配布を待つ時間（大きな一覧を GW の nftables に入れる時間を見込む）。
const intelTimeout = 3 * time.Minute

func ctlIntel(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, ctlIntelUsage)
		return exitUsage
	}
	switch args[0] {
	case "push":
		return ctlIntelPush(args[1:], stdout, stderr)
	case "remove":
		return ctlIntelRemove(args[1:], stdout, stderr)
	case "list":
		return ctlIntelList(args[1:], stdout, stderr)
	case "check":
		return ctlIntelCheck(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, ctlIntelUsage)
		return exitOK
	}
	fmt.Fprintf(stderr, "susanoo: 不明な操作です: ctl intel %s\n\n%s", args[0], ctlIntelUsage)
	return exitUsage
}

// currentIntel は CONTROLLER が使っている脅威情報を取り出す。まだなければ空の一式を返す。
func currentIntel(c *ctlFlags) (*intel.Set, error) {
	var info api.IntelInfo
	if err := c.do(http.MethodGet, api.PathIntel, nil, &info); err != nil {
		return nil, err
	}
	if info.Version == 0 {
		return &intel.Set{}, nil
	}
	var s intel.Set
	if err := c.doLimit(http.MethodGet, api.PathIntel+"/payload", nil, &s, api.MaxIntelBytes, intelTimeout); err != nil {
		return nil, err
	}
	return &s, nil
}

// pushIntel は s に新しい版数を付け、ポリシーの署名の鍵で署名して配布する。
func pushIntel(c *ctlFlags, s *intel.Set) (api.IntelInfo, error) {
	var info api.IntelInfo
	priv, err := keys.LoadPrivate(filepath.Join(c.dir, filePolicyKey))
	if err != nil {
		return info, fmt.Errorf("%w（ctl policy keygen で作ってください）", err)
	}
	signer, err := sign.NewSigner(priv)
	if err != nil {
		return info, err
	}
	s.Version++
	s.IssuedAt = time.Now().UTC().Truncate(time.Second)
	if s.Lists == nil {
		s.Lists = []intel.List{}
	}
	if err := s.Validate(); err != nil {
		return info, err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return info, err
	}
	req := api.IntelPush{Envelope: signer.Sign(sign.PurposeIntel, data)}
	if raw, _ := json.Marshal(req); len(raw) > api.MaxIntelBytes {
		return info, fmt.Errorf("脅威情報が大きすぎます（%d バイト。%d バイトまで）", len(raw), api.MaxIntelBytes)
	}
	err = c.doLimit(http.MethodPost, api.PathIntel, req, &info, api.MaxBodyBytes, intelTimeout)
	return info, err
}

func ctlIntelPush(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl intel push", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	name := flags.String("name", "", "一覧の名前（英小文字、数字、「-」）")
	action := flags.String("action", string(intel.ActionAlert), "扱い（block か alert）")
	source := flags.String("source", "", "入手元（記録のため。URL など）")
	var files []string
	for len(args) > 0 {
		if err := flags.Parse(args); err != nil {
			return exitUsage
		}
		if flags.NArg() == 0 {
			break
		}
		files = append(files, flags.Arg(0))
		args = flags.Args()[1:]
	}
	if !intel.ValidName(*name) {
		return fail(stderr, errors.New("-name に一覧の名前（英小文字、数字、「-」）を指定してください"))
	}
	if *action != string(intel.ActionBlock) && *action != string(intel.ActionAlert) {
		return fail(stderr, errors.New("-action は block か alert にしてください"))
	}
	if len(files) == 0 {
		return fail(stderr, errors.New("取り込む一覧のファイルを指定してください"))
	}
	list := intel.List{Name: *name, Action: intel.Action(*action), Source: *source, Updated: time.Now().UTC().Truncate(time.Second)}
	skipped := 0
	var domains, cidrs []string
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			return fail(stderr, err)
		}
		feed, err := intel.ParseFeed(f)
		f.Close()
		if err != nil {
			return fail(stderr, fmt.Errorf("%s: %w", file, err))
		}
		domains, cidrs = append(domains, feed.Domains...), append(cidrs, feed.CIDRs...)
		skipped += feed.Skipped
	}
	slices.Sort(domains)
	list.Domains = slices.Compact(domains)
	merged, _ := intel.ParseFeed(strings.NewReader(strings.Join(cidrs, "\n")))
	list.CIDRs = merged.CIDRs
	if len(list.Domains) == 0 && len(list.CIDRs) == 0 {
		return fail(stderr, fmt.Errorf("ファイルにドメインもアドレスもありません（読み飛ばした行 %d）", skipped))
	}
	s, err := currentIntel(&c)
	if err != nil {
		return fail(stderr, err)
	}
	if i := slices.IndexFunc(s.Lists, func(l intel.List) bool { return l.Name == list.Name }); i >= 0 {
		s.Lists[i] = list
	} else {
		s.Lists = append(s.Lists, list)
	}
	info, err := pushIntel(&c, s)
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "脅威情報の版 %d を適用しました（一覧「%s」：%s、ドメイン %d、アドレスの範囲 %d、読み飛ばした行 %d）。\n",
		info.Version, list.Name, list.Action, len(list.Domains), len(list.CIDRs), skipped)
	return exitOK
}

func ctlIntelRemove(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl intel remove", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	name := flags.String("name", "", "消す一覧の名前")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	s, err := currentIntel(&c)
	if err != nil {
		return fail(stderr, err)
	}
	i := slices.IndexFunc(s.Lists, func(l intel.List) bool { return l.Name == *name })
	if i < 0 {
		return fail(stderr, fmt.Errorf("一覧「%s」はありません", *name))
	}
	s.Lists = slices.Delete(s.Lists, i, i+1)
	info, err := pushIntel(&c, s)
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "一覧「%s」を消して、脅威情報の版 %d を適用しました。\n", *name, info.Version)
	return exitOK
}

func ctlIntelList(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl intel list", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	asJSON := flags.Bool("json", false, "JSON で表示する")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	var info api.IntelInfo
	if err := c.do(http.MethodGet, api.PathIntel, nil, &info); err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(info)
		return exitOK
	}
	if info.Version == 0 {
		fmt.Fprintln(stdout, "脅威情報はまだ配布していません。")
		return exitOK
	}
	fmt.Fprintf(stdout, "脅威情報の版 %d（発行 %s）\n", info.Version, info.IssuedAt.Local().Format(timeFormat))
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "一覧\t扱い\tドメイン\tアドレスの範囲\t取り込み\t入手元")
	for _, l := range info.Lists {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\t%s\n", l.Name, l.Action, l.Domains, l.CIDRs, l.Updated.Local().Format(timeFormat), dash(l.Source))
	}
	tw.Flush()
	return exitOK
}

func ctlIntelCheck(args []string, stdout, stderr io.Writer) int {
	q, args := splitArg(args)
	flags := flag.NewFlagSet("ctl intel check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if q = strings.TrimSpace(q); q == "" {
		return fail(stderr, errors.New("照合する名前かアドレスを指定してください"))
	}
	var ms []api.IntelMatch
	if err := c.do(http.MethodGet, api.PathIntel+"/check?"+url.Values{"q": {q}}.Encode(), nil, &ms); err != nil {
		return fail(stderr, err)
	}
	if len(ms) == 0 {
		fmt.Fprintf(stdout, "%s はどの一覧にもありません。\n", q)
		return 1
	}
	for _, m := range ms {
		fmt.Fprintf(stdout, "%s は一覧「%s」（%s）の %s に当てはまります。\n", q, m.List, m.Action, m.Indicator)
	}
	return exitOK
}
