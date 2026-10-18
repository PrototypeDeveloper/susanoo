package main

import (
	"cmp"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/keys"
	"susanoo/internal/policy"
	"susanoo/internal/sign"
)

const ctlPolicyUsage = `使い方: susanoo ctl policy <操作> [オプション]

操作:
  keygen    ポリシーの署名の鍵（policy.key、policy.pub）を作る（ctl init で作っていない場合）
  push      ポリシーのファイルに新しい版数を付け、署名して配布する
            （例: susanoo ctl policy push policy.json、先行適用は -canary pc-001,pc-002 や -canary-groups server）
  list      配布した版の一覧と、今の版と先行適用の版を表示する
  show      版の中身を表示する（例: susanoo ctl policy show 3。省略すると今の版）
  promote   先行適用している版を全体に広げる
  abort     先行適用している版を取り消す
  rollback  過去の版の中身に新しい版数を付けて、署名し直して配布する（例: susanoo ctl policy rollback 2）
`

func ctlPolicy(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, ctlPolicyUsage)
		return exitUsage
	}
	switch args[0] {
	case "keygen":
		return ctlPolicyKeygen(args[1:], stdout, stderr)
	case "push":
		return ctlPolicyPush(args[1:], stdout, stderr)
	case "list":
		return ctlPolicyList(args[1:], stdout, stderr)
	case "show":
		return ctlPolicyShow(args[1:], stdout, stderr)
	case "promote", "abort":
		return ctlPolicyCanary(args[0], args[1:], stdout, stderr)
	case "rollback":
		return ctlPolicyRollback(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, ctlPolicyUsage)
		return exitOK
	}
	fmt.Fprintf(stderr, "susanoo: 不明な操作です: ctl policy %s\n\n%s", args[0], ctlPolicyUsage)
	return exitUsage
}

// createPolicyKey は、ポリシーの署名の鍵がなければ作る。
func createPolicyKey(dir string) error {
	keyPath := filepath.Join(dir, filePolicyKey)
	if _, err := os.Stat(keyPath); !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	priv, err := keys.Generate()
	if err != nil {
		return err
	}
	if err := keys.SavePrivate(keyPath, priv); err != nil {
		return err
	}
	return keys.SavePublic(filepath.Join(dir, filePolicyPub), priv.Public().(ed25519.PublicKey))
}

func ctlPolicyKeygen(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl policy keygen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", defaultCtlDir, "ctl init で作ったディレクトリ")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if err := createPolicyKey(*dir); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "%s にポリシーの署名の鍵があります。%s は外に出さないでください。GW は起動し直すと公開鍵を読みます。\n", *dir, filePolicyKey)
	return exitOK
}

// splitArg は、最初の引数がオプションでなければ取り出す（ctl policy push policy.json -canary ... のため）。
func splitArg(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// nextVersion は、CONTROLLER が受け付けた版より新しい版数を返す。
func nextVersion(info api.PolicyInfo) int {
	v := info.Current.Version
	if info.Canary != nil {
		v = max(v, info.Canary.Version)
	}
	for _, r := range info.Versions {
		v = max(v, r.Version)
	}
	return v + 1
}

// pushPolicy は p に新しい版数を付け、ポリシーの署名の鍵で署名して配布する。
func pushPolicy(c *ctlFlags, p *policy.Policy, devices, groups []string) (api.PolicyInfo, error) {
	var info api.PolicyInfo
	if err := c.do(http.MethodGet, api.PathPolicy, nil, &info); err != nil {
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
	p.Version, p.IssuedAt = nextVersion(info), time.Now().UTC().Truncate(time.Second)
	if err := p.Validate(); err != nil {
		return info, err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return info, err
	}
	req := api.PolicyPush{Envelope: signer.Sign(sign.PurposePolicy, data), CanaryDevices: devices, CanaryGroups: groups}
	err = c.do(http.MethodPost, api.PathPolicy, req, &info)
	return info, err
}

func ctlPolicyPush(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl policy push", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	canary := flags.String("canary", "", "先に適用する端末 ID か MAC アドレス（「,」で区切る）")
	canaryGroups := flags.String("canary-groups", "", "先に適用するグループ（「,」で区切る。その端末と機器すべて）")
	file, args := splitArg(args)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	file = cmp.Or(file, flags.Arg(0))
	if file == "" {
		return fail(stderr, errors.New("ポリシーのファイルを指定してください"))
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return fail(stderr, err)
	}
	p, err := policy.Parse(data)
	if err != nil {
		return fail(stderr, err)
	}
	info, err := pushPolicy(&c, p, splitList(*canary), splitList(*canaryGroups))
	if err != nil {
		return fail(stderr, err)
	}
	if info.Canary != nil {
		fmt.Fprintf(stdout, "版 %d を先行適用しました（端末 %s、グループ %s）。問題がなければ ctl policy promote で全体に広げ、問題があれば ctl policy abort で取り消してください。\n",
			info.Canary.Version, dash(strings.Join(info.Canary.Devices, ",")), dash(strings.Join(info.Canary.Groups, ",")))
	} else {
		fmt.Fprintf(stdout, "版 %d を適用しました。\n", info.Current.Version)
	}
	return exitOK
}

func ctlPolicyList(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl policy list", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	asJSON := flags.Bool("json", false, "JSON で表示する")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	var info api.PolicyInfo
	if err := c.do(http.MethodGet, api.PathPolicy, nil, &info); err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(info)
		return exitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "版数\t名前\t発行\t受付\t状態")
	for _, r := range info.Versions {
		state := "-"
		switch {
		case r.Version == info.Current.Version:
			state = "適用中"
		case info.Canary != nil && r.Version == info.Canary.Version:
			state = fmt.Sprintf("先行適用（端末 %s、グループ %s）", dash(strings.Join(info.Canary.Devices, ",")), dash(strings.Join(info.Canary.Groups, ",")))
		}
		applied := "-"
		if !r.AppliedAt.IsZero() {
			applied = r.AppliedAt.Local().Format("01-02 15:04:05")
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", r.Version, r.Name, r.IssuedAt.Local().Format("01-02 15:04:05"), applied, state)
	}
	tw.Flush()
	return exitOK
}

// fetchVersion は版 v の中身を取り出す。v が 0 なら今の版。
func fetchVersion(c *ctlFlags, v int) (json.RawMessage, error) {
	if v == 0 {
		var info api.PolicyInfo
		if err := c.do(http.MethodGet, api.PathPolicy, nil, &info); err != nil {
			return nil, err
		}
		v = info.Current.Version
	}
	var raw json.RawMessage
	err := c.do(http.MethodGet, api.PathPolicy+"/versions/"+strconv.Itoa(v), nil, &raw)
	return raw, err
}

func versionArg(args []string, name string, required bool, stderr io.Writer) (int, []string, bool) {
	arg, rest := splitArg(args)
	if arg == "" {
		if required {
			fmt.Fprintf(stderr, "susanoo: %s する版数を指定してください\n", name)
			return 0, nil, false
		}
		return 0, rest, true
	}
	v, err := strconv.Atoi(arg)
	if err != nil || v < 1 {
		fmt.Fprintf(stderr, "susanoo: 版数 %q が不正です\n", arg)
		return 0, nil, false
	}
	return v, rest, true
}

func ctlPolicyShow(args []string, stdout, stderr io.Writer) int {
	v, args, ok := versionArg(args, "表示", false, stderr)
	if !ok {
		return exitUsage
	}
	flags := flag.NewFlagSet("ctl policy show", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	raw, err := fetchVersion(&c, v)
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

func ctlPolicyRollback(args []string, stdout, stderr io.Writer) int {
	v, args, ok := versionArg(args, "戻", true, stderr)
	if !ok {
		return exitUsage
	}
	flags := flag.NewFlagSet("ctl policy rollback", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	raw, err := fetchVersion(&c, v)
	if err != nil {
		return fail(stderr, err)
	}
	p, err := policy.Parse(raw)
	if err != nil {
		return fail(stderr, err)
	}
	info, err := pushPolicy(&c, p, nil, nil)
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "版 %d の中身を、版 %d として適用しました。\n", v, info.Current.Version)
	return exitOK
}

func ctlPolicyCanary(op string, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl policy "+op, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	var info api.PolicyInfo
	if err := c.do(http.MethodPost, api.PathPolicy+"/"+op, nil, &info); err != nil {
		return fail(stderr, err)
	}
	if op == "promote" {
		fmt.Fprintf(stdout, "版 %d を全体に適用しました。\n", info.Current.Version)
	} else {
		fmt.Fprintf(stdout, "先行適用を取り消しました。今の版は %d です。\n", info.Current.Version)
	}
	return exitOK
}
