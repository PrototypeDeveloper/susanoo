package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/keys"
	"susanoo/internal/pki"
)

// 管理者の証明書の発行と失効、認証局の証明書の更新（2m-3）。

const ctlAdminUsage = `使い方: susanoo ctl admin <操作> [オプション]

管理者の証明書を、管理者ごとに発行し、なくしたときに失効させる。発行には認証局の秘密鍵が要る（一段の認証局なら GW の
ディレクトリ、二段構えならルートのディレクトリで行う）。失効は CONTROLLER に記録する。

操作:
  keygen   管理者の鍵（admin.key、admin.pub）を作る（例: susanoo ctl admin keygen -dir ~/susanoo-admin）
  issue    管理者の公開鍵に証明書を発行し、ctl の -dir に使えるディレクトリに書き出す
           （例: susanoo ctl admin issue -dir /etc/susanoo/controller -id alice -pub admin.pub -out ~/susanoo-admin）
  revoke   その時刻より前に発行した管理者の証明書を失効させる（例: susanoo ctl admin revoke alice）。自分と同じ ID なら、
           今使っている証明書より前に発行したものだけを失効させる（なくした証明書は、発行し直した証明書で失効させる）
  list     失効させた管理者の証明書を表示する
`

func ctlAdmin(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, ctlAdminUsage)
		return exitUsage
	}
	switch args[0] {
	case "keygen":
		return ctlAdminKeygen(args[1:], stdout, stderr)
	case "issue":
		return ctlAdminIssue(args[1:], stdout, stderr)
	case "revoke":
		return ctlAdminRevoke(args[1:], stdout, stderr)
	case "list":
		return ctlAdminList(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, ctlAdminUsage)
		return exitOK
	}
	fmt.Fprintf(stderr, "susanoo: 不明な操作です: ctl admin %s\n\n%s", args[0], ctlAdminUsage)
	return exitUsage
}

const fileAdminPub = "admin.pub"

func ctlAdminKeygen(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl admin keygen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", "", "鍵を置くディレクトリ")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *dir == "" {
		return fail(stderr, errors.New("-dir は必須です"))
	}
	keyPath := filepath.Join(*dir, fileAdminKey)
	if _, err := os.Stat(keyPath); !errors.Is(err, fs.ErrNotExist) {
		return fail(stderr, fmt.Errorf("%s は既にあります（作り直しません）", keyPath))
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return fail(stderr, err)
	}
	priv, err := keys.Generate()
	if err != nil {
		return fail(stderr, err)
	}
	if err := keys.SavePrivate(keyPath, priv); err != nil {
		return fail(stderr, err)
	}
	if err := keys.SavePublic(filepath.Join(*dir, fileAdminPub), priv.Public().(ed25519.PublicKey)); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "管理者の鍵を作りました。%s を認証局のある機器に渡し、ctl admin issue で証明書を発行してください。%s は外に出さないでください。\n",
		filepath.Join(*dir, fileAdminPub), keyPath)
	return exitOK
}

func ctlAdminIssue(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl admin issue", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", defaultCtlDir, "認証局の秘密鍵（ca.key）のあるディレクトリ（一段なら GW、二段構えならルート）")
	id := flags.String("id", "", "管理者の ID（例: alice）")
	pubPath := flags.String("pub", "", "管理者の公開鍵（ctl admin keygen で作った admin.pub）")
	out := flags.String("out", "", "証明書（admin.crt）と認証局の証明書（ca.crt）を書き出すディレクトリ")
	validity := flags.Duration("validity", pki.LeafValidity, "有効期間（90 日まで）")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *id == "" || *pubPath == "" || *out == "" {
		return fail(stderr, errors.New("-id、-pub、-out は必須です"))
	}
	ca, err := pki.LoadCA(*dir)
	if err != nil {
		return fail(stderr, err)
	}
	if ca.TwoTier() {
		return fail(stderr, errors.New("二段構えの GW のディレクトリでは管理者の証明書を発行できません。ルートのディレクトリで発行してください"))
	}
	pub, err := keys.LoadPublic(*pubPath)
	if err != nil {
		return fail(stderr, err)
	}
	cert, err := ca.IssueFor(pub, pki.Identity{Role: pki.RoleAdmin, ID: *id}, time.Now(), *validity)
	if err != nil {
		return fail(stderr, err)
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return fail(stderr, err)
	}
	if err := pki.WriteCertFile(filepath.Join(*out, fileAdminCert), cert); err != nil {
		return fail(stderr, err)
	}
	if err := pki.WriteCertFile(filepath.Join(*out, fileCACert), ca.Root); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "管理者 %s の証明書を発行しました（期限 %s）。%s を管理者の鍵と同じディレクトリに置き、ctl の -dir に指定してください。\n",
		*id, cert.NotAfter.Local().Format("2006-01-02"), *out)
	return exitOK
}

func ctlAdminRevoke(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl admin revoke", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	before := flags.String("before", "", "この時刻より前に発行した証明書を失効させる（RFC 3339。省略すると上の説明のとおり）")
	id, args := splitArg(args)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if id == "" {
		id = flags.Arg(0)
	}
	if id == "" {
		return fail(stderr, errors.New("失効させる管理者の ID を指定してください"))
	}
	var req api.AdminRevokeRequest
	if *before != "" {
		t, err := time.Parse(time.RFC3339, *before)
		if err != nil {
			return fail(stderr, fmt.Errorf("-before は RFC 3339 の時刻で書いてください: %w", err))
		}
		req.Before = t
	}
	var rev api.AdminRevocation
	if err := c.do(http.MethodPost, api.PathAdmins+"/"+url.PathEscape(id)+"/revoke", req, &rev); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "管理者 %s の、%s 以前に発行した証明書を失効させました。\n", rev.ID, rev.RevokedBefore.Local().Format(time.DateTime))
	return exitOK
}

func ctlAdminList(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl admin list", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	asJSON := flags.Bool("json", false, "JSON で表示する")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	var list api.AdminList
	if err := c.do(http.MethodGet, api.PathAdmins, nil, &list); err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(list)
		return exitOK
	}
	fmt.Fprintf(stdout, "今の管理者: %s\n", list.Self)
	if len(list.Revoked) == 0 {
		fmt.Fprintln(stdout, "失効させた管理者の証明書はありません。")
		return exitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "管理者\tこの時刻以前に発行した証明書を失効")
	for _, r := range list.Revoked {
		fmt.Fprintf(tw, "%s\t%s\n", r.ID, r.RevokedBefore.Local().Format(time.DateTime))
	}
	tw.Flush()
	return exitOK
}

const ctlCAUsage = `使い方: susanoo ctl ca renew -dir <認証局のディレクトリ>

認証局の証明書（有効期間 10 年）を、同じ鍵と名前のまま、期限を延ばして発行し直す。発行済みの証明書はそのまま使える。
  一段の認証局：GW のディレクトリで実行し、GW を起動し直す。CLIENT には CONTROLLER が新しい証明書を配る
  二段構え：ルートのディレクトリで実行し、ctl root sign-issuer で発行用の認証局に署名し直してから、GW で ctl init -issuer を
  実行して GW を起動し直す
どちらも、ほかの場所に写した ca.crt（管理者のディレクトリなど）は、前の証明書の期限までに新しいものに置き換える。
`

func ctlCA(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "renew" {
		fmt.Fprint(stderr, ctlCAUsage)
		return exitUsage
	}
	flags := flag.NewFlagSet("ctl ca renew", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", defaultCtlDir, "認証局の秘密鍵（ca.key）のあるディレクトリ（一段なら GW、二段構えならルート）")
	if err := flags.Parse(args[1:]); err != nil {
		return exitUsage
	}
	ca, err := pki.LoadCA(*dir)
	if err != nil {
		return fail(stderr, err)
	}
	if ca.TwoTier() {
		return fail(stderr, errors.New("二段構えの GW のディレクトリです。ルートのディレクトリで実行してください（発行用の認証局は ctl root sign-issuer で更新します）"))
	}
	old := ca.Cert.NotAfter
	cert, err := ca.RenewSelf(time.Now())
	if err != nil {
		return fail(stderr, err)
	}
	if err := pki.WriteCertFile(filepath.Join(*dir, fileCACert), cert); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "認証局の証明書を発行し直しました（期限 %s → %s）。\n", old.Local().Format("2006-01-02"), cert.NotAfter.Local().Format("2006-01-02"))
	if cert.MaxPathLen >= 1 {
		fmt.Fprintln(stdout, "二段構えのルートです。ctl root sign-issuer で発行用の認証局に署名し直し、GW で ctl init -issuer を実行して、GW を起動し直してください。")
	} else {
		fmt.Fprintln(stdout, "GW を起動し直してください。CLIENT には CONTROLLER が新しい証明書を配ります。ほかの場所に写した ca.crt も置き換えてください。")
	}
	return exitOK
}
