package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/enroll"
	"susanoo/internal/keys"
	"susanoo/internal/pki"
)

const ctlEnrollUsage = `使い方: susanoo ctl enroll <操作> [オプション]

一回限りの登録コードで端末を登録する。コードは端末 ID ごとに作り、一度使うか期限が切れると使えなくなる。
有効なコードがある間だけ、CONTROLLER は証明書なしの接続（登録の窓口だけ）を受け付ける。

操作:
  create  登録コードを作る（例: susanoo ctl enroll create pc-001 -ttl 24h）。同じ端末のコードがあれば置き換える
  list    有効な登録コードの一覧を表示する（コードそのものは表示しない）
  delete  登録コードを取り消す（例: susanoo ctl enroll delete pc-001）

端末では「susanoo client enroll -controller <アドレス:ポート> -id <端末ID> -code <コード>」を実行する。
`

func ctlEnroll(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, ctlEnrollUsage)
		return exitUsage
	}
	switch args[0] {
	case "create":
		return ctlEnrollCreate(args[1:], stdout, stderr)
	case "list":
		return ctlEnrollList(args[1:], stdout, stderr)
	case "delete":
		return ctlEnrollDelete(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, ctlEnrollUsage)
		return exitOK
	}
	fmt.Fprintf(stderr, "susanoo: 不明な操作です: ctl enroll %s\n\n%s", args[0], ctlEnrollUsage)
	return exitUsage
}

func ctlEnrollCreate(args []string, stdout, stderr io.Writer) int {
	id, args := splitArg(args)
	flags := flag.NewFlagSet("ctl enroll create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	ttl := flags.Duration("ttl", 24*time.Hour, "登録コードの有効期間（7 日まで）")
	asJSON := flags.Bool("json", false, "JSON で表示する")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if id == "" {
		return fail(stderr, errors.New("端末 ID を指定してください（例: susanoo ctl enroll create pc-001）"))
	}
	var code api.EnrollCode
	if err := c.do(http.MethodPost, api.PathEnrollCodes, api.EnrollCodeCreate{ID: id, TTL: ttl.String()}, &code); err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		json.NewEncoder(stdout).Encode(code)
		return exitOK
	}
	server := c.server
	if ap, err := netip.ParseAddrPort(server); err == nil && ap.Addr().IsLoopback() {
		server = fmt.Sprintf("<CONTROLLER の LAN 側のアドレス>:%d", ap.Port())
	}
	fmt.Fprintf(stdout, "端末 %s の登録コード: %s（期限 %s）\n端末で次のように実行してください。コードは一度だけ使えます。\n  susanoo client enroll -controller %s -id %s -code %s\n",
		code.ID, code.Code, code.Expires.Local().Format("2006-01-02 15:04"), server, code.ID, code.Code)
	return exitOK
}

func ctlEnrollList(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl enroll list", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	asJSON := flags.Bool("json", false, "JSON で表示する")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	var list []api.EnrollCode
	if err := c.do(http.MethodGet, api.PathEnrollCodes, nil, &list); err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		json.NewEncoder(stdout).Encode(list)
		return exitOK
	}
	if len(list) == 0 {
		fmt.Fprintln(stdout, "有効な登録コードはありません")
		return exitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "端末\t作成\t期限\t誤った証明")
	for _, e := range list {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", e.ID, e.Created.Local().Format(timeFormat), e.Expires.Local().Format(timeFormat), e.Failures)
	}
	tw.Flush()
	return exitOK
}

func ctlEnrollDelete(args []string, stdout, stderr io.Writer) int {
	id, args := splitArg(args)
	flags := flag.NewFlagSet("ctl enroll delete", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if id == "" {
		return fail(stderr, errors.New("端末 ID を指定してください（例: susanoo ctl enroll delete pc-001）"))
	}
	var code api.EnrollCode
	if err := c.do(http.MethodDelete, api.PathEnrollCodes+"/"+url.PathEscape(id), nil, &code); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "端末 %s の登録コードを取り消しました。\n", id)
	return exitOK
}

// runEnroll は、一回限りの登録コードで端末を登録し、鍵のディレクトリに証明書、認証局の証明書、指示の公開鍵を置く。
func runEnroll(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("client enroll", flag.ContinueOnError)
	flags.SetOutput(stderr)
	addr := flags.String("controller", "", "CONTROLLER のアドレスとポート（例: 192.168.10.1:8443）")
	id := flags.String("id", "", "端末 ID（登録コードを作ったときの ID）")
	code := flags.String("code", "", "登録コード（省略すると標準入力から読む）")
	dir := flags.String("dir", "/etc/susanoo/client", "鍵を置くディレクトリ")
	force := flags.Bool("force", false, "既にある証明書を置き換える（入れ直すとき）")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *addr == "" || *id == "" {
		return fail(stderr, errors.New("-controller と -id は必須です"))
	}
	if _, _, err := net.SplitHostPort(*addr); err != nil {
		return fail(stderr, fmt.Errorf("-controller %q はアドレスとポート（例: 192.168.10.1:8443）で書いてください", *addr))
	}
	if *code == "" {
		fmt.Fprint(stderr, "登録コード: ")
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && line == "" {
			return fail(stderr, errors.New("登録コードを読めません"))
		}
		*code = strings.TrimSpace(line)
	}
	if _, err := enroll.Normalize(*code); err != nil {
		return fail(stderr, err)
	}
	certPath := filepath.Join(*dir, fileClientCert)
	if _, err := os.Stat(certPath); err == nil && !*force {
		return fail(stderr, fmt.Errorf("%s が既にあります。入れ直す場合は -force を付けてください", certPath))
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return fail(stderr, err)
	}
	priv, err := loadOrCreateClientKey(*dir)
	if err != nil {
		return fail(stderr, err)
	}
	res, err := enroll.Enroll(ctx, *addr, *id, *code, priv)
	if err != nil {
		return fail(stderr, err)
	}
	if err := pki.WriteChainFile(certPath, res.Chain...); err != nil {
		return fail(stderr, err)
	}
	if err := pki.WriteCertFile(filepath.Join(*dir, fileCACert), res.CA); err != nil {
		return fail(stderr, err)
	}
	if err := keys.SavePublic(filepath.Join(*dir, fileCommandPub), res.CommandKey); err != nil {
		return fail(stderr, err)
	}
	if res.ReleaseKey != nil {
		if err := keys.SavePublic(filepath.Join(*dir, fileReleasePub), res.ReleaseKey); err != nil {
			return fail(stderr, err)
		}
	}
	fmt.Fprintf(stdout, "端末 %s を登録しました（証明書の期限 %s）。\n%s に %s、%s、%s を置きました。"+
		"設定ファイルの pki_dir にこのディレクトリを、controller に %s を書いて、CLIENT を起動してください。\n",
		*id, res.Chain[0].NotAfter.Local().Format("2006-01-02"), *dir, fileClientCert, fileCACert, fileCommandPub, *addr)
	return exitOK
}

// loadOrCreateClientKey は端末の鍵を読む。なければ作る。秘密鍵は端末から出さない。
func loadOrCreateClientKey(dir string) (ed25519.PrivateKey, error) {
	keyPath := filepath.Join(dir, fileClientKey)
	priv, err := keys.LoadPrivate(keyPath)
	if err == nil {
		return priv, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if priv, err = keys.Generate(); err != nil {
		return nil, err
	}
	if err := keys.SavePrivate(keyPath, priv); err != nil {
		return nil, err
	}
	return priv, keys.SavePublic(filepath.Join(dir, fileClientPub), priv.Public().(ed25519.PublicKey))
}
