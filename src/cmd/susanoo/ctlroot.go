package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"susanoo/internal/fsutil"
	"susanoo/internal/keys"
	"susanoo/internal/pki"
)

// 二段構えの鍵（ルートの認証局をオフラインで持つ）。
//
// 管理者の手元（USB メモリなど、GW の外）にルートの認証局の鍵と、ポリシーの署名の鍵と、管理者の証明書を置く。
// GW はルートの署名した発行用の認証局の鍵だけを持つ。発行用の認証局の証明書は名前の制約で、端末、CONTROLLER、
// GW の証明書しか検証に通らないので、GW を乗っ取られても、管理者の証明書や、署名したポリシーは作れない。
const ctlRootUsage = `使い方: susanoo ctl root <操作> [オプション]

二段構えの鍵の、管理者の手元（GW の外）で行う操作です。-dir は USB メモリなど、ふだんは外しておく場所にしてください。

操作:
  init         ルートの認証局、ポリシーの署名の鍵、管理者の証明書を作る
               （例: susanoo ctl root init -dir /media/usb/susanoo-root）
  sign-issuer  GW の発行用の認証局の公開鍵（ctl init -two-tier で作る issuer.pub）に署名し、GW に渡すファイルを書き出す
               （例: susanoo ctl root sign-issuer -dir /media/usb/susanoo-root -pub issuer.pub -out to-gw）
  admin        管理者の証明書を、今の鍵のまま発行し直す（期限が近づいたら行う）

GW の側の手順:
  1. susanoo ctl init -two-tier -dir /etc/susanoo/controller     発行用の認証局の鍵を作る
  2. issuer.pub を管理者に渡し、管理者が sign-issuer で署名する
  3. susanoo ctl init -issuer to-gw -dir /etc/susanoo/controller  署名を受け取り、CONTROLLER の証明書を作る
発行用の認証局の証明書の期限が近づいたら、2 と 3 を繰り返して GW を起動し直します。
`

// issuerWarnBefore は、発行用の認証局の証明書の期限が近いと知らせる残りの日数。
const issuerWarnBefore = 30 * 24 * time.Hour

func ctlRoot(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, ctlRootUsage)
		return exitUsage
	}
	switch args[0] {
	case "init":
		return ctlRootInit(args[1:], stdout, stderr)
	case "sign-issuer":
		return ctlRootSignIssuer(args[1:], stdout, stderr)
	case "admin":
		return ctlRootAdmin(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, ctlRootUsage)
		return exitOK
	}
	fmt.Fprintf(stderr, "susanoo: 不明な操作です: ctl root %s\n\n%s", args[0], ctlRootUsage)
	return exitUsage
}

func ctlRootInit(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl root init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", "", "ルートの認証局の鍵を置くディレクトリ（USB メモリなど、GW の外）")
	name := flags.String("name", "susanoo ルート認証局", "ルートの認証局の名前")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *dir == "" {
		return fail(stderr, errors.New("-dir は必須です"))
	}
	if _, err := os.Stat(filepath.Join(*dir, fileCAKey)); !errors.Is(err, fs.ErrNotExist) {
		return fail(stderr, fmt.Errorf("%s には既に認証局があります", *dir))
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return fail(stderr, err)
	}
	now := time.Now()
	root, err := pki.NewRootCA(*name, now)
	if err != nil {
		return fail(stderr, err)
	}
	if err := root.Save(*dir); err != nil {
		return fail(stderr, err)
	}
	if err := createPolicyKey(*dir); err != nil {
		return fail(stderr, err)
	}
	admin, err := root.NewLeaf(pki.Identity{Role: pki.RoleAdmin, ID: "admin"}, now)
	if err != nil {
		return fail(stderr, err)
	}
	if err := pki.WriteCertFile(filepath.Join(*dir, fileAdminCert), admin.Leaf); err != nil {
		return fail(stderr, err)
	}
	if err := keys.SavePrivate(filepath.Join(*dir, fileAdminKey), admin.PrivateKey.(ed25519.PrivateKey)); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "%s にルートの認証局（期限 %s）、ポリシーの署名の鍵、管理者の証明書（期限 %s）を作りました。\n"+
		"%s と %s は GW に置かないでください。ctl の操作は -dir %s で行います。\n",
		*dir, root.Cert.NotAfter.Local().Format("2006-01-02"), admin.Leaf.NotAfter.Local().Format("2006-01-02"), fileCAKey, filePolicyKey, *dir)
	return exitOK
}

// loadRoot はルートの認証局を読む。一段の認証局（ctl init で作ったもの）は断る。
func loadRoot(dir string) (*pki.CA, error) {
	if _, err := os.Stat(filepath.Join(dir, pki.IssuerKeyFile)); err == nil {
		return nil, fmt.Errorf("%s は GW の発行用の認証局です。ctl root init で作ったディレクトリを指定してください", dir)
	}
	ca, err := pki.LoadCA(dir)
	if err != nil {
		return nil, err
	}
	if ca.Cert.MaxPathLenZero || ca.Cert.MaxPathLen < 1 {
		return nil, fmt.Errorf("%s は一段の認証局です。ctl root init で作ったディレクトリを指定してください", dir)
	}
	return ca, nil
}

func ctlRootSignIssuer(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl root sign-issuer", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", "", "ctl root init で作ったディレクトリ")
	pubPath := flags.String("pub", "", "GW の発行用の認証局の公開鍵（ctl init -two-tier で作った issuer.pub）")
	out := flags.String("out", "", "GW に渡すファイル（issuer.crt、ca.crt、policy.pub）を書き出すディレクトリ")
	name := flags.String("name", "susanoo 発行用認証局", "発行用の認証局の名前")
	validity := flags.Duration("validity", pki.IssuerValidity, "発行用の認証局の証明書の有効期間（1 年まで。短いほど、鍵を盗まれたときの影響が短い）")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *dir == "" || *pubPath == "" || *out == "" {
		return fail(stderr, errors.New("-dir、-pub、-out は必須です"))
	}
	if *validity <= 0 || *validity > pki.IssuerValidity {
		return fail(stderr, fmt.Errorf("-validity は 0 より長く %s までにしてください", pki.IssuerValidity))
	}
	root, err := loadRoot(*dir)
	if err != nil {
		return fail(stderr, err)
	}
	pub, err := keys.LoadPublic(*pubPath)
	if err != nil {
		return fail(stderr, err)
	}
	cert, err := root.SignIssuer(pub, *name, time.Now(), *validity)
	if err != nil {
		return fail(stderr, err)
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return fail(stderr, err)
	}
	if err := pki.WriteCertFile(filepath.Join(*out, pki.IssuerCertFile), cert); err != nil {
		return fail(stderr, err)
	}
	if err := pki.WriteCertFile(filepath.Join(*out, fileCACert), root.Cert); err != nil {
		return fail(stderr, err)
	}
	policyPub, err := os.ReadFile(filepath.Join(*dir, filePolicyPub))
	if err != nil {
		return fail(stderr, err)
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(*out, filePolicyPub), policyPub, 0o644); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "発行用の認証局の証明書に署名しました（期限 %s）。\n%s を GW に運び、susanoo ctl init -issuer %s で受け取ってください。\n",
		cert.NotAfter.Local().Format("2006-01-02"), *out, *out)
	return exitOK
}

func ctlRootAdmin(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl root admin", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", "", "ctl root init で作ったディレクトリ")
	validity := flags.Duration("validity", pki.LeafValidity, "管理者の証明書の有効期間（90 日まで）")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *dir == "" {
		return fail(stderr, errors.New("-dir は必須です"))
	}
	root, err := loadRoot(*dir)
	if err != nil {
		return fail(stderr, err)
	}
	priv, err := keys.LoadPrivate(filepath.Join(*dir, fileAdminKey))
	if err != nil {
		return fail(stderr, err)
	}
	cert, err := root.IssueFor(priv.Public().(ed25519.PublicKey), pki.Identity{Role: pki.RoleAdmin, ID: "admin"}, time.Now(), *validity)
	if err != nil {
		return fail(stderr, err)
	}
	if err := pki.WriteCertFile(filepath.Join(*dir, fileAdminCert), cert); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "管理者の証明書を発行し直しました（期限 %s）。\n", cert.NotAfter.Local().Format("2006-01-02"))
	return exitOK
}

// ctlInitIssuerKey は GW の発行用の認証局の鍵を作る（二段構えの 1 段目）。既にあれば作り直さない。
func ctlInitIssuerKey(dir string, stdout io.Writer) error {
	if _, err := os.Stat(filepath.Join(dir, fileCAKey)); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s には既に一段の認証局があります", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	keyPath, pubPath := filepath.Join(dir, pki.IssuerKeyFile), filepath.Join(dir, pki.IssuerPubFile)
	if _, err := os.Stat(keyPath); errors.Is(err, fs.ErrNotExist) {
		priv, err := keys.Generate()
		if err != nil {
			return err
		}
		if err := keys.SavePrivate(keyPath, priv); err != nil {
			return err
		}
		if err := keys.SavePublic(pubPath, priv.Public().(ed25519.PublicKey)); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s に発行用の認証局の鍵があります。\n%s を管理者に渡し、ctl root sign-issuer で署名を受けてから、"+
		"susanoo ctl init -issuer <受け取ったディレクトリ> -dir %s を実行してください。\n", dir, pubPath, dir)
	return nil
}

// ctlInitIssuer は、ルートの署名した発行用の認証局の証明書を受け取り、署名の鍵と CONTROLLER の証明書を作る（二段構えの 2 段目）。
// 既に受け取っていれば、発行用の認証局の証明書だけを差し替える（期限の更新）。CONTROLLER の証明書は GW の起動のときに発行し直す。
func ctlInitIssuer(dir, from string, stdout io.Writer) error {
	priv, err := keys.LoadPrivate(filepath.Join(dir, pki.IssuerKeyFile))
	if err != nil {
		return fmt.Errorf("%w。先に susanoo ctl init -two-tier -dir %s で発行用の認証局の鍵を作ってください", err, dir)
	}
	root, err := pki.ReadCertFile(filepath.Join(from, fileCACert))
	if err != nil {
		return err
	}
	issuer, err := pki.ReadCertFile(filepath.Join(from, pki.IssuerCertFile))
	if err != nil {
		return err
	}
	if err := pki.CheckIssuer(root, issuer, priv.Public().(ed25519.PublicKey)); err != nil {
		return err
	}
	if cur, err := pki.ReadCertFile(filepath.Join(dir, fileCACert)); err == nil && !cur.Equal(root) {
		return fmt.Errorf("%s のルートの認証局が、今のもの（%s）と違います", from, filepath.Join(dir, fileCACert))
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	policyPub, err := keys.LoadPublic(filepath.Join(from, filePolicyPub))
	if err != nil {
		return err
	}
	if err := pki.WriteCertFile(filepath.Join(dir, fileCACert), root); err != nil {
		return err
	}
	if err := pki.WriteCertFile(filepath.Join(dir, pki.IssuerCertFile), issuer); err != nil {
		return err
	}
	if err := keys.SavePublic(filepath.Join(dir, filePolicyPub), policyPub); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, fileSignKey)); err == nil {
		fmt.Fprintf(stdout, "発行用の認証局の証明書を差し替えました（期限 %s）。GW を起動し直すと、CONTROLLER の証明書を発行し直します。\n",
			issuer.NotAfter.Local().Format("2006-01-02"))
		return nil
	}
	ca, err := pki.LoadCA(dir)
	if err != nil {
		return err
	}
	signKey, err := keys.Generate()
	if err != nil {
		return err
	}
	if err := keys.SavePrivate(filepath.Join(dir, fileSignKey), signKey); err != nil {
		return err
	}
	if err := keys.SavePublic(filepath.Join(dir, fileSignPub), signKey.Public().(ed25519.PublicKey)); err != nil {
		return err
	}
	c, err := ca.NewLeaf(pki.Identity{Role: pki.RoleController, ID: "main"}, time.Now())
	if err != nil {
		return err
	}
	if err := pki.WriteChainFile(filepath.Join(dir, fileControllerCert), ca.ChainOf(c.Leaf)...); err != nil {
		return err
	}
	if err := keys.SavePrivate(filepath.Join(dir, fileControllerKey), c.PrivateKey.(ed25519.PrivateKey)); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s に署名の鍵と CONTROLLER の証明書を作りました（発行用の認証局の期限 %s）。\n"+
		"管理者の証明書とポリシーの署名の鍵はルートのディレクトリにあります。ctl の操作は管理者の手元から -dir で指定して行います。\n",
		dir, issuer.NotAfter.Local().Format("2006-01-02"))
	return nil
}
