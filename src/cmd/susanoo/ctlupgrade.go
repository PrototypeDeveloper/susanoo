package main

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/fsutil"
	"susanoo/internal/keys"
	"susanoo/internal/release"
	"susanoo/internal/sign"
)

const ctlUpgradeUsage = `使い方: susanoo ctl upgrade <操作> [オプション]

署名したリリース（susanoo の実行ファイル）を CLIENT に段階的に配り、入れ替えさせる。目録は管理者の手元の
ポリシーの署名の鍵で署名する（二段構えならルートのディレクトリで行う）。CLIENT は目録の署名とハッシュを確かめ、
今より新しい版だけに入れ替えて終わる（systemd などで起動し直す）。CLIENT には release.pub（ctl issue と
client enroll が置く）が必要。

操作:
  sign      実行ファイルのハッシュの目録を作って署名し、配るファイルをまとめる
            （例: susanoo ctl upgrade sign -dir /media/usb/susanoo-root -version 0.2.0 -bin linux/amd64=susanoo-amd64 -out rel）
  push      まとめたリリースを CONTROLLER に送る（例: susanoo ctl upgrade push rel -canary pc-001。先行適用は -canary か -canary-groups）
  status    配っているリリースと、入れ替えた端末を表示する
  promote   先行適用しているリリースを全体に広げる
  abort     リリースの配布をやめる（入れ替えた端末はそのまま）
  verify    実行ファイルが目録と合うかを確かめる（GW を手で入れ替えるときなど）
            （例: susanoo ctl upgrade verify -manifest rel/manifest.json -key policy.pub -bin susanoo-amd64 -os linux -arch amd64）
`

const manifestFile = "manifest.json"

func ctlUpgrade(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, ctlUpgradeUsage)
		return exitUsage
	}
	switch args[0] {
	case "sign":
		return ctlUpgradeSign(args[1:], stdout, stderr)
	case "push":
		return ctlUpgradePush(args[1:], stdout, stderr)
	case "status":
		return ctlUpgradeStatus(args[1:], stdout, stderr)
	case "promote", "abort":
		return ctlUpgradeChange(args[0], args[1:], stdout, stderr)
	case "verify":
		return ctlUpgradeVerify(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, ctlUpgradeUsage)
		return exitOK
	}
	fmt.Fprintf(stderr, "susanoo: 不明な操作です: ctl upgrade %s\n\n%s", args[0], ctlUpgradeUsage)
	return exitUsage
}

// binFlags は「OS/CPU=ファイル」の並び。
type binFlags []string

func (b *binFlags) String() string     { return strings.Join(*b, ",") }
func (b *binFlags) Set(s string) error { *b = append(*b, s); return nil }

func binaryFileName(goos, goarch string) string { return "susanoo-" + goos + "-" + goarch }

// fileDigest はファイルの大きさと SHA-256 を返す。
func fileDigest(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return n, hex.EncodeToString(h.Sum(nil)), err
}

func ctlUpgradeSign(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl upgrade sign", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", defaultCtlDir, "ポリシーの署名の鍵（policy.key）のあるディレクトリ")
	version := flags.String("version", "", "リリースの版数（例 0.2.0。実行ファイルが「susanoo version」で答える版数）")
	out := flags.String("out", "", "目録と実行ファイルを書き出すディレクトリ")
	var bins binFlags
	flags.Var(&bins, "bin", "OS/CPU=実行ファイル（例 linux/amd64=bin/susanoo。繰り返して指定できる）")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *version == "" || *out == "" || len(bins) == 0 {
		return fail(stderr, errors.New("-version、-out、-bin は必須です"))
	}
	priv, err := keys.LoadPrivate(filepath.Join(*dir, filePolicyKey))
	if err != nil {
		return fail(stderr, err)
	}
	signer, err := sign.NewSigner(priv)
	if err != nil {
		return fail(stderr, err)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return fail(stderr, err)
	}
	m := api.ReleaseManifest{Version: *version, IssuedAt: time.Now().UTC()}
	for _, b := range bins {
		target, path, ok := strings.Cut(b, "=")
		goos, goarch, ok2 := strings.Cut(target, "/")
		if !ok || !ok2 {
			return fail(stderr, fmt.Errorf("-bin %q は「OS/CPU=ファイル」の形で書いてください", b))
		}
		size, sum, err := fileDigest(path)
		if err != nil {
			return fail(stderr, err)
		}
		m.Files = append(m.Files, api.ReleaseFile{OS: goos, Arch: goarch, SHA256: sum, Size: size})
		data, err := os.ReadFile(path)
		if err != nil {
			return fail(stderr, err)
		}
		if err := fsutil.WriteFileAtomic(filepath.Join(*out, binaryFileName(goos, goarch)), data, 0o755); err != nil {
			return fail(stderr, err)
		}
	}
	if err := release.Validate(m); err != nil {
		return fail(stderr, err)
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return fail(stderr, err)
	}
	env, err := json.MarshalIndent(signer.Sign(sign.PurposeRelease, payload), "", "  ")
	if err != nil {
		return fail(stderr, err)
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(*out, manifestFile), append(env, '\n'), 0o644); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "版 %s の目録に署名しました（実行ファイル %d 個）。susanoo ctl upgrade push %s で配ってください。\n", m.Version, len(m.Files), *out)
	return exitOK
}

// readManifest はまとめたリリースの目録を読む（署名は確かめない。確かめるのは CONTROLLER と CLIENT）。
func readManifest(dir string) (sign.Envelope, api.ReleaseManifest, error) {
	var env sign.Envelope
	var m api.ReleaseManifest
	data, err := os.ReadFile(filepath.Join(dir, manifestFile))
	if err != nil {
		return env, m, err
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return env, m, fmt.Errorf("%s を解析できません: %w", manifestFile, err)
	}
	if err := json.Unmarshal(env.Payload, &m); err != nil {
		return env, m, fmt.Errorf("目録を解析できません: %w", err)
	}
	return env, m, release.Validate(m)
}

func ctlUpgradePush(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl upgrade push", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	canary := flags.String("canary", "", "先に入れ替えさせる端末 ID（「,」で区切る）")
	canaryGroups := flags.String("canary-groups", "", "先に入れ替えさせるグループ（「,」で区切る）")
	dir, args := splitArg(args)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	dir = cmp.Or(dir, flags.Arg(0))
	if dir == "" {
		return fail(stderr, errors.New("ctl upgrade sign で書き出したディレクトリを指定してください"))
	}
	env, m, err := readManifest(dir)
	if err != nil {
		return fail(stderr, err)
	}
	var info api.ReleaseInfo
	if err := c.do(http.MethodPost, api.PathReleases, api.ReleasePush{Manifest: env, Canary: splitList(*canary), CanaryGroups: splitList(*canaryGroups)}, &info); err != nil {
		return fail(stderr, err)
	}
	for _, f := range m.Files {
		file, err := os.Open(filepath.Join(dir, binaryFileName(f.OS, f.Arch)))
		if err != nil {
			return fail(stderr, err)
		}
		err = c.doRaw(http.MethodPut, fmt.Sprintf("%s/files/%s/%s", api.PathReleases, f.OS, f.Arch), file, &info, api.MaxBodyBytes, 10*time.Minute)
		file.Close()
		if err != nil {
			return fail(stderr, fmt.Errorf("%s/%s の実行ファイルを送れません: %w", f.OS, f.Arch, err))
		}
	}
	if info.Promoted {
		fmt.Fprintf(stdout, "版 %s をすべての端末に配りました。\n", info.Version)
	} else {
		fmt.Fprintf(stdout, "版 %s を先行適用で配りました（端末 %s、グループ %s）。問題がなければ ctl upgrade promote で全体に広げてください。\n",
			info.Version, dash(strings.Join(info.Canary, ",")), dash(strings.Join(info.CanaryGroups, ",")))
	}
	return exitOK
}

func ctlUpgradeStatus(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl upgrade status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	asJSON := flags.Bool("json", false, "JSON で表示する")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	var info api.ReleaseInfo
	if err := c.do(http.MethodGet, api.PathReleases, nil, &info); err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		json.NewEncoder(stdout).Encode(info)
		return exitOK
	}
	scope := "全体"
	if !info.Promoted {
		scope = fmt.Sprintf("先行適用（端末 %s、グループ %s）", dash(strings.Join(info.Canary, ",")), dash(strings.Join(info.CanaryGroups, ",")))
	}
	fmt.Fprintf(stdout, "版 %s（%s。配布 %s）\n実行ファイル %s（未送信 %s）\n入れ替えた端末 %s\n入れ替え待ちの端末 %s\n",
		info.Version, scope, info.PushedAt.Local().Format(timeFormat), strings.Join(info.Files, ","), dash(strings.Join(info.Missing, ",")),
		dash(strings.Join(info.Updated, ",")), dash(strings.Join(info.Pending, ",")))
	return exitOK
}

func ctlUpgradeChange(op string, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl upgrade "+op, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	var info api.ReleaseInfo
	if err := c.do(http.MethodPost, api.PathReleases+"/"+op, nil, &info); err != nil {
		return fail(stderr, err)
	}
	if op == "promote" {
		fmt.Fprintf(stdout, "版 %s を全体に広げました。\n", info.Version)
	} else {
		fmt.Fprintf(stdout, "版 %s の配布をやめました（入れ替えた端末はそのまま）。\n", info.Version)
	}
	return exitOK
}

func ctlUpgradeVerify(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl upgrade verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifest := flags.String("manifest", "", "目録（manifest.json）")
	keyPath := flags.String("key", "", "ポリシーの署名の公開鍵（policy.pub か、CLIENT の release.pub）")
	bin := flags.String("bin", "", "確かめる実行ファイル")
	goos := flags.String("os", "linux", "実行ファイルの OS")
	goarch := flags.String("arch", "amd64", "実行ファイルの CPU")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *manifest == "" || *keyPath == "" || *bin == "" {
		return fail(stderr, errors.New("-manifest、-key、-bin は必須です"))
	}
	pub, err := keys.LoadPublic(*keyPath)
	if err != nil {
		return fail(stderr, err)
	}
	v, err := sign.NewVerifier(pub)
	if err != nil {
		return fail(stderr, err)
	}
	data, err := os.ReadFile(*manifest)
	if err != nil {
		return fail(stderr, err)
	}
	var env sign.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return fail(stderr, err)
	}
	m, err := release.Verify(v, env)
	if err != nil {
		return fail(stderr, err)
	}
	f, ok := release.File(m, *goos, *goarch)
	if !ok {
		return fail(stderr, fmt.Errorf("目録に %s/%s の実行ファイルがありません", *goos, *goarch))
	}
	size, sum, err := fileDigest(*bin)
	if err != nil {
		return fail(stderr, err)
	}
	if size != f.Size || sum != f.SHA256 {
		return fail(stderr, fmt.Errorf("%s は目録の版 %s の %s/%s の実行ファイルと合いません", *bin, m.Version, *goos, *goarch))
	}
	fmt.Fprintf(stdout, "%s は、署名した目録の版 %s の %s/%s の実行ファイルと合います。\n", *bin, m.Version, *goos, *goarch)
	return exitOK
}
