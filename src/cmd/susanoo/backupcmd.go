package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"susanoo/internal/backup"
	"susanoo/internal/config"
	"susanoo/internal/version"
)

// 設定のバックアップと復元（M11）。

const backupUsage = `使い方: susanoo backup <操作> [オプション]

操作:
  create   GW の設定、ポリシー、鍵と証明書、状態（台帳、監査ログ、検知ルール、脅威情報、インシデントなど）を 1 つのファイルに書き出す
           （例: susanoo backup create -config /etc/susanoo/gw.json -out /root/susanoo.backup -passphrase-file /root/backup.pass）
  verify   バックアップを復号して、すべてのファイルの大きさとハッシュを確かめる（書き出さない）
  restore  バックアップを戻す。GW を止めてから行う
           （例: susanoo backup restore -config /etc/susanoo/gw.json -in /root/susanoo.backup -passphrase-file /root/backup.pass）

認証局とポリシーの署名の秘密鍵を含むので、パスフレーズ（12 文字以上）で暗号化する。パスフレーズは -passphrase-file のファイルか、
環境変数 SUSANOO_BACKUP_PASSPHRASE で渡す。イベントと証拠は大きいので、-events、-evidence を付けたときだけ入れる。
GW を動かしたままでも作れる（書き込み中のログは、読み始めた時点の最後の行までを入れる）。
`

// passphraseEnv はパスフレーズを渡す環境変数。
const passphraseEnv = "SUSANOO_BACKUP_PASSPHRASE"

func runBackup(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, backupUsage)
		return exitUsage
	}
	switch args[0] {
	case "create":
		return backupCreate(args[1:], stdout, stderr)
	case "verify":
		return backupVerify(args[1:], stdout, stderr)
	case "restore":
		return backupRestore(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, backupUsage)
		return exitOK
	}
	fmt.Fprintf(stderr, "susanoo: 不明な操作です: backup %s\n\n%s", args[0], backupUsage)
	return exitUsage
}

// readPassphrase は、ファイル（最後の改行は除く）か環境変数からパスフレーズを読む。
func readPassphrase(file string) ([]byte, error) {
	if file != "" {
		fi, err := os.Stat(file)
		if err != nil {
			return nil, err
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("パスフレーズのファイル %s をほかの利用者も読めます。chmod 600 にしてください", file)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		return bytes.TrimRight(data, "\r\n"), nil
	}
	return []byte(os.Getenv(passphraseEnv)), nil
}

// gwPaths はバックアップする GW の場所。
type gwPaths struct {
	config, policy, pki, state string
}

func loadGWPaths(path string) (gwPaths, error) {
	var cfg gwConfig
	if err := config.Load(path, &cfg); err != nil {
		return gwPaths{}, err
	}
	if cfg.PKIDir == "" || cfg.StateDir == "" {
		return gwPaths{}, errors.New("設定ファイルに pki_dir と state_dir がありません")
	}
	return gwPaths{config: path, policy: config.Resolve(path, cfg.Policy), pki: config.Resolve(path, cfg.PKIDir), state: config.Resolve(path, cfg.StateDir)}, nil
}

// tempFile は fsutil.WriteFileAtomic の一時ファイルかを返す。
func tempFile(name string) bool {
	return strings.HasPrefix(name, ".") && strings.Contains(name, ".tmp-")
}

// backupEntries はバックアップに入れるファイルを集める。
func backupEntries(p gwPaths, events, evidence bool) ([]backup.Entry, []string, error) {
	entries := []backup.Entry{{Name: "config/gw.json", Path: p.config}}
	if p.policy != "" {
		if _, err := os.Stat(p.policy); err == nil {
			entries = append(entries, backup.Entry{Name: "config/policy.json", Path: p.policy})
		}
	}
	var excluded []string
	walk := func(root, prefix string, skip func(rel string) bool) error {
		return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				if rel != "." && skip(rel) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || tempFile(d.Name()) || skip(rel) {
				return nil
			}
			entries = append(entries, backup.Entry{Name: prefix + rel, Path: path, Log: strings.HasSuffix(rel, ".log") || strings.HasSuffix(rel, ".jsonl") || strings.HasSuffix(rel, ".idx")})
			return nil
		})
	}
	if err := walk(p.pki, "pki/", func(string) bool { return false }); err != nil {
		return nil, nil, err
	}
	if !events {
		excluded = append(excluded, "イベント（state/controller/events。-events で入れる）")
	}
	if !evidence {
		excluded = append(excluded, "証拠（state/controller/evidence。-evidence で入れる）")
	}
	err := walk(p.state, "state/", func(rel string) bool {
		return (!events && rel == "controller/events") || (!evidence && rel == "controller/evidence")
	})
	return entries, excluded, err
}

func backupCreate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("backup create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	cfgPath := flags.String("config", "/etc/susanoo/gw.json", "GW の設定ファイル")
	out := flags.String("out", "", "書き出すファイル（必須）")
	passFile := flags.String("passphrase-file", "", "パスフレーズのファイル（省略すると環境変数 "+passphraseEnv+"）")
	plain := flags.Bool("plain", false, "暗号化しない（秘密鍵がそのまま入るので、勧めない）")
	events := flags.Bool("events", false, "イベントも入れる")
	evidence := flags.Bool("evidence", false, "証拠も入れる")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *out == "" {
		return fail(stderr, errors.New("-out で書き出すファイルを指定してください"))
	}
	pass, err := readPassphrase(*passFile)
	if err != nil {
		return fail(stderr, err)
	}
	if len(pass) == 0 && !*plain {
		return fail(stderr, fmt.Errorf("パスフレーズを -passphrase-file か環境変数 %s で渡してください（暗号化しないなら -plain）", passphraseEnv))
	}
	if *plain {
		pass = nil
		fmt.Fprintln(stderr, "susanoo: 暗号化しません。認証局とポリシーの署名の秘密鍵がそのまま入るので、厳重に保管してください")
	}
	p, err := loadGWPaths(*cfgPath)
	if err != nil {
		return fail(stderr, err)
	}
	entries, excluded, err := backupEntries(p, *events, *evidence)
	if err != nil {
		return fail(stderr, err)
	}
	f, err := os.CreateTemp(filepath.Dir(*out), "."+filepath.Base(*out)+".tmp-*")
	if err != nil {
		return fail(stderr, err)
	}
	tmp := f.Name()
	m, err := backup.Create(f, entries, backup.Options{Passphrase: pass, Plain: *plain, Version: version.Version, Excluded: excluded, Now: time.Now()})
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, *out)
	}
	if err != nil {
		os.Remove(tmp)
		return fail(stderr, err)
	}
	var total int64
	for _, fi := range m.Files {
		total += fi.Size
	}
	fmt.Fprintf(stdout, "バックアップを %s に書き出しました（ファイル %d、%d バイト、暗号化 %s）。\n", *out, len(m.Files), total, map[bool]string{true: "あり", false: "なし"}[m.Encrypted])
	for _, x := range excluded {
		fmt.Fprintf(stdout, "  入れなかったもの: %s\n", x)
	}
	fmt.Fprintln(stdout, "susanoo backup verify で、復号できることを確かめてから、GW とは別の場所に保管してください。")
	return exitOK
}

func openBackup(in, passFile string) (*os.File, []byte, error) {
	if in == "" {
		return nil, nil, errors.New("-in でバックアップのファイルを指定してください")
	}
	pass, err := readPassphrase(passFile)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(in)
	return f, pass, err
}

func backupVerify(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("backup verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	in := flags.String("in", "", "バックアップのファイル（必須）")
	passFile := flags.String("passphrase-file", "", "パスフレーズのファイル（省略すると環境変数 "+passphraseEnv+"）")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	f, pass, err := openBackup(*in, *passFile)
	if err != nil {
		return fail(stderr, err)
	}
	defer f.Close()
	m, err := backup.Extract(f, pass, "")
	if err != nil {
		return fail(stderr, err)
	}
	printManifest(stdout, m)
	fmt.Fprintln(stdout, "すべてのファイルの大きさとハッシュが目録と一致しました。")
	return exitOK
}

func printManifest(w io.Writer, m backup.Manifest) {
	var total int64
	counts := map[string]int{}
	for _, fi := range m.Files {
		total += fi.Size
		counts[strings.SplitN(fi.Name, "/", 2)[0]]++
	}
	fmt.Fprintf(w, "susanoo %s が %s に作ったバックアップ（暗号化 %s）\n", m.Version, m.Created.Local().Format("2006-01-02 15:04:05"), map[bool]string{true: "あり", false: "なし"}[m.Encrypted])
	fmt.Fprintf(w, "ファイル %d（設定 %d、鍵と証明書 %d、状態 %d）、%d バイト\n", len(m.Files), counts["config"], counts["pki"], counts["state"], total)
	for _, x := range m.Excluded {
		fmt.Fprintf(w, "  入れなかったもの: %s\n", x)
	}
}

// runningGW は、設定ファイル path で動いている GW のプロセスの番号を返す（なければ 0）。/proc のコマンドラインで見分ける。
func runningGW(path string) int {
	want, err := filepath.Abs(path)
	if err != nil {
		return 0
	}
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		args := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
		if len(args) < 2 || filepath.Base(args[0]) != "susanoo" || args[1] != "gw" {
			continue
		}
		cfg := "/etc/susanoo/gw.json"
		for i, a := range args[2:] {
			switch {
			case (a == "-config" || a == "--config") && i+3 < len(args):
				cfg = args[i+3]
			case strings.HasPrefix(a, "-config="), strings.HasPrefix(a, "--config="):
				cfg = a[strings.IndexByte(a, '=')+1:]
			}
		}
		if !filepath.IsAbs(cfg) {
			cwd, err := os.Readlink(filepath.Join("/proc", e.Name(), "cwd"))
			if err != nil {
				continue
			}
			cfg = filepath.Join(cwd, cfg)
		}
		if filepath.Clean(cfg) == want {
			return pid
		}
	}
	return 0
}

func backupRestore(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("backup restore", flag.ContinueOnError)
	flags.SetOutput(stderr)
	cfgPath := flags.String("config", "/etc/susanoo/gw.json", "戻す先の GW の設定ファイル（鍵と状態の場所は、戻した設定ファイルから決める）")
	in := flags.String("in", "", "バックアップのファイル（必須）")
	passFile := flags.String("passphrase-file", "", "パスフレーズのファイル（省略すると環境変数 "+passphraseEnv+"）")
	force := flags.Bool("force", false, "戻す先に今の設定や状態があれば、名前に .before-restore-<時刻> を付けて退かしてから戻す")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if pid := runningGW(*cfgPath); pid != 0 {
		return fail(stderr, fmt.Errorf("この設定ファイルの GW が動いています（PID %d）。止めてから戻してください", pid))
	}
	f, pass, err := openBackup(*in, *passFile)
	if err != nil {
		return fail(stderr, err)
	}
	defer f.Close()
	dir := filepath.Dir(*cfgPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail(stderr, err)
	}
	stage, err := os.MkdirTemp(dir, ".susanoo-restore-*")
	if err != nil {
		return fail(stderr, err)
	}
	defer os.RemoveAll(stage)
	m, err := backup.Extract(f, pass, stage)
	if err != nil {
		return fail(stderr, err)
	}
	// 鍵と状態の場所は、戻す設定ファイルから決める（相対パスなら、戻す先の設定ファイルのディレクトリから）。
	var cfg gwConfig
	if err := config.Load(filepath.Join(stage, "config", "gw.json"), &cfg); err != nil || cfg.PKIDir == "" || cfg.StateDir == "" {
		return fail(stderr, fmt.Errorf("バックアップの設定ファイルを読めません: %v", err))
	}
	dst := gwPaths{config: *cfgPath, policy: config.Resolve(*cfgPath, cfg.Policy), pki: config.Resolve(*cfgPath, cfg.PKIDir), state: config.Resolve(*cfgPath, cfg.StateDir)}
	var present []string
	for _, p := range []string{dst.config, dst.policy, dst.pki, dst.state} {
		if p == "" {
			continue
		}
		if _, err := os.Lstat(p); err == nil {
			present = append(present, p)
		}
	}
	if len(present) > 0 && !*force {
		return fail(stderr, fmt.Errorf("戻す先に今の設定か状態があります（%s）。-force を付けると、退かしてから戻します", strings.Join(present, "、")))
	}
	suffix := ".before-restore-" + time.Now().Format("20060102-150405")
	for _, p := range present {
		if err := os.Rename(p, p+suffix); err != nil {
			return fail(stderr, fmt.Errorf("%s を退かせません: %w", p, err))
		}
		fmt.Fprintf(stdout, "今の %s を %s に退かしました。\n", p, p+suffix)
	}
	for _, fi := range m.Files {
		var target string
		switch {
		case fi.Name == "config/gw.json":
			target = dst.config
		case fi.Name == "config/policy.json":
			target = dst.policy
		case strings.HasPrefix(fi.Name, "pki/"):
			target = filepath.Join(dst.pki, filepath.FromSlash(strings.TrimPrefix(fi.Name, "pki/")))
		case strings.HasPrefix(fi.Name, "state/"):
			target = filepath.Join(dst.state, filepath.FromSlash(strings.TrimPrefix(fi.Name, "state/")))
		default:
			continue
		}
		if target == "" {
			continue
		}
		if err := moveFile(filepath.Join(stage, filepath.FromSlash(fi.Name)), target, os.FileMode(fi.Mode)); err != nil {
			return fail(stderr, err)
		}
	}
	printManifest(stdout, m)
	fmt.Fprintf(stdout, "バックアップを戻しました（設定 %s、鍵 %s、状態 %s）。GW を起動すると、状態のディレクトリの持ち主を整えます。\n", dst.config, dst.pki, dst.state)
	return exitOK
}

// moveFile は src を dst に移す（同じファイルシステムなら名前を変え、違えば写す）。
func moveFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	err := os.Rename(src, dst)
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
