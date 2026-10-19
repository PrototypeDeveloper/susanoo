package main

import (
	"debug/buildinfo"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"susanoo/internal/fsutil"
	"susanoo/internal/sbom"
	"susanoo/internal/version"
)

// productLicense は susanoo のライセンス（SPDX の識別子。LICENSE のもの）。
const productLicense = "Apache-2.0"

// runSBOM は、実行ファイルの SBOM（SPDX 2.3 の JSON）を書き出す（2n）。部品は実行ファイルに埋め込まれたビルドの情報から読む。
// 既定ではこの実行ファイルのものを書き、-bin でほかの CPU 向けにビルドした実行ファイルのものも書ける（版数は -version。
// -trimpath でビルドすると、-ldflags で埋め込んだ版数はビルドの情報に残らないため）。
func runSBOM(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sbom", flag.ContinueOnError)
	flags.SetOutput(stderr)
	out := flags.String("o", "", "書き出すファイル（省略すると画面に表示する）")
	bin := flags.String("bin", "", "SBOM を作る実行ファイル（省略するとこの実行ファイル）")
	ver := flags.String("version", version.Version, "製品の版数（-bin のとき。省略するとこの実行ファイルの版数）")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	path := *bin
	var bi *debug.BuildInfo
	var err error
	if path == "" {
		var ok bool
		if bi, ok = debug.ReadBuildInfo(); !ok {
			return fail(stderr, errors.New("この実行ファイルにはビルドの情報がありません"))
		}
		path, _ = os.Executable()
	} else if bi, err = buildinfo.ReadFile(path); err != nil {
		return fail(stderr, fmt.Errorf("%s のビルドの情報を読めません: %w", path, err))
	}
	opts := sbom.Options{Name: "susanoo", Version: *ver, License: productLicense, ToolName: "susanoo sbom"}
	if path != "" {
		if _, sum, err := fileDigest(path); err == nil {
			opts.SHA256 = sum
		}
	}
	data, err := sbom.Generate(bi, opts)
	if err != nil {
		return fail(stderr, err)
	}
	if *out == "" {
		stdout.Write(data)
		return exitOK
	}
	if err := fsutil.WriteFileAtomic(*out, data, 0o644); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "SBOM（SPDX 2.3）を %s に書き出しました。\n", *out)
	return exitOK
}
