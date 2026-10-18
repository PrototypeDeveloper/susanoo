// Command susanoo は統合防御システムの実行ファイル。最初の引数でモードを選んで起動する。
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"susanoo/internal/version"
)

const usage = `使い方: susanoo <モード> [オプション]

モード:
  gw           GWモード（すべての通信が通る関所）で起動する。CONTROLLERを同居させる
  client       CLIENTモード（端末の監視）で起動する
  client keygen  端末の鍵を作る
  ctl init     CONTROLLERの認証局と鍵を作る
  ctl issue    端末の証明書を発行する
  ctl status   全体の状態を表示する
  ctl devices  端末の一覧を表示する
  ctl events   保存したイベントを検索する
  ctl isolate  端末を隔離する
  ctl release  端末の隔離を解除する
  ctl policy   ポリシーを署名して配布する（「susanoo ctl」でほかの操作も表示する）
  version      版数を表示する
  help         この説明を表示する

各モードのオプションは「susanoo <モード> -h」で表示する。
`

// 終了コード。
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch mode := args[0]; mode {
	case "version":
		fmt.Fprintln(stdout, "susanoo", version.Version)
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	case "gw":
		if len(args) > 1 && args[1] == "controller" {
			return runGWController(stderr) // 執行部が起動する CONTROLLER（使い方には載せない）
		}
		if len(args) > 1 && args[1] == "lan" {
			return runGWLAN(stderr) // 執行部が起動する LAN 側の処理（使い方には載せない）
		}
		return runGW(ctx, args[1:], stderr)
	case "client":
		if len(args) > 1 && args[1] == "keygen" {
			return runKeygen(args[2:], stdout, stderr)
		}
		if len(args) > 1 && args[1] == "analyzer" {
			return runAnalyzer(stderr) // 執行部が起動する解析部（使い方には載せない）
		}
		return runClient(ctx, args[1:], stderr)
	case "ctl":
		return runCtl(args[1:], stdout, stderr)
	case "controller":
		fmt.Fprintln(stderr, "susanoo: CONTROLLER は今は GW に同居させて動かします。「susanoo gw」で起動してください")
		return exitError
	default:
		fmt.Fprintf(stderr, "susanoo: 不明なモードです: %s\n\n%s", mode, usage)
		return exitUsage
	}
}

func newLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// fail はエラーを表示して終了コードを返す。
func fail(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "susanoo:", err)
	return exitError
}
