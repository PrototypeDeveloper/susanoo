package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"text/tabwriter"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/fsutil"
)

// 証拠の保全（C11）と通知（M7）の操作。

const ctlEvidenceUsage = `使い方: susanoo ctl evidence <操作> [オプション]

操作:
  list     保存した証拠の一覧を表示する（例: susanoo ctl evidence list -device pc-001）
  show     証拠の中身の要点を表示する（例: susanoo ctl evidence show pc-001 <ID>）。
           -json で中身をすべて表示し、-out <ファイル> で端末の署名付きのまま保存する（ほかの場所に保管するため）
  collect  端末に証拠を集めさせる（例: susanoo ctl evidence collect pc-001）。隔離しなくても集められる

証拠は、隔離の指示を受けた端末の CLIENT が自動で集める（プロセスの一覧、接続と持ち主のプロセス、カーネルモジュール、ログの末尾）。
`

const ctlNotifyUsage = `使い方: susanoo ctl notify test

  test  試験の通知を、設定したすべての宛先に送り、結果を表示する（宛先は GW の設定ファイルの notify に書く）
`

func ctlEvidence(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, ctlEvidenceUsage)
		return exitUsage
	}
	switch args[0] {
	case "list":
		return ctlEvidenceList(args[1:], stdout, stderr)
	case "show":
		return ctlEvidenceShow(args[1:], stdout, stderr)
	case "collect":
		return ctlEvidenceCollect(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, ctlEvidenceUsage)
		return exitOK
	}
	fmt.Fprintf(stderr, "susanoo: 不明な操作です: ctl evidence %s\n\n%s", args[0], ctlEvidenceUsage)
	return exitUsage
}

var evidenceReasons = map[string]string{api.EvidenceReasonIsolation: "隔離", api.EvidenceReasonRequest: "管理者の求め"}

func ctlEvidenceList(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl evidence list", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	device := flags.String("device", "", "端末 ID")
	asJSON := flags.Bool("json", false, "JSON で表示する")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	path := api.PathEvidence
	if *device != "" {
		path += "?device=" + url.QueryEscape(*device)
	}
	var list []api.EvidenceInfo
	if err := c.do(http.MethodGet, path, nil, &list); err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(list)
		return exitOK
	}
	if len(list) == 0 {
		fmt.Fprintln(stdout, "保存した証拠はありません。")
		return exitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "端末\tID\t集めた時刻\tきっかけ\tプロセス\t接続\tログ\tバイト")
	for _, e := range list {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\n", e.Device, e.ID, e.Time.Local().Format(timeFormat),
			evidenceReasons[e.Reason], e.Processes, e.Connections, e.Logs, e.Bytes)
	}
	tw.Flush()
	return exitOK
}

// twoArgs はオプションの前に書いた 2 つの引数（端末と ID）を取り出す。
func twoArgs(args []string) (string, string, []string) {
	var pos []string
	for len(args) > 0 && !strings.HasPrefix(args[0], "-") && len(pos) < 2 {
		pos, args = append(pos, args[0]), args[1:]
	}
	for len(pos) < 2 {
		pos = append(pos, "")
	}
	return pos[0], pos[1], args
}

func ctlEvidenceShow(args []string, stdout, stderr io.Writer) int {
	device, id, rest := twoArgs(args)
	flags := flag.NewFlagSet("ctl evidence show", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	asJSON := flags.Bool("json", false, "中身をすべて JSON で表示する")
	out := flags.String("out", "", "端末の署名付きのまま、このファイルに保存する")
	if err := flags.Parse(rest); err != nil {
		return exitUsage
	}
	if device == "" || id == "" {
		return fail(stderr, errors.New("端末 ID と証拠の ID を指定してください（ctl evidence list で確かめられます）"))
	}
	path := api.PathEvidence + "/" + url.PathEscape(device) + "/" + url.PathEscape(id)
	if *out != "" {
		var raw json.RawMessage
		if err := c.doLimit(http.MethodGet, path+"?signed=1", nil, &raw, api.MaxEvidenceBytes, time.Minute); err != nil {
			return fail(stderr, err)
		}
		if err := fsutil.WriteFileAtomic(*out, append(raw, '\n'), 0o600); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "証拠を端末の署名付きのまま %s に保存しました。\n", *out)
		return exitOK
	}
	var raw json.RawMessage
	if err := c.doLimit(http.MethodGet, path, nil, &raw, api.MaxEvidenceBytes, time.Minute); err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		var v any
		json.Unmarshal(raw, &v)
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(v)
		return exitOK
	}
	var ev api.Evidence
	if err := json.Unmarshal(raw, &ev); err != nil {
		return fail(stderr, err)
	}
	printEvidence(stdout, ev)
	return exitOK
}

// printEvidence は証拠の要点（外への接続、待ち受け、一時的な場所のプログラムなど）を表示する。
func printEvidence(w io.Writer, ev api.Evidence) {
	s := ev.Snapshot
	fmt.Fprintf(w, "端末 %s（%s）の証拠 %s\n", ev.DeviceID, dash(ev.Hostname), ev.ID)
	fmt.Fprintf(w, "集めた時刻 %s、きっかけ %s（指示の版 %d、隔離 %s）\n", ev.Time.Local().Format("2006-01-02 15:04:05"),
		evidenceReasons[ev.Reason], ev.Command, dash(string(ev.Isolation)))
	fmt.Fprintf(w, "プロセス %d、接続 %d、カーネルモジュール %d、ログ %d\n", len(s.Processes), len(s.Connections), len(s.Modules), len(s.Logs))
	for _, e := range s.Errors {
		fmt.Fprintf(w, "  集められなかったもの: %s\n", e)
	}
	var outbound, listening []string
	for _, c := range s.Connections {
		owner := fmt.Sprintf("%s（PID %d）", dash(c.Process), c.PID)
		switch {
		case c.State == "listen" || c.State == "bound":
			listening = append(listening, fmt.Sprintf("  %s %s\t%s", c.Proto, c.Local, owner))
		case c.Remote != "":
			outbound = append(outbound, fmt.Sprintf("  %s %s → %s\t%s\t%s", c.Proto, c.Local, c.Remote, c.State, owner))
		}
	}
	section := func(title string, lines []string) {
		if len(lines) == 0 {
			return
		}
		fmt.Fprintf(w, "\n%s:\n", title)
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, l := range lines {
			fmt.Fprintln(tw, l)
		}
		tw.Flush()
	}
	section("接続", outbound)
	section("待ち受け", listening)
	var temp []string
	for _, p := range s.Processes {
		for _, dir := range []string{"/tmp/", "/var/tmp/", "/dev/shm/"} {
			if strings.HasPrefix(p.Exe, dir) {
				temp = append(temp, fmt.Sprintf("  PID %d\t%s\t%s", p.PID, p.Exe, oneLine(p.CmdLine)))
			}
		}
	}
	section("一時的な場所から動いているプログラム", temp)
	for _, l := range s.Logs {
		fmt.Fprintf(w, "\nログ %s（末尾 %d 行）\n", l.Path, len(l.Lines))
	}
	fmt.Fprintln(w, "\nすべての中身は -json で表示できます。")
}

func ctlEvidenceCollect(args []string, stdout, stderr io.Writer) int {
	device, _, rest := twoArgs(args)
	flags := flag.NewFlagSet("ctl evidence collect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	if err := flags.Parse(rest); err != nil {
		return exitUsage
	}
	if device == "" {
		return fail(stderr, errors.New("端末 ID を指定してください"))
	}
	var d api.Device
	if err := c.do(http.MethodPost, api.PathDevices+"/"+url.PathEscape(device)+"/evidence", nil, &d); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "端末 %s に証拠を集めさせます。次のハートビートで指示が届き、集め終わると ctl evidence list -device %s に載ります。\n", d.ID, d.ID)
	return exitOK
}

func ctlNotify(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "test" {
		fmt.Fprint(stderr, ctlNotifyUsage)
		return exitUsage
	}
	flags := flag.NewFlagSet("ctl notify test", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	asJSON := flags.Bool("json", false, "JSON で表示する")
	if err := flags.Parse(args[1:]); err != nil {
		return exitUsage
	}
	var res []api.NotifyResult
	if err := c.doLimit(http.MethodPost, api.PathNotifyTest, nil, &res, api.MaxBodyBytes, 40*time.Second); err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		json.NewEncoder(stdout).Encode(res)
	}
	failed := 0
	for _, r := range res {
		if r.Error != "" {
			failed++
		}
		if !*asJSON {
			if r.Error == "" {
				fmt.Fprintf(stdout, "%s: 送りました\n", r.Name)
			} else {
				fmt.Fprintf(stdout, "%s: 送れません（%s）\n", r.Name, r.Error)
			}
		}
	}
	if failed > 0 {
		return exitError
	}
	return exitOK
}
