package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/audit"
	"susanoo/internal/fsutil"
	"susanoo/internal/keys"
	"susanoo/internal/pki"
	"susanoo/internal/policy"
	"susanoo/internal/transport"
)

const ctlUsage = `使い方: susanoo ctl <操作> [オプション]

操作:
  init     CONTROLLERの認証局、署名の鍵、証明書を作る（-two-tier と -issuer で、ルートの認証局を GW の外に置く二段構えにする）
  root     二段構えのルートの認証局を、管理者の手元で作る・使う（susanoo ctl root で説明を表示）
  enroll   一回限りの登録コードを作る・一覧する・取り消す（例: susanoo ctl enroll create pc-001）。端末は client enroll で登録する
  issue    端末の公開鍵に証明書を発行し、端末に配るファイルを書き出す
  status   全体の状態（ポリシー、端末と機器の台数、危険度の高い端末、証明書の期限が近い端末、最近の検知）を表示する
  devices  端末の一覧を表示する
  hosts    LAN の機器の一覧を表示する（CLIENT のない機器を含む）
  isolate  端末か機器を隔離する（例: susanoo ctl isolate pc-001 -level full、susanoo ctl isolate 02:00:00:00:00:01）
  release  端末か機器の隔離を解除する（例: susanoo ctl release pc-001）
  revoke   端末の証明書を失効させ、端末を隔離する（例: susanoo ctl revoke pc-001）。入れ直すときは issue で発行し直す
  policy   ポリシーを署名して配布する、版を一覧する、先行適用を全体に広げる・取り消す、過去の版に戻す（susanoo ctl policy で説明を表示）
  rules    検知ルールを署名して配布する、版を一覧する、過去の版に戻す、当てはまった回数を表示する（susanoo ctl rules で説明を表示）
  intel    脅威情報の一覧のファイルを取り込んで署名して配布する、一覧を消す、照合する（susanoo ctl intel で説明を表示）
  group    端末か機器のグループを変える（例: susanoo ctl group pc-001 server）
  learned  学習モードで通した名前と、遮断した名前を表示する。learned suggest で、学習した名前から許可リストを作り、
           グループを原則拒否にしたポリシーの案を書き出す（例: susanoo ctl learned suggest -group default -out policy.json）
  audit    監査ログの連鎖を確かめ、記録を表示する
  events   保存したイベントを検索する（例: susanoo ctl events -device pc-001 -class finding -since 24h）
  evidence 端末の証拠（隔離のときに CLIENT が集めたもの）を一覧する、表示する、集めさせる（susanoo ctl evidence で説明を表示）
  notify   試験の通知を送る（例: susanoo ctl notify test）
  incident インシデントを開く、手順と報告の期限を管理する、時系列と報告書を作る（susanoo ctl incident で説明を表示）
  apps     プロセス単位の通信の制御で拒否した接続を、プログラムと宛先ごとにまとめる（例: susanoo ctl apps learned -since 24h）
`

const defaultCtlDir = "/etc/susanoo/controller"

func runCtl(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, ctlUsage)
		return exitUsage
	}
	switch args[0] {
	case "init":
		return ctlInit(args[1:], stdout, stderr)
	case "issue":
		return ctlIssue(args[1:], stdout, stderr)
	case "root":
		return ctlRoot(args[1:], stdout, stderr)
	case "enroll":
		return ctlEnroll(args[1:], stdout, stderr)
	case "status":
		return ctlStatus(args[1:], stdout, stderr)
	case "events":
		return ctlEvents(args[1:], stdout, stderr)
	case "devices":
		return ctlDevices(args[1:], stdout, stderr)
	case "hosts":
		return ctlHosts(args[1:], stdout, stderr)
	case "isolate":
		return ctlChange(args[1:], "isolate", stdout, stderr)
	case "release":
		return ctlChange(args[1:], "release", stdout, stderr)
	case "revoke":
		return ctlChange(args[1:], "revoke", stdout, stderr)
	case "audit":
		return ctlAudit(args[1:], stdout, stderr)
	case "group":
		return ctlGroup(args[1:], stdout, stderr)
	case "learned":
		return ctlLearned(args[1:], stdout, stderr)
	case "policy":
		return ctlPolicy(args[1:], stdout, stderr)
	case "rules":
		return ctlRules(args[1:], stdout, stderr)
	case "intel":
		return ctlIntel(args[1:], stdout, stderr)
	case "evidence":
		return ctlEvidence(args[1:], stdout, stderr)
	case "notify":
		return ctlNotify(args[1:], stdout, stderr)
	case "incident":
		return ctlIncident(args[1:], stdout, stderr)
	case "apps":
		return ctlApps(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, ctlUsage)
		return exitOK
	}
	fmt.Fprintf(stderr, "susanoo: 不明な操作です: ctl %s\n\n%s", args[0], ctlUsage)
	return exitUsage
}

func ctlInit(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", defaultCtlDir, "認証局と鍵を置くディレクトリ")
	name := flags.String("name", "susanoo 内部認証局", "認証局の名前")
	twoTier := flags.Bool("two-tier", false, "二段構え: GW の発行用の認証局の鍵だけを作る（公開鍵を管理者が ctl root sign-issuer で署名する）")
	issuerDir := flags.String("issuer", "", "二段構え: ctl root sign-issuer の書き出したディレクトリから署名を受け取り、CONTROLLER の証明書を作る")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	switch {
	case *twoTier && *issuerDir != "":
		return fail(stderr, errors.New("-two-tier と -issuer は別々に実行してください"))
	case *twoTier:
		if err := ctlInitIssuerKey(*dir, stdout); err != nil {
			return fail(stderr, err)
		}
		return exitOK
	case *issuerDir != "":
		if err := ctlInitIssuer(*dir, *issuerDir, stdout); err != nil {
			return fail(stderr, err)
		}
		return exitOK
	}
	for _, f := range []string{fileCAKey, pki.IssuerKeyFile} {
		if _, err := os.Stat(filepath.Join(*dir, f)); !errors.Is(err, fs.ErrNotExist) {
			return fail(stderr, fmt.Errorf("%s には既に認証局があります", *dir))
		}
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return fail(stderr, err)
	}
	now := time.Now()
	ca, err := pki.NewCA(*name, now)
	if err != nil {
		return fail(stderr, err)
	}
	if err := ca.Save(*dir); err != nil {
		return fail(stderr, err)
	}
	signKey, err := keys.Generate()
	if err != nil {
		return fail(stderr, err)
	}
	if err := keys.SavePrivate(filepath.Join(*dir, fileSignKey), signKey); err != nil {
		return fail(stderr, err)
	}
	if err := keys.SavePublic(filepath.Join(*dir, fileSignPub), signKey.Public().(ed25519.PublicKey)); err != nil {
		return fail(stderr, err)
	}
	if err := createPolicyKey(*dir); err != nil {
		return fail(stderr, err)
	}
	for _, leaf := range []struct {
		id        pki.Identity
		cert, key string
	}{
		{pki.Identity{Role: pki.RoleController, ID: "main"}, fileControllerCert, fileControllerKey},
		{pki.Identity{Role: pki.RoleAdmin, ID: "admin"}, fileAdminCert, fileAdminKey},
	} {
		c, err := ca.NewLeaf(leaf.id, now)
		if err != nil {
			return fail(stderr, err)
		}
		if err := pki.WriteCertFile(filepath.Join(*dir, leaf.cert), c.Leaf); err != nil {
			return fail(stderr, err)
		}
		if err := keys.SavePrivate(filepath.Join(*dir, leaf.key), c.PrivateKey.(ed25519.PrivateKey)); err != nil {
			return fail(stderr, err)
		}
	}
	fmt.Fprintf(stdout, "%s に認証局、署名の鍵、ポリシーの署名の鍵、CONTROLLER と管理者の証明書を作りました。\n"+
		"%s、%s、%s は外に出さないでください。\n", *dir, fileCAKey, fileSignKey, filePolicyKey)
	return exitOK
}

func ctlIssue(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl issue", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", defaultCtlDir, "ctl init で作ったディレクトリ")
	id := flags.String("id", "", "端末 ID（英小文字、数字、「.」「_」「-」）")
	pubPath := flags.String("pub", "", "端末の公開鍵（client keygen で作った client.pub）")
	out := flags.String("out", "", "端末に配るファイルを書き出すディレクトリ")
	validity := flags.Duration("validity", pki.LeafValidity, "証明書の有効期間（90 日まで。試験で短い証明書を作るときに使う）")
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
	pub, err := keys.LoadPublic(*pubPath)
	if err != nil {
		return fail(stderr, err)
	}
	cert, err := ca.IssueFor(pub, pki.Identity{Role: pki.RoleClient, ID: *id}, time.Now(), *validity)
	if err != nil {
		return fail(stderr, err)
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return fail(stderr, err)
	}
	if err := pki.WriteChainFile(filepath.Join(*out, fileClientCert), ca.ChainOf(cert)...); err != nil {
		return fail(stderr, err)
	}
	if err := pki.WriteCertFile(filepath.Join(*out, fileCACert), ca.Root); err != nil {
		return fail(stderr, err)
	}
	signPub, err := os.ReadFile(filepath.Join(*dir, fileSignPub))
	if err != nil {
		return fail(stderr, err)
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(*out, fileCommandPub), signPub, 0o644); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "端末 %s の証明書を発行しました（有効期限 %s）。\n%s の %s、%s、%s を、端末の鍵のディレクトリに置いてください。\n",
		*id, cert.NotAfter.Local().Format("2006-01-02"), *out, fileCACert, fileClientCert, fileCommandPub)
	return exitOK
}

// ctlFlags は API を使う操作に共通のオプション。
type ctlFlags struct {
	dir, server string
}

func (c *ctlFlags) register(flags *flag.FlagSet) {
	flags.StringVar(&c.dir, "dir", defaultCtlDir, "管理者の証明書（admin.crt）のあるディレクトリ")
	flags.StringVar(&c.server, "server", "127.0.0.1:8443", "CONTROLLER のアドレスとポート")
}

func (c *ctlFlags) do(method, path string, body, out any) error {
	return c.doLimit(method, path, body, out, api.MaxBodyBytes, 15*time.Second)
}

// doLimit は do と同じだが、応答の大きさの上限と、待つ時間を指定する（脅威情報の一覧など、大きなものに使う）。
func (c *ctlFlags) doLimit(method, path string, body, out any, limit int64, timeout time.Duration) error {
	pool, err := loadPool(c.dir)
	if err != nil {
		return err
	}
	cert, err := loadLeaf(c.dir, fileAdminCert, fileAdminKey)
	if err != nil {
		return err
	}
	tr := &http.Transport{TLSClientConfig: transport.ClientConfig(pool, cert, pki.RoleController), ForceAttemptHTTP2: true}
	defer tr.CloseIdleConnections()
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, "https://"+c.server+path, r)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Transport: tr, Timeout: timeout}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e api.Error
		json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e)
		return fmt.Errorf("%s: %s", resp.Status, e.Error)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(out)
}

func ctlDevices(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl devices", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	asJSON := flags.Bool("json", false, "JSON で表示する")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	var list []api.Device
	if err := c.do(http.MethodGet, api.PathDevices, nil, &list); err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(list)
		return exitOK
	}
	printDevices(stdout, list...)
	return exitOK
}

func printDevices(w io.Writer, list ...api.Device) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "端末\tグループ\tアドレス\tMAC\t最終接続\t状態\t危険度\t隔離\t理由\t承認待ち\t自己隔離\t証明書の期限")
	for _, d := range list {
		state := "-"
		if d.Away {
			state = "不在"
		}
		if !d.Revoked.IsZero() {
			state = "失効"
		}
		expiry := "-"
		if !d.CertExpiry.IsZero() {
			expiry = d.CertExpiry.Local().Format("2006-01-02")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
			d.ID, d.Group, dash(d.Addr), dash(strings.Join(d.MACs, ",")), d.LastSeen.Local().Format("01-02 15:04:05"), state, d.Risk,
			dash(string(d.Isolation)), dash(d.Reason), dash(d.Pending), dash(string(d.Applied)), expiry)
	}
	tw.Flush()
}

func ctlHosts(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl hosts", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	asJSON := flags.Bool("json", false, "JSON で表示する")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	var list []api.Host
	if err := c.do(http.MethodGet, api.PathHosts, nil, &list); err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(list)
		return exitOK
	}
	printHosts(stdout, list...)
	return exitOK
}

func printHosts(w io.Writer, list ...api.Host) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "MAC\tアドレス\tIPv6\tホスト名\t端末\t最終確認\t割り当て期限\t危険度\t隔離\t理由\t承認待ち")
	for _, h := range list {
		device := h.DeviceID
		if device == "" {
			device = "未登録"
		}
		lease := "-"
		if !h.Lease.IsZero() {
			lease = h.Lease.Local().Format("01-02 15:04:05")
		}
		v6 := strings.Join(h.IPv6, ",")
		if len(h.IPv6) > 2 {
			v6 = strings.Join(h.IPv6[len(h.IPv6)-2:], ",") + fmt.Sprintf("（ほか %d）", len(h.IPv6)-2)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
			h.MAC, dash(h.IP), dash(v6), dash(h.Hostname), device, h.LastSeen.Local().Format("01-02 15:04:05"), lease, h.Risk,
			dash(string(h.Isolation)), dash(h.Reason), dash(h.Pending))
	}
	tw.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ctlChange は隔離（op が isolate）と解除（release）を行う。対象は端末 ID か機器の MAC アドレスで、
// オプションの前後どちらにも書ける。
func ctlChange(args []string, op string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl "+op, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	var req api.IsolateRequest
	if op == "isolate" {
		flags.Func("level", "隔離の段階（full、management、management_and_updates）。省略するとポリシーに従う", func(s string) error {
			req.Level = policy.IsolationLevel(s)
			return nil
		})
		flags.StringVar(&req.Reason, "reason", "", "隔離の理由")
	}
	var id string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id, args = args[0], args[1:]
	}
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if id == "" {
		id = flags.Arg(0)
	}
	if id == "" {
		return fail(stderr, errors.New("端末 ID か MAC アドレスを指定してください"))
	}
	if op == "revoke" {
		var d api.Device
		if err := c.do(http.MethodPost, api.PathDevices+"/"+url.PathEscape(id)+"/revoke", nil, &d); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "端末 %s の証明書を失効させました。入れ直すときは ctl issue で証明書を発行し直してから、ctl release で隔離を解除してください。\n", d.ID)
		printDevices(stdout, d)
		return exitOK
	}
	var body any
	if op == "isolate" {
		body = req
	}
	if hw, err := net.ParseMAC(id); err == nil && len(hw) == 6 {
		var h api.Host
		if err := c.do(http.MethodPost, api.PathHosts+"/"+hw.String()+"/"+op, body, &h); err != nil {
			return fail(stderr, err)
		}
		printHosts(stdout, h)
		return exitOK
	}
	var d api.Device
	if err := c.do(http.MethodPost, api.PathDevices+"/"+url.PathEscape(id)+"/"+op, body, &d); err != nil {
		return fail(stderr, err)
	}
	printDevices(stdout, d)
	return exitOK
}

// ctlAudit は監査ログの連鎖を確かめ、記録を表示する。連鎖が壊れていたら終了コード 1 で終わる。
func ctlAudit(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl audit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("file", "/var/lib/susanoo/gw/audit.log", "監査ログのファイル")
	asJSON := flags.Bool("json", false, "記録を JSON で表示する")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	data, err := os.ReadFile(*path)
	if err != nil {
		return fail(stderr, err)
	}
	head, err := audit.Verify(bytes.NewReader(data))
	if err != nil {
		return fail(stderr, fmt.Errorf("監査ログの連鎖が壊れています: %w", err))
	}
	records := []audit.Record{}
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r audit.Record
		if err := json.Unmarshal(line, &r); err != nil {
			return fail(stderr, err)
		}
		records = append(records, r)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(records)
		return exitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "番号\t時刻\t主体\t操作\t対象\t詳細")
	for _, r := range records {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n", r.Seq, r.Time.Local().Format("2006-01-02 15:04:05"), r.Actor, r.Action, dash(r.Target), dash(string(r.Detail)))
	}
	tw.Flush()
	fmt.Fprintf(stdout, "連鎖を確認しました（%d 件、末尾のハッシュ %s）\n", head.Seq, head.Hash)
	return exitOK
}

// ctlGroup は端末か機器（MAC アドレス）のグループを変える。対象とグループはオプションの前後どちらにも書ける。
func ctlGroup(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ctl group", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	var pos []string
	for len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		pos, args = append(pos, args[0]), args[1:]
	}
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	pos = append(pos, flags.Args()...)
	if len(pos) != 2 {
		return fail(stderr, errors.New("端末 ID か MAC アドレスと、グループを指定してください（例: susanoo ctl group pc-001 server）"))
	}
	req := api.GroupRequest{Group: pos[1]}
	if hw, err := net.ParseMAC(pos[0]); err == nil && len(hw) == 6 {
		var h api.Host
		if err := c.do(http.MethodPost, api.PathHosts+"/"+hw.String()+"/group", req, &h); err != nil {
			return fail(stderr, err)
		}
		printHosts(stdout, h)
		return exitOK
	}
	var d api.Device
	if err := c.do(http.MethodPost, api.PathDevices+"/"+url.PathEscape(pos[0])+"/group", req, &d); err != nil {
		return fail(stderr, err)
	}
	printDevices(stdout, d)
	return exitOK
}

func ctlLearned(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "suggest" {
		return ctlLearnedSuggest(args[1:], stdout, stderr)
	}
	flags := flag.NewFlagSet("ctl learned", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c ctlFlags
	c.register(flags)
	group := flags.String("group", "", "このグループの記録だけを表示する")
	blocked := flags.Bool("blocked", false, "遮断した名前だけを表示する")
	asJSON := flags.Bool("json", false, "JSON で表示する")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	var list []api.Learned
	if err := c.do(http.MethodGet, api.PathLearned, nil, &list); err != nil {
		return fail(stderr, err)
	}
	list = slices.DeleteFunc(list, func(l api.Learned) bool {
		return (*group != "" && l.Group != *group) || (*blocked && !l.Blocked)
	})
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(list)
		return exitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "グループ\t名前\t扱い\t回数\t最初\t最後")
	for _, l := range list {
		kind := "学習"
		if l.Blocked {
			kind = "遮断"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n", l.Group, l.Domain, kind, l.Count,
			l.First.Local().Format("01-02 15:04"), l.Last.Local().Format("01-02 15:04"))
	}
	tw.Flush()
	return exitOK
}
