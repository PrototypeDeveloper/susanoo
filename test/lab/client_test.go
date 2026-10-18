//go:build lab

package lab

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func init() {
	extraHelpers["hook"] = hookServe
	extraHelpers["smtp"] = smtpServe
}

// hookServe は偽の webhook の受け口（アドレス:ファイル）。受け取った POST の本文を、1 行ずつファイルに足す。
func hookServe(arg string) int {
	i := strings.LastIndex(arg, ":")
	addr, file := arg[:i], arg[i+1:]
	var mu sync.Mutex
	err := http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var line bytes.Buffer
		if json.Compact(&line, b) != nil {
			line.Reset()
			line.WriteString(strings.ReplaceAll(string(b), "\n", " "))
		}
		mu.Lock()
		defer mu.Unlock()
		if f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			f.Write(append(line.Bytes(), '\n'))
			f.Close()
		}
	}))
	fmt.Fprintln(os.Stderr, err)
	return 1
}

// smtpServe は偽の SMTP サーバー（アドレス:ファイル）。受け取ったメールの題名（RFC 2047 を戻したもの）と本文（base64 を戻したもの）を
// ファイルに足す。STARTTLS と認証は扱わない。
func smtpServe(arg string) int {
	i := strings.LastIndex(arg, ":")
	addr, file := arg[:i], arg[i+1:]
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var mu sync.Mutex
	for {
		c, err := ln.Accept()
		if err != nil {
			return 1
		}
		go func() {
			defer c.Close()
			r := bufio.NewReader(c)
			reply := func(s string) { io.WriteString(c, s+"\r\n") }
			reply("220 lab ESMTP")
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
				case strings.HasPrefix(cmd, "EHLO"):
					reply("250-lab")
					reply("250 8BITMIME")
				case cmd == "DATA":
					reply("354 go")
					var msg strings.Builder
					for {
						l, err := r.ReadString('\n')
						if err != nil || l == ".\r\n" {
							break
						}
						msg.WriteString(l)
					}
					head, body, _ := strings.Cut(msg.String(), "\r\n\r\n")
					var out strings.Builder
					for _, h := range strings.Split(head, "\r\n") {
						if v, ok := strings.CutPrefix(h, "Subject: "); ok {
							subject, _ := new(mime.WordDecoder).DecodeHeader(v)
							out.WriteString("Subject: " + subject + "\n")
						}
					}
					text, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(body, "\r\n", ""))
					out.WriteString(strings.ReplaceAll(string(text), "\r\n", "\n") + "\n----\n")
					mu.Lock()
					if f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
						f.WriteString(out.String())
						f.Close()
					}
					mu.Unlock()
					reply("250 queued")
				case cmd == "QUIT":
					reply("221 bye")
					return
				default:
					reply("250 ok")
				}
			}
		}()
	}
}

// fileHas は、ファイルがすべての文字列を含む行（区切りが sep のまとまり）を持つかを返す。
func fileHas(path, sep string, parts ...string) bool {
	data, _ := os.ReadFile(path)
	for _, chunk := range strings.Split(string(data), sep) {
		ok := chunk != ""
		for _, p := range parts {
			if !strings.Contains(chunk, p) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// TestClient は CLIENT の権限の分離と自己防御（C10）、監視（C1、C2、C3）、永続化の場所の変更と認証情報の読み取りの検知（C4、C8）、
// AI エージェントの帰属（C9）、既定の条件のルールによる検知（C8 の連続する列挙、C9 のエージェントの操作）、大量の変更による隔離、
// 隔離の通知（M7。Slack の形の webhook とメールを、疑似インターネットの偽の受け口で受ける）、証拠の保全（C11）、
// おとりの削除の検知（C5）、証明書の更新（M1）を確かめる。
func TestClient(t *testing.T) {
	if *susanooBin == "" {
		t.Fatal("-susanoo で susanoo の実行ファイルを指定してください")
	}
	pc := &machine{ns: "sus-c1", id: "pc-001", agent: true, port: "p-c1"}
	l := &lab{t: t, dir: t.TempDir()}
	buildTopology(t, []*machine{pc})
	l.init()
	hookLog, mailLog := filepath.Join(l.dir, "hook.log"), filepath.Join(l.dir, "mail.log")
	l.writeGW([]map[string]any{{"name": "default", "egress": map[string]any{"default": "allow"}, "isolation": "management"}}, map[string]any{
		"notify": map[string]any{"destinations": []map[string]any{
			{"name": "chat", "type": "slack", "url": "http://203.0.113.2:9091/services/T000/B000/lab"},
			{"name": "mail", "type": "email", "email": map[string]any{
				"server": "203.0.113.2:2525", "tls": "none", "from": "susanoo@example.jp", "to": []string{"admin@example.jp"},
			}},
		}},
	})
	authLog := filepath.Join(l.dir, "auth.log")
	if err := os.WriteFile(authLog, []byte("Oct 19 10:00:00 pc-001 sshd[100]: susanoo-lab-log-line from 192.0.2.10\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	watched := filepath.Join(l.dir, "watched")
	persist := filepath.Join(l.dir, "systemd")
	protected := filepath.Join(l.dir, "Documents")
	for _, d := range []string{watched, persist, protected} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(l.dir, "id_ed25519")
	if err := os.WriteFile(secret, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	decoy := filepath.Join(l.dir, "decoy", ".aws", "credentials")
	keyDir := filepath.Join(l.dir, pc.id)
	l.susanoo("client", "keygen", "-dir", keyDir)
	// 証明書の更新を確かめるため、有効期間の短い証明書を発行する（残りが 3 分の 1 を切ったら CLIENT が更新する）。
	l.susanoo("ctl", "issue", "-dir", l.ctrlDir, "-id", pc.id, "-pub", filepath.Join(keyDir, "client.pub"), "-out", keyDir, "-validity", "40s")
	writeJSON(t, filepath.Join(l.dir, pc.id+".json"), map[string]any{
		"controller": controllerAddr, "pki_dir": pc.id, "state_dir": pc.id + "-state", "heartbeat_interval": "1s",
		"files": map[string]any{
			"watch": []string{watched}, "persistence": []string{persist}, "privilege": []string{},
			"sensitive": []map[string]any{{"path": secret, "readers": []string{"ssh"}}},
			"protect":   []string{protected}, "mass_files": 50, "mass_window": "10s",
		},
		"honeytokens": []map[string]any{{"path": decoy, "kind": "aws"}},
		"evidence":    map[string]any{"logs": []string{authLog}},
	})

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start(t, "試験用サーバー", nsInet, []string{helperEnv + "=sink:203.0.113.2:9090"}, self)
	start(t, "通知の受け口（webhook）", nsInet, []string{helperEnv + "=hook:203.0.113.2:9091:" + hookLog}, self)
	start(t, "通知の受け口（メール）", nsInet, []string{helperEnv + "=smtp:203.0.113.2:2525:" + mailLog}, self)
	start(t, "GW", nsGW, nil, *susanooBin, "gw", "-config", filepath.Join(l.dir, "gw.json"))
	waitFor(t, "GW の起動", 10*time.Second, func() bool { return l.devices() != nil })
	l.dhcp(pc)
	agent := start(t, "CLIENT "+pc.id, pc.ns, nil, *susanooBin, "client", "-config", filepath.Join(l.dir, pc.id+".json"))
	waitFor(t, "端末の登録と機能の申告", 15*time.Second, func() bool {
		f := l.devices()[pc.id].Features
		return slices.Contains(f, "process_events") && slices.Contains(f, "network_events") && slices.Contains(f, "file_events") &&
			slices.Contains(f, "kernel_modules") && slices.Contains(f, "isolation") && slices.Contains(f, "evidence")
	})

	t.Log("段階1: CLIENT は権限を分けて動く。執行部は必要な capability だけを持ち、解析部は非特権の利用者で capability を持たない")
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal(err)
	}
	checkPrivsep(t, agent.cmd.Process.Pid, clientExecutorCaps, map[string]string{"client\x00analyzer": nobody.Uid})

	t.Log("段階2: 端末でプロセスを起動すると、コマンドラインとともに記録される")
	if out, err := inNS(pc.ns, "/bin/sh", "-c", "sleep 1; echo susanoo-process-test").CombinedOutput(); err != nil {
		t.Fatalf("コマンドを実行できません: %v %s", err, out)
	}
	waitFor(t, "プロセスの起動の記録", 15*time.Second, func() bool {
		return eventLine(l.events(), `"type_uid":100701`, "susanoo-process-test")
	})

	t.Log("段階3: 端末から外部に接続すると、接続したプロセスとともに記録される")
	runHelper(t, pc.ns, "hold:203.0.113.2:9090:4")
	waitFor(t, "通信の記録", 15*time.Second, func() bool {
		return eventLine(l.events(), `"type_uid":400101`, `"port":9090`, `"actor":{"process"`, `"name":"lab.test"`)
	})

	t.Log("段階4: 重要な場所でファイルを作ると、作ったプロセスとともに記録される")
	target := filepath.Join(watched, "new-cron-job")
	if err := os.WriteFile(target, []byte("* * * * * root evil\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "ファイルの記録", 15*time.Second, func() bool {
		return eventLine(l.events(), `"class_uid":1001`, fmt.Sprintf(`"path":"%s"`, target), `"name":"lab.test"`)
	})

	t.Log("段階5: 永続化の場所にサービスの定義を作ると、作ったプロセスと実行する命令の抜粋とともに検知結果になる")
	unit := filepath.Join(persist, "updater.service")
	if err := os.WriteFile(unit, []byte("[Service]\nExecStart=/usr/local/bin/updater --daemon\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "永続化の場所の変更の検知", 15*time.Second, func() bool {
		return eventLine(l.events(), `"persistence"`, `"snippet":"ExecStart=/usr/local/bin/updater --daemon"`, `"name":"lab.test"`)
	})

	t.Log("段階6: 認証情報のファイルを、ふだん読むプログラム以外が読むと、読んだプロセスとともに検知結果になる")
	if _, err := os.ReadFile(secret); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "認証情報の読み取りの検知", 15*time.Second, func() bool {
		return eventLine(l.events(), `"credential_access"`, fmt.Sprintf(`"path":"%s"`, secret), `"name":"lab.test"`)
	})

	t.Log("段階7: AI エージェントの配下で起動したプロセスの記録には、エージェントの名前が付く")
	// 名前を claude にした bash の子として /bin/sh を起動する。bash は -c に単純なコマンドが 1 つだけだと fork せずに exec するので、
	// 「; :」を足して fork させ、claude の名前のプロセスを親として残す。
	if out, err := inNS(pc.ns, "/bin/bash", "-c", `exec -a claude /bin/bash -c '/bin/sh -c "sleep 1; echo susanoo-agent-test"; :'`).CombinedOutput(); err != nil {
		t.Fatalf("コマンドを実行できません: %v %s", err, out)
	}
	waitFor(t, "エージェントの帰属", 15*time.Second, func() bool {
		return eventLine(l.events(), `"type_uid":100701`, "susanoo-agent-test", `"agent":{"name":"claude"`)
	})

	t.Log("段階8: 既定の条件のルール（試験運用）：連続する列挙、エージェントによる権限の操作と要注意の操作が検知結果になり、回数が数えられる")
	if out, err := inNS(pc.ns, "/bin/sh", "-c", "for i in 1 2 3; do id; whoami; uname -a; hostname; done").CombinedOutput(); err != nil {
		t.Fatalf("列挙の命令を実行できません: %v %s", err, out)
	}
	// 名前を claude にした bash の配下で、sudo と永続化の場所への書き込みを行う。sudo は root なので認証なしに動き、すぐ終わる
	// （失敗しても起動は記録される）。エージェント役の bash は、実際の AI エージェントと同じく長く動くプロセスとして 1 秒生かす。
	inNS(pc.ns, "/bin/bash", "-c", `exec -a claude /bin/bash -c 'sudo -n true; sleep 1'`).Run()
	if out, err := inNS(pc.ns, "/bin/bash", "-c", `exec -a claude /bin/bash -c 'echo "@reboot /usr/local/bin/sync-notes" > `+persist+`/agent-job; sleep 1'`).CombinedOutput(); err != nil {
		t.Fatalf("エージェントの配下の書き込みを実行できません: %v %s", err, out)
	}
	for _, id := range []string{"enumeration", "agent-privilege", "agent-sensitive-action"} {
		waitFor(t, "条件のルール "+id+" の検知", 20*time.Second, func() bool {
			return eventLine(l.events(), `"rule_match"`, `"uid":"`+id+`"`)
		})
	}
	var stats struct {
		Rules []struct {
			ID        string `json:"id"`
			Default   bool   `json:"default"`
			Monitored int64  `json:"monitored"`
		} `json:"rules"`
	}
	if !l.ctlJSON(&stats, "rules", "stats") {
		t.Fatal("ctl rules stats に失敗しました")
	}
	for _, id := range []string{"enumeration", "agent-privilege", "agent-sensitive-action"} {
		i := slices.IndexFunc(stats.Rules, func(r struct {
			ID        string `json:"id"`
			Default   bool   `json:"default"`
			Monitored int64  `json:"monitored"`
		}) bool {
			return r.ID == id
		})
		if i < 0 || !stats.Rules[i].Default || stats.Rules[i].Monitored < 1 {
			t.Errorf("ctl rules stats の %s = %+v（既定のルールで、試験運用の回数が 1 以上のはず）", id, stats.Rules)
		}
	}

	t.Log("段階9: 守る場所で短時間に大量のファイルを変更すると、端末が隔離される")
	for i := range 60 {
		if err := os.WriteFile(filepath.Join(protected, fmt.Sprintf("doc-%02d.encrypted", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "大量の変更による隔離と自己隔離", 15*time.Second, func() bool {
		d := l.devices()[pc.id]
		return d.Isolation == "management" && d.Reason == "短時間の大量変更" && d.Applied == "management"
	})

	t.Log("段階10: 隔離は Slack の形の webhook とメールで通知される")
	waitFor(t, "webhook の通知", 15*time.Second, func() bool {
		return fileHas(hookLog, "\n", `"text"`, "端末 pc-001 を隔離しました", "短時間の大量変更")
	})
	waitFor(t, "メールの通知", 15*time.Second, func() bool {
		return fileHas(mailLog, "----", "Subject: [susanoo] 端末 pc-001 を隔離しました", "理由: 短時間の大量変更")
	})

	t.Log("段階11: 隔離された端末は証拠（プロセス、接続、ログ）を集めて署名し、CONTROLLER が受け取って監査ログにハッシュを残す")
	type evidenceInfo struct {
		ID, Reason, SHA256           string
		Processes, Connections, Logs int
	}
	evidence := func() []evidenceInfo {
		var list []evidenceInfo
		l.ctlJSON(&list, "evidence", "list", "-device", pc.id)
		return list
	}
	waitFor(t, "隔離の証拠", 20*time.Second, func() bool {
		list := evidence()
		return len(list) == 1 && list[0].Reason == "isolation"
	})
	first := evidence()[0]
	var ev struct {
		DeviceID string `json:"device_id"`
		Snapshot struct {
			Processes []struct {
				CmdLine string `json:"cmd_line"`
			} `json:"processes"`
			Connections []struct {
				Remote, Process string
			} `json:"connections"`
			Logs []struct {
				Path  string
				Lines []string
			} `json:"logs"`
		} `json:"snapshot"`
	}
	if !l.ctlJSON(&ev, "evidence", "show", pc.id, first.ID) {
		t.Fatal("ctl evidence show に失敗しました")
	}
	s := ev.Snapshot
	if ev.DeviceID != pc.id || !slices.ContainsFunc(s.Processes, func(p struct {
		CmdLine string `json:"cmd_line"`
	}) bool {
		return strings.Contains(p.CmdLine, "client -config")
	}) {
		t.Errorf("証拠のプロセスに CLIENT がありません（%d 件）", len(s.Processes))
	}
	if !slices.ContainsFunc(s.Connections, func(c struct{ Remote, Process string }) bool { return c.Remote == controllerAddr }) {
		t.Errorf("証拠の接続に CONTROLLER への管理通信がありません: %+v", s.Connections)
	}
	if len(s.Logs) != 1 || s.Logs[0].Path != authLog || !slices.ContainsFunc(s.Logs[0].Lines, func(x string) bool { return strings.Contains(x, "susanoo-lab-log-line") }) {
		t.Errorf("証拠のログ = %+v", s.Logs)
	}
	if actions := l.auditActions(); !slices.Contains(actions, "evidence.receive:"+pc.id) {
		t.Errorf("監査ログに evidence.receive:%s がありません: %v", pc.id, actions)
	}

	t.Log("段階12: 管理者が求めると、隔離を変えずに証拠を集め直す。試験の通知はすべての宛先に届く")
	sh(t, "ip", "netns", "exec", nsGW, *susanooBin, "ctl", "evidence", "collect", pc.id, "-dir", l.ctrlDir, "-server", controllerAddr)
	waitFor(t, "求めた証拠", 20*time.Second, func() bool {
		list := evidence()
		return len(list) == 2 && list[0].Reason == "request" && list[0].ID != first.ID
	})
	if d := l.devices()[pc.id]; d.Isolation != "management" || d.Applied != "management" {
		t.Errorf("証拠を求めた後の隔離 = %+v", d)
	}
	var results []struct{ Name, Error string }
	if !l.ctlJSON(&results, "notify", "test") || len(results) != 2 || results[0].Error != "" || results[1].Error != "" {
		t.Errorf("試験の通知 = %+v", results)
	}
	waitFor(t, "試験の通知", 10*time.Second, func() bool {
		return fileHas(hookLog, "\n", "試験の通知") && fileHas(mailLog, "----", "Subject: [susanoo] susanoo の試験の通知")
	})

	t.Log("段階13: 隔離中に端末側の遮断のルールを消すと、入れ直され、改ざんが記録される")
	sh(t, "ip", "netns", "exec", pc.ns, "nft", "delete", "table", "inet", "susanoo_client")
	waitFor(t, "自己隔離のルールの入れ直し", 10*time.Second, func() bool {
		return inNS(pc.ns, "nft", "list", "table", "inet", "susanoo_client").Run() == nil
	})
	waitFor(t, "改ざんの記録", 10*time.Second, func() bool {
		return eventLine(l.events(), `"tamper"`)
	})

	t.Log("段階14: おとりを消すと、消したプロセスとともに記録される")
	if err := os.Remove(decoy); err != nil { // すぐ終わるプロセスは名前を取れないことがあるので、試験のプロセスが消す
		t.Fatal(err)
	}
	waitFor(t, "おとりの削除の記録", 10*time.Second, func() bool {
		return eventLine(l.events(), `"operation":"delete"`, `"name":"lab.test"`)
	})

	t.Log("段階15: 有効期間の短い証明書は、CLIENT が CONTROLLER に頼んで更新し、新しい証明書で通信を続ける")
	farFuture := time.Now().Add(80 * 24 * time.Hour)
	waitFor(t, "証明書の更新", 40*time.Second, func() bool {
		return l.devices()[pc.id].CertExpiry.After(farFuture)
	})
	if c := readCert(t, filepath.Join(keyDir, "client.crt")); !c.NotAfter.After(farFuture) {
		t.Errorf("端末の証明書のファイルが更新されていません（期限 %v）", c.NotAfter)
	}
	if actions := l.auditActions(); !slices.Contains(actions, "device.renew:"+pc.id) {
		t.Errorf("監査ログに device.renew:%s がありません: %v", pc.id, actions)
	}
}

// readCert は PEM 形式の証明書を読む。
func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s は PEM 形式ではありません", path)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// eventLine は、すべての文字列を含むイベントの行があるかを返す。
func eventLine(events string, parts ...string) bool {
	for _, line := range strings.Split(events, "\n") {
		ok := true
		for _, p := range parts {
			if !strings.Contains(line, p) {
				ok = false
				break
			}
		}
		if ok && line != "" {
			return true
		}
	}
	return false
}
