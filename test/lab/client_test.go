//go:build lab

package lab

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestClient は CLIENT の権限の分離と自己防御（C10）、監視（C1、C2、C3）、永続化の場所の変更と認証情報の読み取りの検知（C4、C8）、
// AI エージェントの帰属（C9）、大量の変更による隔離、おとりの削除の検知（C5）、証明書の更新（M1）を確かめる。
func TestClient(t *testing.T) {
	if *susanooBin == "" {
		t.Fatal("-susanoo で susanoo の実行ファイルを指定してください")
	}
	pc := &machine{ns: "sus-c1", id: "pc-001", agent: true, port: "p-c1"}
	l := &lab{t: t, dir: t.TempDir()}
	buildTopology(t, []*machine{pc})
	l.init()
	l.writeGW([]map[string]any{{"name": "default", "egress": map[string]any{"default": "allow"}, "isolation": "management"}}, nil)

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
	})

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start(t, "試験用サーバー", nsInet, []string{helperEnv + "=sink:203.0.113.2:9090"}, self)
	start(t, "GW", nsGW, nil, *susanooBin, "gw", "-config", filepath.Join(l.dir, "gw.json"))
	waitFor(t, "GW の起動", 10*time.Second, func() bool { return l.devices() != nil })
	l.dhcp(pc)
	agent := start(t, "CLIENT "+pc.id, pc.ns, nil, *susanooBin, "client", "-config", filepath.Join(l.dir, pc.id+".json"))
	waitFor(t, "端末の登録と機能の申告", 15*time.Second, func() bool {
		f := l.devices()[pc.id].Features
		return slices.Contains(f, "process_events") && slices.Contains(f, "network_events") && slices.Contains(f, "file_events") &&
			slices.Contains(f, "kernel_modules") && slices.Contains(f, "isolation")
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

	t.Log("段階8: 守る場所で短時間に大量のファイルを変更すると、端末が隔離される")
	for i := range 60 {
		if err := os.WriteFile(filepath.Join(protected, fmt.Sprintf("doc-%02d.encrypted", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "大量の変更による隔離と自己隔離", 15*time.Second, func() bool {
		d := l.devices()[pc.id]
		return d.Isolation == "management" && d.Reason == "短時間の大量変更" && d.Applied == "management"
	})

	t.Log("段階9: 隔離中に端末側の遮断のルールを消すと、入れ直され、改ざんが記録される")
	sh(t, "ip", "netns", "exec", pc.ns, "nft", "delete", "table", "inet", "susanoo_client")
	waitFor(t, "自己隔離のルールの入れ直し", 10*time.Second, func() bool {
		return inNS(pc.ns, "nft", "list", "table", "inet", "susanoo_client").Run() == nil
	})
	waitFor(t, "改ざんの記録", 10*time.Second, func() bool {
		return eventLine(l.events(), `"tamper"`)
	})

	t.Log("段階10: おとりを消すと、消したプロセスとともに記録される")
	if err := os.Remove(decoy); err != nil { // すぐ終わるプロセスは名前を取れないことがあるので、試験のプロセスが消す
		t.Fatal(err)
	}
	waitFor(t, "おとりの削除の記録", 10*time.Second, func() bool {
		return eventLine(l.events(), `"operation":"delete"`, `"name":"lab.test"`)
	})

	t.Log("段階11: 有効期間の短い証明書は、CLIENT が CONTROLLER に頼んで更新し、新しい証明書で通信を続ける")
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
