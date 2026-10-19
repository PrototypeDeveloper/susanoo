//go:build lab

package lab

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func init() {
	extraHelpers["nocert"] = noCertProbe
}

// noCertProbe は証明書なしで CONTROLLER（arg）に TLS でつなぎ、全体の状態を求める。応答の状態の番号か、
// 「refused」（TLS の段階で断られた）を出力する。
func noCertProbe(arg string) int {
	conn, err := tls.Dial("tcp", arg, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		fmt.Println("refused")
		return 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(conn, "GET /v1/status HTTP/1.1\r\nHost: controller\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		if strings.Contains(err.Error(), "remote error: tls") {
			fmt.Println("refused") // TLS 1.3 では、断られたことは最初の読み込みで分かる
			return 0
		}
		fmt.Println("error:", err)
		return 1
	}
	resp.Body.Close()
	fmt.Println(resp.StatusCode)
	return 0
}

// TestEnroll は、一回限りの登録コードによる端末の初回登録（M1）を確かめる。
func TestEnroll(t *testing.T) {
	if *susanooBin == "" {
		t.Fatal("-susanoo で susanoo の実行ファイルを指定してください")
	}
	pc := &machine{ns: "sus-c1", id: "pc-001", agent: true, port: "p-c1"}
	l := &lab{t: t, dir: t.TempDir()}
	buildTopology(t, []*machine{pc})
	l.init()
	l.writeGW([]map[string]any{{"name": "default", "egress": map[string]any{"default": "allow"}, "isolation": "management"}}, nil)
	start(t, "GW", nsGW, nil, *susanooBin, "gw", "-config", filepath.Join(l.dir, "gw.json"))
	waitFor(t, "GW の起動", 10*time.Second, func() bool { return l.devices() != nil })
	l.dhcp(pc)
	keyDir := filepath.Join(l.dir, pc.id)
	probe := func() string {
		t.Helper()
		ok, out := runHelper(t, pc.ns, "nocert:"+controllerAddr)
		if !ok {
			t.Fatalf("証明書なしの接続を試せません: %s", out)
		}
		return out
	}
	enroll := func(id, code, dir string) (bool, string) {
		t.Helper()
		out, err := inNS(pc.ns, *susanooBin, "client", "enroll", "-controller", controllerAddr, "-id", id, "-code", code, "-dir", dir).CombinedOutput()
		return err == nil, string(out)
	}
	type enrollCode struct {
		ID      string    `json:"id"`
		Code    string    `json:"code"`
		Expires time.Time `json:"expires"`
	}
	codes := func() []enrollCode {
		var list []enrollCode
		if !l.ctlJSON(&list, "enroll", "list") {
			t.Fatal("ctl enroll list を実行できません")
		}
		return list
	}

	t.Log("段階1: 登録コードがない間は、証明書なしの接続を TLS の段階で断る")
	if out := probe(); out != "refused" {
		t.Errorf("登録コードがないときの証明書なしの接続 = %s", out)
	}
	if ok, out := enroll(pc.id, "0000-0000-0000-0000", keyDir); ok || !strings.Contains(out, "断りました") {
		t.Errorf("登録コードがないときの登録: %s", out)
	}

	t.Log("段階2: 管理者が登録コードを作ると、証明書なしの接続を受け付けるが、登録の窓口のほかは使えない")
	var code enrollCode
	if !l.ctlJSON(&code, "enroll", "create", pc.id, "-ttl", "10m") || code.Code == "" {
		t.Fatal("ctl enroll create を実行できません")
	}
	if out := probe(); out != "403" {
		t.Errorf("登録コードがあるときの、証明書なしの状態の取得 = %s", out)
	}
	if ok, out := enroll(pc.id, "0000-0000-0000-0000", keyDir); ok || !strings.Contains(out, "登録コードが正しくない") {
		t.Errorf("誤ったコードでの登録: %s", out)
	}

	t.Log("段階3: 端末は登録コードで鍵を作り、証明書、認証局の証明書、指示の公開鍵を受け取って、CLIENT を動かせる")
	if ok, out := enroll(pc.id, strings.ToLower(code.Code), keyDir); !ok || !strings.Contains(out, "登録しました") {
		t.Fatalf("登録できません: %s", out)
	}
	if st, err := os.Stat(filepath.Join(keyDir, "client.key")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("端末の秘密鍵 = %v %v", st, err)
	}
	if c := readCert(t, filepath.Join(keyDir, "client.crt")); c.Subject.CommonName != pc.id {
		t.Errorf("端末の証明書の持ち主 = %s", c.Subject.CommonName)
	}
	if string(mustRead(t, filepath.Join(keyDir, "ca.crt"))) != string(mustRead(t, filepath.Join(l.ctrlDir, "ca.crt"))) ||
		string(mustRead(t, filepath.Join(keyDir, "command.pub"))) != string(mustRead(t, filepath.Join(l.ctrlDir, "sign.pub"))) {
		t.Error("受け取った認証局の証明書か指示の公開鍵が、CONTROLLER のものと違います")
	}
	writeJSON(t, filepath.Join(l.dir, pc.id+".json"), map[string]any{
		"controller": controllerAddr, "pki_dir": pc.id, "state_dir": pc.id + "-state", "heartbeat_interval": "1s",
		"files":          map[string]any{"watch": []string{}, "persistence": []string{}, "privilege": []string{}, "sensitive": []map[string]any{}, "protect": []string{}, "wide": []string{}},
		"kernel_modules": false, "logons": map[string]any{"enabled": false},
	})
	start(t, "CLIENT "+pc.id, pc.ns, nil, *susanooBin, "client", "-config", filepath.Join(l.dir, pc.id+".json"))
	waitFor(t, "登録した端末の接続", 15*time.Second, func() bool { return !l.devices()[pc.id].LastSeen.IsZero() })

	t.Log("段階4: 使ったコードは消え、同じコードでは登録できず、証明書なしの接続もまた断る")
	if list := codes(); len(list) != 0 {
		t.Errorf("使ったコードが残っています: %+v", list)
	}
	if ok, _ := enroll(pc.id, code.Code, filepath.Join(l.dir, "again")); ok {
		t.Error("同じコードで二度登録できました")
	}
	if out := probe(); out != "refused" {
		t.Errorf("コードを使った後の証明書なしの接続 = %s", out)
	}

	t.Log("段階5: 誤った証明が続くと、そのコードを消し、総当たりの疑いを記録する")
	if !l.ctlJSON(&code, "enroll", "create", "pc-002", "-ttl", "10m") {
		t.Fatal("ctl enroll create を実行できません")
	}
	for i := range 5 {
		if ok, _ := enroll("pc-002", fmt.Sprintf("0000-0000-0000-000%d", i), filepath.Join(l.dir, "pc-002")); ok {
			t.Fatal("誤ったコードで登録できました")
		}
	}
	if list := codes(); len(list) != 0 {
		t.Errorf("誤った証明が続いたのにコードが残っています: %+v", list)
	}
	if ok, _ := enroll("pc-002", code.Code, filepath.Join(l.dir, "pc-002")); ok {
		t.Error("消したコードで登録できました")
	}
	actions := l.auditActions()
	for _, want := range []string{"device.enroll.create:pc-001", "device.enroll.fail:pc-001", "device.enroll:pc-001", "device.enroll.lock:pc-002"} {
		if !slices.Contains(actions, want) {
			t.Errorf("監査ログに %s がありません: %v", want, actions)
		}
	}
	waitFor(t, "総当たりの疑いの記録", 10*time.Second, func() bool { return eventLine(l.events(), "enroll_lock", "pc-002") })
}
