//go:build lab

package lab

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func readCertFile(t *testing.T, path string) (*x509.Certificate, []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(data)
	if b == nil {
		t.Fatalf("%s に証明書がありません", path)
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c, data
}

// TestAdminAndCA は、1f-3 で v1 に残した管理の項目（2m-3）を確かめる：管理者の証明書の発行と失効、認証局の証明書の更新と
// 端末への配布、イベントの検索の索引。
func TestAdminAndCA(t *testing.T) {
	if *susanooBin == "" {
		t.Fatal("-susanoo で susanoo の実行ファイルを指定してください")
	}
	pc1 := &machine{ns: "sus-c1", id: "pc-001", agent: true, port: "p-c1"}
	machines := []*machine{pc1}
	l := &lab{t: t, dir: t.TempDir()}
	buildTopology(t, machines)
	l.setup(machines)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	gwArgs := []string{*susanooBin, "gw", "-config", filepath.Join(l.dir, "gw.json")}
	gwProc := start(t, "GW", nsGW, nil, gwArgs...)
	waitFor(t, "GW の起動", 10*time.Second, func() bool { return l.devices() != nil })
	l.dhcp(pc1)
	// CLIENT は、起動し直しを求めて終わったら（終了コード 75）起動し直す監視の下で動かす（systemd の代わり）。
	client := start(t, "CLIENT "+pc1.id, pc1.ns, []string{helperEnv + "=supervise:" + *susanooBin + "|" + filepath.Join(l.dir, pc1.id+".json")}, self)
	waitFor(t, "端末の登録", 15*time.Second, func() bool { return !l.devices()[pc1.id].LastSeen.IsZero() })
	ctlAs := func(dir string, args ...string) (string, error) {
		out, err := inNS(nsGW, append(append([]string{*susanooBin, "ctl"}, args...), "-dir", dir, "-server", controllerAddr)...).CombinedOutput()
		return string(out), err
	}
	newAdmin := func(name, id string) string {
		t.Helper()
		d := filepath.Join(l.dir, name)
		l.susanoo("ctl", "admin", "keygen", "-dir", d)
		l.susanoo("ctl", "admin", "issue", "-dir", l.ctrlDir, "-id", id, "-pub", filepath.Join(d, "admin.pub"), "-out", d)
		return d
	}

	t.Log("段階1: 管理者ごとに証明書を発行し、失効させた管理者は操作できない。なくした証明書は、同じ ID で発行し直した証明書で失効させる")
	alice := newAdmin("alice", "alice")
	if out, err := ctlAs(alice, "status"); err != nil {
		t.Fatalf("alice の ctl status: %v\n%s", err, out)
	}
	if out, err := ctlAs(l.ctrlDir, "admin", "revoke", "alice"); err != nil {
		t.Fatalf("alice の失効: %v\n%s", err, out)
	}
	if out, err := ctlAs(alice, "status"); err == nil {
		t.Errorf("失効させた管理者の証明書で操作できました:\n%s", out)
	}
	if out, err := ctlAs(l.ctrlDir, "admin", "revoke", "admin", "-before", time.Now().Add(time.Hour).Format(time.RFC3339)); err == nil {
		t.Errorf("今使っている証明書まで失効させる操作を受け付けました:\n%s", out)
	}
	time.Sleep(1100 * time.Millisecond) // 証明書の時刻は秒単位
	admin2 := newAdmin("admin2", "admin")
	if out, err := ctlAs(admin2, "admin", "revoke", "admin"); err != nil {
		t.Fatalf("前の管理者の証明書の失効: %v\n%s", err, out)
	}
	if out, err := ctlAs(l.ctrlDir, "status"); err == nil {
		t.Errorf("前の管理者の証明書で操作できました:\n%s", out)
	}
	l.adminDir = admin2 // ここからは発行し直した証明書で操作する
	if out, err := ctlAs(admin2, "admin", "list"); err != nil || !strings.Contains(out, "alice") {
		t.Errorf("ctl admin list（%v）:\n%s", err, out)
	}
	actions := l.auditActions()
	for _, want := range []string{"admin.revoke:alice", "admin.revoke:admin"} {
		if !slices.Contains(actions, want) {
			t.Errorf("監査ログに %s がありません: %v", want, actions)
		}
	}

	t.Log("段階2: 認証局の証明書を同じ鍵のまま発行し直して GW を起動し直すと、CONTROLLER が端末に配り、端末は置き換えて起動し直す")
	clientCA := filepath.Join(l.dir, pc1.id, "ca.crt")
	_, oldCA := readCertFile(t, clientCA)
	l.susanoo("ctl", "ca", "renew", "-dir", l.ctrlDir)
	renewed, renewedPEM := readCertFile(t, filepath.Join(l.ctrlDir, "ca.crt"))
	gwProc.stop(syscall.SIGTERM)
	restarted := time.Now()
	gwProc = start(t, "GW（起動し直し）", nsGW, nil, gwArgs...)
	waitFor(t, "端末への認証局の証明書の配布", 20*time.Second, func() bool {
		data, err := os.ReadFile(clientCA)
		return err == nil && bytes.Equal(data, renewedPEM)
	})
	if bytes.Equal(oldCA, renewedPEM) {
		t.Fatal("認証局の証明書が変わっていません")
	}
	waitFor(t, "起動し直した端末の接続", 20*time.Second, func() bool {
		return strings.Contains(client.log.String(), "起動し直します") && l.devices()[pc1.id].LastSeen.After(restarted.Add(2*time.Second))
	})
	var st struct {
		CAExpiry time.Time `json:"ca_expiry"`
	}
	if !l.ctlJSON(&st, "status") || !st.CAExpiry.Equal(renewed.NotAfter) {
		t.Errorf("ctl status の認証局の期限 = %v（%v のはず）", st.CAExpiry, renewed.NotAfter)
	}
	// 前の証明書を写した管理者のディレクトリ（admin2 の ca.crt）でも、前の証明書の期限までは操作できる。
	if out, err := ctlAs(admin2, "status"); err != nil {
		t.Errorf("前の認証局の証明書のディレクトリから操作できません: %v\n%s", err, out)
	}

	t.Log("段階3: イベントの索引を書き、索引を使って端末と種類で検索できる")
	idx, _ := filepath.Glob(filepath.Join(l.dir, "gw-state", "controller", "events", "events-*.idx"))
	if len(idx) == 0 {
		t.Error("イベントの索引がありません（GW を止めるときに書く）")
	}
	out, err := ctlAs(admin2, "events", "-device", pc1.id, "-limit", "5", "-json")
	if err != nil || strings.Count(out, "\n") == 0 || !strings.Contains(out, `"uid":"`+pc1.id+`"`) {
		t.Errorf("ctl events -device（%v）:\n%.500s", err, out)
	}
	if out, err := ctlAs(admin2, "events", "-device", "no-such-device", "-json"); err != nil || strings.TrimSpace(out) != "" {
		t.Errorf("ない端末の検索（%v）:\n%.500s", err, out)
	}
}
