package controller

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/keys"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/policy"
)

// try は、接続できないとき（TLS の段階で断られたとき）も試験を止めずに、状態の要求の応答コードを返す（断られたら 0）。
func (d *peer) try() int {
	d.http.CloseIdleConnections()
	resp, err := d.http.Get("https://" + d.f.addr + api.PathStatus)
	if err != nil {
		return 0
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// pastAdmin は、発行の時刻を ago だけ前にした管理者の証明書を作る。
func pastAdmin(t *testing.T, env *pkitest.Env, id string, ago time.Duration) tls.Certificate {
	t.Helper()
	priv, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := env.CA.IssueFor(priv.Public().(ed25519.PublicKey), pki.Identity{Role: pki.RoleAdmin, ID: id}, time.Now().Add(-ago), pki.LeafValidity)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: priv, Leaf: cert}
}

// 管理者の証明書は ID ごとに失効させられる。自分と同じ ID なら、今使っている証明書より前に発行したものだけを失効させ、
// 今使っている証明書まで失効させる操作は断る。
func TestAdminRevocation(t *testing.T) {
	env := pkitest.New(t)
	f := start(t, env, t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	f.clock.set(time.Now()) // 証明書の発行の時刻と比べるため
	admin, alice := f.peer(pki.RoleAdmin, "admin"), f.peer(pki.RoleAdmin, "alice")
	bobOld, bobNew := f.peerWith(pastAdmin(t, env, "bob", time.Hour), "bob"), f.peer(pki.RoleAdmin, "bob")
	for _, p := range []*peer{admin, alice, bobOld, bobNew} {
		if code := p.try(); code != http.StatusOK {
			t.Fatalf("%s の状態の要求 = %d", p.id, code)
		}
	}
	if status, body := admin.do(http.MethodPost, api.PathAdmins+"/alice/revoke", nil); status != http.StatusOK {
		t.Fatalf("alice の失効 = %d %s", status, body)
	}
	if code := alice.try(); code == http.StatusOK {
		t.Error("失効させた管理者の証明書で操作できました")
	}
	// 手元の証明書をなくした bob は、発行し直した証明書で、前の証明書を失効させる。
	status, body := bobNew.do(http.MethodPost, api.PathAdmins+"/bob/revoke", nil)
	if status != http.StatusOK {
		t.Fatalf("bob の失効 = %d %s", status, body)
	}
	if bobOld.try() == http.StatusOK || bobNew.try() != http.StatusOK {
		t.Errorf("bob の前の証明書 = %d、新しい証明書 = %d", bobOld.try(), bobNew.try())
	}
	// 今使っている証明書まで失効させる操作は断る。
	if status, _ := admin.do(http.MethodPost, api.PathAdmins+"/admin/revoke", api.AdminRevokeRequest{Before: time.Now().Add(time.Hour)}); status != http.StatusConflict {
		t.Errorf("自分の証明書まで失効させる操作 = %d", status)
	}
	if status, _ := admin.do(http.MethodPost, api.PathAdmins+"/not valid/revoke", nil); status != http.StatusBadRequest && status != http.StatusNotFound {
		t.Errorf("不正な ID の失効 = %d", status)
	}
	// 端末は管理者を失効させられない。
	if status, _ := f.peer(pki.RoleClient, "pc-001").do(http.MethodPost, api.PathAdmins+"/admin/revoke", nil); status != http.StatusForbidden {
		t.Errorf("端末からの失効 = %d", status)
	}
	_, body = admin.do(http.MethodGet, api.PathAdmins, nil)
	var list api.AdminList
	json.Unmarshal(body, &list)
	var ids []string
	for _, r := range list.Revoked {
		ids = append(ids, r.ID)
	}
	if list.Self != "admin" || !slices.Equal(ids, []string{"alice", "bob"}) {
		t.Errorf("失効の一覧 = %+v", list)
	}
	if got := auditActions(t, f.dir); !slices.Contains(got, ActionAdminRevoke+":alice") || !slices.Contains(got, ActionAdminRevoke+":bob") {
		t.Errorf("監査ログ = %v", got)
	}
	// 失効の記録は CONTROLLER を起動し直しても続く。
	f.stop()
	f2 := start(t, env, f.dir, testPolicy(policy.ResponseEnforce, false))
	f2.clock.set(time.Now())
	if code := f2.peerWith(alice.cert, "alice").try(); code == http.StatusOK {
		t.Error("起動し直したら、失効させた管理者の証明書で操作できました")
	}
}

// heartbeatCA は、信頼している認証局の証明書のハッシュ hash を知らせるハートビートを送り、指示を返す。
func (d *peer) heartbeatCA(hash string) api.Command {
	d.f.t.Helper()
	d.count++
	status, body := d.do(http.MethodPost, api.PathHeartbeat, d.signedHeartbeat(api.Heartbeat{
		DeviceID: d.id, BootID: d.boot, Counter: d.count, Time: d.f.clock.now(), Hostname: d.id, CAHash: hash,
	}))
	return d.command(status, body)
}

// 端末の信頼している認証局の証明書が今のものと違えば、指示に今の証明書を入れる。全体の状態に認証局の期限を載せる。
func TestDistributeCA(t *testing.T) {
	env := pkitest.New(t)
	f := start(t, env, t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	pc1 := f.peer(pki.RoleClient, "pc-001")
	if cmd := pc1.heartbeatCA(""); cmd.CA != nil {
		t.Error("ハッシュを知らせない端末に認証局の証明書を渡しました")
	}
	if cmd := pc1.heartbeatCA(caHash(env.CA.Root)); cmd.CA != nil {
		t.Error("今の証明書を信頼している端末に認証局の証明書を渡しました")
	}
	if cmd := pc1.heartbeatCA(strings.Repeat("0", 64)); string(cmd.CA) != string(env.CA.Root.Raw) {
		t.Error("前の証明書を信頼している端末に今の証明書を渡しません")
	}
	st := f.status(f.peer(pki.RoleAdmin, "admin"))
	if st.CAExpiry == nil || !st.CAExpiry.Equal(env.CA.Root.NotAfter) {
		t.Errorf("認証局の期限 = %v", st.CAExpiry)
	}
}
