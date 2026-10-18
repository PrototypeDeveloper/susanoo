package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/keys"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/policy"
	"susanoo/internal/transport"
)

// 証明書は実際の時刻で発行するので、これらの試験では CONTROLLER の時計を今の時刻に合わせる。
func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// fakeIssuer は GW の執行部の代わりに、試験用の認証局で端末の証明書を発行する。
type fakeIssuer struct {
	env   *pkitest.Env
	mu    sync.Mutex
	calls []string
}

func (i *fakeIssuer) IssueClient(_ context.Context, id string, pub ed25519.PublicKey) (*x509.Certificate, error) {
	i.mu.Lock()
	i.calls = append(i.calls, id)
	i.mu.Unlock()
	return i.env.CA.Issue(pub, pki.Identity{Role: pki.RoleClient, ID: id}, time.Now())
}

// shortCert は有効期間 validity の端末の証明書を作る。
func shortCert(t *testing.T, env *pkitest.Env, id string, validity time.Duration) tls.Certificate {
	t.Helper()
	priv, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := env.CA.IssueFor(priv.Public().(ed25519.PublicKey), pki.Identity{Role: pki.RoleClient, ID: id}, time.Now(), validity)
	if err != nil {
		t.Fatal(err)
	}
	return pki.TLSCertificate(cert, priv)
}

// 端末は、有効期間の残りが 3 分の 1 を切った証明書を、同じ鍵で更新できる。時期より前の更新は断る。
func TestRenewCertificate(t *testing.T) {
	env := pkitest.New(t)
	dir := t.TempDir()
	issuer := &fakeIssuer{env: env}
	f := startFull(t, env, dir, testPolicy(policy.ResponseEnforce, false), nil, issuer)
	f.clock.set(time.Now())

	fresh := f.peer(pki.RoleClient, "pc-001")
	if status, body := fresh.do(http.MethodPost, api.PathCertificate, nil); status != http.StatusConflict {
		t.Fatalf("時期より前の更新の応答 = %d %s", status, body)
	}

	cert := shortCert(t, env, "pc-002", time.Hour)
	pc := f.peerWith(cert, "pc-002")
	f.clock.advance(41 * time.Minute)
	status, body := pc.do(http.MethodPost, api.PathCertificate, nil)
	if status != http.StatusOK {
		t.Fatalf("更新の応答 = %d %s", status, body)
	}
	var resp api.CertificateResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	renewed, err := x509.ParseCertificate(resp.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := pki.IdentityFromCert(renewed)
	if id != (pki.Identity{Role: pki.RoleClient, ID: "pc-002"}) || !renewed.PublicKey.(ed25519.PublicKey).Equal(cert.Leaf.PublicKey) ||
		renewed.NotAfter.Before(time.Now().Add(80*24*time.Hour)) {
		t.Errorf("更新した証明書 = %v、期限 %v", id, renewed.NotAfter)
	}
	if !slices.Equal(issuer.calls, []string{"pc-002"}) {
		t.Errorf("発行の依頼 = %v", issuer.calls)
	}
	if !slices.Contains(auditActions(t, dir), ActionRenew+":pc-002") {
		t.Errorf("監査ログ = %v", auditActions(t, dir))
	}

	// 管理者は端末の証明書の更新を求められない。
	admin := f.peer(pki.RoleAdmin, "admin")
	if status, _ := admin.do(http.MethodPost, api.PathCertificate, nil); status != http.StatusForbidden {
		t.Errorf("管理者の更新の応答 = %d", status)
	}
}

// 発行の仕組みがなければ、更新は断る。
func TestRenewWithoutIssuer(t *testing.T) {
	env := pkitest.New(t)
	f := start(t, env, t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	f.clock.set(time.Now().Add(50 * time.Minute))
	pc := f.peerWith(shortCert(t, env, "pc-001", time.Hour), "pc-001")
	if status, _ := pc.do(http.MethodPost, api.PathCertificate, nil); status != http.StatusServiceUnavailable {
		t.Errorf("発行の仕組みがないときの応答 = %d", status)
	}
}

// 管理者が端末の証明書を失効させると、端末は全遮断で隔離され、その証明書では続いている接続でも
// 新しい接続でも通信できない。失効の後に発行し直した証明書では、また接続できる。
func TestRevokeDevice(t *testing.T) {
	env := pkitest.New(t)
	dir := t.TempDir()
	f := start(t, env, dir, testPolicy(policy.ResponseEnforce, false))
	f.clock.set(time.Now())
	pc := f.peer(pki.RoleClient, "pc-001")
	if status, _ := pc.heartbeat(); status != http.StatusOK {
		t.Fatalf("ハートビートの応答 = %d", status)
	}
	admin := f.peer(pki.RoleAdmin, "admin")
	status, body := admin.do(http.MethodPost, api.PathDevices+"/pc-001/revoke", nil)
	if status != http.StatusOK {
		t.Fatalf("失効の応答 = %d %s", status, body)
	}
	var view api.Device
	json.Unmarshal(body, &view)
	if view.Isolation != policy.IsolateFull || view.Reason != ReasonRevoked || view.Revoked.IsZero() {
		t.Errorf("失効させた端末 = %+v", view)
	}
	if got := f.enf.last(); len(got.addrs) == 0 {
		t.Errorf("GW で遮断していない: %+v", got)
	}

	// 続いている接続（HTTP/2）でも、要求ごとに拒む。
	if status, _ := pc.heartbeat(); status != http.StatusForbidden {
		t.Errorf("失効した証明書の続いている接続のハートビート = %d", status)
	}
	// 新しい接続は TLS の段階で拒む。
	tr := &http.Transport{TLSClientConfig: transport.ClientConfig(env.CA.Pool(), pc.cert, pki.RoleController)}
	defer tr.CloseIdleConnections()
	if resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Post("https://"+f.addr+api.PathHeartbeat, "application/json", nil); err == nil {
		resp.Body.Close()
		t.Errorf("失効した証明書で新しく接続できた（%s）", resp.Status)
	}

	// 失効は再起動しても続く。
	f.stop()
	f2 := start(t, env, dir, testPolicy(policy.ResponseEnforce, false))
	f2.clock.set(time.Now())
	old := f2.peerWith(pc.cert, "pc-001")
	tr2 := old.http.Transport.(*http.Transport)
	if resp, err := (&http.Client{Transport: tr2, Timeout: 5 * time.Second}).Post("https://"+f2.addr+api.PathHeartbeat, "application/json", nil); err == nil {
		resp.Body.Close()
		t.Error("再起動後に失効した証明書で接続できた")
	}

	// 証明書の時刻は秒単位なので、失効と同じ秒に発行したものは失効の前とみなす。1 秒待ってから発行し直す。
	time.Sleep(1100 * time.Millisecond)
	again := f2.peer(pki.RoleClient, "pc-001")
	again.boot = "boot-2" // 入れ直した端末は起動し直している
	if status, _ := again.heartbeat(); status != http.StatusOK {
		t.Fatalf("発行し直した証明書のハートビート = %d", status)
	}
	if d := f2.devices(admin2(f2))["pc-001"]; !d.Revoked.IsZero() || d.CertExpiry.IsZero() || d.Isolation != policy.IsolateFull {
		t.Errorf("入れ直した端末 = %+v（隔離は管理者が解除するまで続く）", d)
	}
	if !slices.Contains(auditActions(t, dir), ActionRevoke+":pc-001") {
		t.Errorf("監査ログ = %v", auditActions(t, dir))
	}
	// 形の不正な ID は失効させられない。
	if status, _ := admin2(f2).do(http.MethodPost, api.PathDevices+"/PC_001!/revoke", nil); status != http.StatusBadRequest {
		t.Errorf("不正な ID の失効の応答 = %d", status)
	}
}

func admin2(f *fixture) *peer { return f.peer(pki.RoleAdmin, "admin") }

// CONTROLLER の証明書は、止めずに切り替えられる（新しい接続から使う）。
func TestSetCertificate(t *testing.T) {
	env := pkitest.New(t)
	f := start(t, env, t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	serial := func() string {
		tr := &http.Transport{TLSClientConfig: transport.ClientConfig(env.CA.Pool(), env.Leaf(t, pki.RoleAdmin, "admin"), pki.RoleController)}
		defer tr.CloseIdleConnections()
		resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://" + f.addr + api.PathDevices)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.TLS.PeerCertificates[0].SerialNumber.String()
	}
	before := serial()
	next := env.Leaf(t, pki.RoleController, "main")
	f.ctrl.SetCertificate(next)
	if got := serial(); got == before || got != next.Leaf.SerialNumber.String() {
		t.Errorf("切り替え後の証明書のシリアル番号 = %s（前 %s、新 %s）", got, before, next.Leaf.SerialNumber)
	}
}
