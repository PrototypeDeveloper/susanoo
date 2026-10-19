package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/enroll"
	"susanoo/internal/event"
	"susanoo/internal/keys"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/policy"
)

// createCode は管理者として登録コードを作る。
func (f *fixture) createCode(id, ttl string) api.EnrollCode {
	f.t.Helper()
	status, body := f.peer(pki.RoleAdmin, "admin").do(http.MethodPost, api.PathEnrollCodes, api.EnrollCodeCreate{ID: id, TTL: ttl})
	if status != http.StatusOK {
		f.t.Fatalf("登録コードを作れない: %d %s", status, body)
	}
	var code api.EnrollCode
	if err := json.Unmarshal(body, &code); err != nil {
		f.t.Fatal(err)
	}
	return code
}

func (f *fixture) enrollCodes() []api.EnrollCode {
	f.t.Helper()
	status, body := f.peer(pki.RoleAdmin, "admin").do(http.MethodGet, api.PathEnrollCodes, nil)
	if status != http.StatusOK {
		f.t.Fatalf("登録コードの一覧 = %d %s", status, body)
	}
	var list []api.EnrollCode
	json.Unmarshal(body, &list)
	return list
}

// noCertConn は証明書なしで TLS の接続を試み、受け付けられたら接続を返す。
func (f *fixture) noCertConn() (*tls.Conn, error) {
	conn, err := tls.Dial("tcp", f.addr, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		return nil, err
	}
	// TLS 1.3 では、サーバーが断ったことは最初の読み込みで分かる。
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Read(make([]byte, 1)); err != nil && !isTimeout(err) {
		conn.Close()
		return nil, err
	}
	conn.SetReadDeadline(time.Time{})
	return conn, nil
}

func isTimeout(err error) bool {
	type timeout interface{ Timeout() bool }
	t, ok := err.(timeout)
	return ok && t.Timeout()
}

// connClient は、証明書なしの接続 conn だけを使う HTTP のクライアントを返す。
func connClient(conn *tls.Conn) *http.Client {
	used := false
	return &http.Client{Transport: &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
		if used {
			return nil, errors.New("接続は 1 つだけ")
		}
		used = true
		return conn, nil
	}}}
}

// rawRequest は client で要求を送り、状態と本文を返す。
func rawRequest(t *testing.T, client *http.Client, method, path string, body []byte) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, "https://controller"+path, bytes.NewReader(body))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

// 登録コードがある間だけ証明書なしの接続を受け付け、登録の窓口のほかには通さない。端末はコードで登録し、
// 認証局と指示の公開鍵を受け取る。コードは一度しか使えない。
func TestEnroll(t *testing.T) {
	for _, tc := range []struct {
		name  string
		env   *pkitest.Env
		chain int
	}{{"一段", pkitest.New(t), 0}, {"二段構え", pkitest.NewTwoTier(t), 1}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			issuer := &fakeIssuer{env: tc.env}
			f := startFull(t, tc.env, dir, testPolicy(policy.ResponseEnforce, false), nil, issuer)
			if _, err := f.noCertConn(); err == nil {
				t.Fatal("登録コードがないのに、証明書なしの接続を受け付けた")
			}
			code := f.createCode("pc-001", "1h")
			if len(code.Code) != 19 || !code.Expires.Equal(f.clock.now().Add(time.Hour)) {
				t.Errorf("登録コード = %+v", code)
			}
			if list := f.enrollCodes(); len(list) != 1 || list[0].ID != "pc-001" || list[0].Code != "" {
				t.Errorf("一覧 = %+v", list)
			}
			if n := f.status(f.peer(pki.RoleAdmin, "admin")).EnrollCodes; n != 1 {
				t.Errorf("状態の登録コードの数 = %d", n)
			}
			// 証明書なしの接続では、登録の窓口のほかは使えない。
			conn, err := f.noCertConn()
			if err != nil {
				t.Fatalf("登録コードがあるのに、証明書なしの接続を断った: %v", err)
			}
			if status, _ := rawRequest(t, connClient(conn), http.MethodGet, api.PathStatus, nil); status != http.StatusForbidden {
				t.Errorf("証明書なしの状態の取得 = %d", status)
			}
			priv, _ := keys.Generate()
			res, err := enroll.Enroll(context.Background(), f.addr, "pc-001", strings.ToLower(code.Code), priv)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Chain) != 1+tc.chain || !res.CA.Equal(tc.env.CA.Root) || !res.CommandKey.Equal(tc.env.Signer.PublicKey()) {
				t.Errorf("受け取ったもの: 連なり %d、認証局 %v", len(res.Chain), res.CA.Subject)
			}
			if !slices.Contains(auditActions(t, dir), ActionEnroll+":pc-001") || !slices.Equal(issuer.calls, []string{"pc-001"}) {
				t.Errorf("監査ログ = %v、発行 = %v", auditActions(t, dir), issuer.calls)
			}
			// 受け取った証明書で、相互TLSの通信ができる。
			cert := pki.TLSChain(res.Chain, priv)
			if status, body := f.peerWith(cert, "pc-001").do(http.MethodPost, api.PathCertificate, nil); status != http.StatusConflict {
				t.Errorf("登録した証明書での接続 = %d %s", status, body)
			}
			// コードは使ったら消え、証明書なしの接続も断るようになる。
			if list := f.enrollCodes(); len(list) != 0 {
				t.Errorf("使ったコードが残っている: %+v", list)
			}
			if _, err := enroll.Enroll(context.Background(), f.addr, "pc-001", code.Code, priv); err == nil {
				t.Error("同じコードで二度登録できた")
			}
		})
	}
}

// 誤った証明が続くとコードを消す。別の接続の exporter で計算した証明（途中で TLS を終端した者が中継したもの）も通らない。
// 期限の切れたコードは使えない。
func TestEnrollRejects(t *testing.T) {
	env := pkitest.New(t)
	dir := t.TempDir()
	f := startFull(t, env, dir, testPolicy(policy.ResponseEnforce, false), nil, &fakeIssuer{env: env})
	code := f.createCode("pc-001", "")
	key, _ := enroll.Key(code.Code)
	priv, _ := keys.Generate()
	pub := priv.Public().(ed25519.PublicKey)
	relay := func() int {
		conn, err := f.noCertConn()
		if err != nil {
			t.Fatal(err)
		}
		other := bytes.Repeat([]byte{7}, 32) // この接続のものではない exporter
		body, _ := json.Marshal(api.EnrollRequest{ID: "pc-001", PublicKey: pub, Proof: enroll.RequestProof(key, other, "pc-001", pub)})
		status, _ := rawRequest(t, connClient(conn), http.MethodPost, api.PathEnroll, body)
		return status
	}
	if status := relay(); status != http.StatusForbidden {
		t.Errorf("中継した証明の応答 = %d", status)
	}
	if list := f.enrollCodes(); len(list) != 1 || list[0].Failures != 1 {
		t.Errorf("誤った証明の回数 = %+v", list)
	}
	for range enrollMaxFailures - 1 {
		if _, err := enroll.Enroll(context.Background(), f.addr, "pc-001", "0000-0000-0000-0000", priv); err == nil {
			t.Fatal("誤ったコードで登録できた")
		}
	}
	if list := f.enrollCodes(); len(list) != 0 {
		t.Errorf("誤った証明が続いたのにコードが残っている: %+v", list)
	}
	if _, err := enroll.Enroll(context.Background(), f.addr, "pc-001", code.Code, priv); err == nil {
		t.Error("消したコードで登録できた")
	}
	actions := auditActions(t, dir)
	if !slices.Contains(actions, ActionEnrollFail+":pc-001") || !slices.Contains(actions, ActionEnrollLock+":pc-001") {
		t.Errorf("監査ログ = %v", actions)
	}
	if fs := f.status(f.peer(pki.RoleAdmin, "admin")).RecentFindings; len(fs) == 0 || !fs[len(fs)-1].FindingInfo.HasType(event.FindingTypeEnrollLock) {
		t.Errorf("最近の検知に登録コードの総当たりがない: %+v", fs)
	}

	// 期限の切れたコードでは接続も登録もできない。
	code = f.createCode("pc-002", "10m")
	f.clock.advance(11 * time.Minute)
	if _, err := enroll.Enroll(context.Background(), f.addr, "pc-002", code.Code, priv); err == nil {
		t.Error("期限の切れたコードで登録できた")
	}
	// 管理者でなければコードを作れない。有効期間は 7 日まで。
	if status, _ := f.peer(pki.RoleClient, "pc-009").do(http.MethodPost, api.PathEnrollCodes, api.EnrollCodeCreate{ID: "pc-009"}); status != http.StatusForbidden {
		t.Errorf("端末がコードを作った応答 = %d", status)
	}
	if status, _ := f.peer(pki.RoleAdmin, "admin").do(http.MethodPost, api.PathEnrollCodes, api.EnrollCodeCreate{ID: "pc-003", TTL: "200h"}); status != http.StatusBadRequest {
		t.Errorf("7 日より長いコードの応答 = %d", status)
	}
	// 取り消したコードは使えない。
	code = f.createCode("pc-004", "1h")
	if status, _ := f.peer(pki.RoleAdmin, "admin").do(http.MethodDelete, api.PathEnrollCodes+"/pc-004", nil); status != http.StatusOK {
		t.Errorf("取り消しの応答 = %d", status)
	}
	if _, err := enroll.Enroll(context.Background(), f.addr, "pc-004", code.Code, priv); err == nil {
		t.Error("取り消したコードで登録できた")
	}
}

// 登録の要求は 1 分に enrollRateLimit 回まで。発行の仕組みがなければ登録しない。
func TestEnrollLimits(t *testing.T) {
	env := pkitest.New(t)
	f := startFull(t, env, t.TempDir(), testPolicy(policy.ResponseEnforce, false), nil, &fakeIssuer{env: env})
	f.createCode("pc-001", "1h")
	conn, err := f.noCertConn()
	if err != nil {
		t.Fatal(err)
	}
	client := connClient(conn)
	body, _ := json.Marshal(api.EnrollRequest{ID: "pc-999", PublicKey: make([]byte, 32), Proof: make([]byte, 32)})
	var last int
	for range enrollRateLimit + 1 {
		last, _ = rawRequest(t, client, http.MethodPost, api.PathEnroll, body)
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("上限を超えた要求の応答 = %d", last)
	}
	f.clock.advance(enrollRateWindow)
	if status, _ := rawRequest(t, client, http.MethodPost, api.PathEnroll, body); status != http.StatusForbidden {
		t.Errorf("時間をおいた要求の応答 = %d", status)
	}

	g := start(t, env, t.TempDir(), testPolicy(policy.ResponseEnforce, false))
	if status, _ := g.peer(pki.RoleAdmin, "admin").do(http.MethodPost, api.PathEnrollCodes, api.EnrollCodeCreate{ID: "pc-001"}); status != http.StatusServiceUnavailable {
		t.Errorf("発行の仕組みがないときの応答 = %d", status)
	}
}
