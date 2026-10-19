package enroll

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/keys"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
)

func TestCode(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		c, err := NewCode()
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$`).MatchString(c) || seen[c] {
			t.Fatalf("コード = %q", c)
		}
		seen[c] = true
	}
	// 大文字と小文字、区切り、読み違えやすい文字を同じものとみなす。
	k1, _ := Key("0123-4567-89AB-CDEF")
	for _, in := range []string{"0123456789abcdef", "O123 4567 89AB CDEF", "o1z3-4567-89ab-cdef"} {
		k, err := Key(in)
		if err != nil {
			t.Fatal(in, err)
		}
		if bytes.Equal(k, k1) != (in != "o1z3-4567-89ab-cdef") {
			t.Errorf("%q の鍵の一致が違う", in)
		}
	}
	if _, err := Key("0123-4567-89AB-CDE"); err == nil {
		t.Error("15 文字のコードを受け付けた")
	}
	if _, err := Key("0123-4567-89AB-CDEU"); err == nil {
		t.Error("U を含むコードを受け付けた")
	}
	if _, err := Key("0123-4567-89AB-CDEF-0"); err == nil {
		t.Error("17 文字のコードを受け付けた")
	}
	// 部分の境目を変えると、証明も変わる。
	if bytes.Equal(RequestProof(k1, []byte("e"), "pc-0", []byte("01")), RequestProof(k1, []byte("e"), "pc-", []byte("001"))) {
		t.Error("境目の違う要求で同じ証明になった")
	}
}

// fakeServer は、handler で登録の要求に答える、証明書 cert の TLS のサーバーを動かす。
func fakeServer(t *testing.T, cert tls.Certificate, handler func(w http.ResponseWriter, r *http.Request, req api.EnrollRequest, exporter []byte)) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.EnrollRequest
		json.NewDecoder(r.Body).Decode(&req)
		exporter, err := Exporter(*r.TLS)
		if err != nil {
			t.Error(err)
		}
		handler(w, r, req, exporter)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// 端末は、応答の証明が合わないもの、受け取った認証局で確かめられないもの、持ち主や鍵の違う証明書を受け入れない。
func TestEnrollChecksResponse(t *testing.T) {
	env := pkitest.NewTwoTier(t)
	code, _ := NewCode()
	key, _ := Key(code)
	priv, _ := keys.Generate()
	issue := func(env *pkitest.Env, id string, pub ed25519.PublicKey) api.EnrollResponse {
		c, err := env.CA.Issue(pub, pki.Identity{Role: pki.RoleClient, ID: id}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return api.EnrollResponse{Certificate: c.Raw, Chain: [][]byte{env.CA.Cert.Raw}, CA: env.CA.Root.Raw, CommandKey: env.Signer.PublicKey()}
	}
	other := pkitest.NewTwoTier(t)
	otherKey, _ := keys.Generate()
	cases := []struct {
		name   string
		server *pkitest.Env // サーバーの証明書を発行する認証局
		resp   func(req api.EnrollRequest) api.EnrollResponse
		proofK []byte // 応答の証明に使う鍵
		ok     bool
	}{
		{"正しい応答", env, func(req api.EnrollRequest) api.EnrollResponse { return issue(env, req.ID, req.PublicKey) }, key, true},
		{"コードを知らない者の応答", env, func(req api.EnrollRequest) api.EnrollResponse { return issue(env, req.ID, req.PublicKey) }, make([]byte, 32), false},
		{"サーバーの証明書が別の認証局", other, func(req api.EnrollRequest) api.EnrollResponse { return issue(env, req.ID, req.PublicKey) }, key, false},
		{"別の端末の証明書", env, func(req api.EnrollRequest) api.EnrollResponse { return issue(env, "pc-002", req.PublicKey) }, key, false},
		{"別の鍵の証明書", env, func(req api.EnrollRequest) api.EnrollResponse {
			return issue(env, req.ID, otherKey.Public().(ed25519.PublicKey))
		}, key, false},
		{"連なりがない", env, func(req api.EnrollRequest) api.EnrollResponse {
			r := issue(env, req.ID, req.PublicKey)
			r.Chain = nil
			return r
		}, key, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := fakeServer(t, tc.server.Leaf(t, pki.RoleController, "main"), func(w http.ResponseWriter, r *http.Request, req api.EnrollRequest, exporter []byte) {
				if !Equal(req.Proof, RequestProof(key, exporter, req.ID, req.PublicKey)) {
					t.Error("要求の証明が合わない")
				}
				resp := tc.resp(req)
				resp.Proof = ResponseProof(tc.proofK, exporter, resp.Certificate, resp.Chain, resp.CA, resp.CommandKey)
				json.NewEncoder(w).Encode(resp)
			})
			res, err := Enroll(context.Background(), addr, "pc-001", code, priv)
			if (err == nil) != tc.ok {
				t.Fatalf("結果 = %v", err)
			}
			if tc.ok && (len(res.Chain) != 2 || !res.CA.Equal(env.CA.Root)) {
				t.Errorf("受け取ったもの = %+v", res)
			}
		})
	}
	// 正しくない形のコードと端末 ID は、接続する前に断る。
	if _, err := Enroll(context.Background(), "127.0.0.1:1", "pc-001", "short", priv); err == nil || !strings.Contains(err.Error(), "形") {
		t.Errorf("短いコード = %v", err)
	}
	if _, err := Enroll(context.Background(), "127.0.0.1:1", "PC 001", code, priv); err == nil {
		t.Error("不正な端末 ID を受け付けた")
	}
}
