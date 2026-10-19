package enroll

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/pki"
)

// Result は登録で受け取ったもの。どれも、応答の証明と、受け取った認証局での検証を済ませてある。
type Result struct {
	Chain      []*x509.Certificate // 先頭が端末の証明書。続くのは連ねる認証局の証明書（二段構えの発行用の認証局）
	CA         *x509.Certificate   // 内部の認証局（ルート）の証明書
	CommandKey ed25519.PublicKey   // CONTROLLER の指示の署名を確かめる公開鍵
}

const enrollTimeout = 30 * time.Second

// Enroll は addr（アドレスとポート）の CONTROLLER に、コード code で端末 id を登録し、鍵 priv の証明書を受け取る。
func Enroll(ctx context.Context, addr, id, code string, priv ed25519.PrivateKey) (*Result, error) {
	key, err := Key(code)
	if err != nil {
		return nil, err
	}
	want := pki.Identity{Role: pki.RoleClient, ID: id}
	if err := want.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, enrollTimeout)
	defer cancel()
	d := tls.Dialer{Config: &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
		ServerName: pki.ServerName(pki.RoleController),
		// 端末はまだ内部の認証局を知らないので、ここでは CONTROLLER の証明書を確かめない。応答の証明で
		// CONTROLLER（コードを知っている者）を確かめてから、受け取った認証局でこの接続の証明書を確かめる。
		InsecureSkipVerify: true,
	}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("enroll: CONTROLLER に接続できません: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	tc := conn.(*tls.Conn)
	cs := tc.ConnectionState()
	exporter, err := Exporter(cs)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	body, err := json.Marshal(api.EnrollRequest{ID: id, PublicKey: pub, Proof: RequestProof(key, exporter, id, pub)})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr+api.PathEnroll, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Close = true
	if err := req.Write(tc); err != nil {
		return nil, refused(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), req)
	if err != nil {
		return nil, refused(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e api.Error
		json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e)
		return nil, fmt.Errorf("enroll: 登録できません: %s: %s", resp.Status, e.Error)
	}
	var er api.EnrollResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, api.MaxBodyBytes)).Decode(&er); err != nil {
		return nil, fmt.Errorf("enroll: 応答を解析できません: %w", err)
	}
	if !Equal(er.Proof, ResponseProof(key, exporter, er.Certificate, er.Chain, er.CA, er.CommandKey)) {
		return nil, errors.New("enroll: 応答の証明が合いません（登録コードが違うか、途中で書き換えられています）")
	}
	return check(cs, want, pub, &er)
}

// refused は、要求を送るか応答を読むときのエラーを説明する。TLS 1.3 では、CONTROLLER が証明書なしの接続を断ったことは
// ここで分かる（有効な登録コードがない間は断る）。
func refused(err error) error {
	if strings.Contains(err.Error(), "remote error: tls") {
		return fmt.Errorf("enroll: CONTROLLER が接続を断りました（有効な登録コードがない間は、証明書なしの接続を受け付けません。"+
			"コードの期限と、管理者が作ったかを確かめてください）: %w", err)
	}
	return fmt.Errorf("enroll: 応答を読めません: %w", err)
}

// check は、証明を確かめた応答の中身と、この接続の CONTROLLER の証明書を、受け取った認証局で確かめる。
func check(cs tls.ConnectionState, want pki.Identity, pub ed25519.PublicKey, er *api.EnrollResponse) (*Result, error) {
	ca, err := x509.ParseCertificate(er.CA)
	if err != nil {
		return nil, fmt.Errorf("enroll: 認証局の証明書を解析できません: %w", err)
	}
	if !ca.IsCA || ca.CheckSignatureFrom(ca) != nil {
		return nil, errors.New("enroll: 受け取った認証局の証明書が、自己署名の認証局の証明書ではありません")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if len(cs.PeerCertificates) == 0 {
		return nil, errors.New("enroll: CONTROLLER が証明書を示していません")
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	server := cs.PeerCertificates[0]
	if _, err := server.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: pki.ServerName(pki.RoleController),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, fmt.Errorf("enroll: CONTROLLER の証明書を確かめられません: %w", err)
	}
	if id, err := pki.IdentityFromCert(server); err != nil || id.Role != pki.RoleController {
		return nil, fmt.Errorf("enroll: 接続した相手が CONTROLLER ではありません（%v）", id)
	}
	if len(er.Chain) > 3 {
		return nil, errors.New("enroll: 証明書の連なりが長すぎます")
	}
	var chain []*x509.Certificate
	inter = x509.NewCertPool()
	for i, der := range append([][]byte{er.Certificate}, er.Chain...) {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("enroll: 発行された証明書を解析できません: %w", err)
		}
		chain = append(chain, c)
		if i > 0 {
			inter.AddCert(c)
		}
	}
	leaf := chain[0]
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, fmt.Errorf("enroll: 発行された証明書を確かめられません: %w", err)
	}
	if id, err := pki.IdentityFromCert(leaf); err != nil || id != want {
		return nil, fmt.Errorf("enroll: 発行された証明書の持ち主が %v です（%v が必要）", id, want)
	}
	if got, ok := leaf.PublicKey.(ed25519.PublicKey); !ok || !got.Equal(pub) {
		return nil, errors.New("enroll: 発行された証明書の鍵が、端末の鍵と違います")
	}
	if len(er.CommandKey) != ed25519.PublicKeySize {
		return nil, errors.New("enroll: 指示の公開鍵の長さが正しくありません")
	}
	return &Result{Chain: chain, CA: ca, CommandKey: ed25519.PublicKey(er.CommandKey)}, nil
}
