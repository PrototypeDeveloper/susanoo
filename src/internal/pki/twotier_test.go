package pki

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"susanoo/internal/keys"
)

// twoTier はルートの認証局と、その署名した発行用の認証局（鍵のディレクトリ）を作る。
func twoTier(t *testing.T) (root *CA, issuer *CA, dir string) {
	t.Helper()
	now := time.Now()
	root, err := NewRootCA("ルート", now)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := keys.Generate()
	cert, err := root.SignIssuer(priv.Public().(ed25519.PublicKey), "GW の発行用", now, IssuerValidity)
	if err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	WriteCertFile(filepath.Join(dir, CACertFile), root.Cert)
	WriteCertFile(filepath.Join(dir, IssuerCertFile), cert)
	keys.SavePrivate(filepath.Join(dir, IssuerKeyFile), priv)
	issuer, err = LoadCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	return root, issuer, dir
}

func verify(root *x509.Certificate, chain []*x509.Certificate) error {
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err
}

// 発行用の認証局は、端末と CONTROLLER の証明書は発行できるが、管理者の証明書は名前の制約で検証に通らない。
func TestTwoTierNameConstraints(t *testing.T) {
	root, issuer, _ := twoTier(t)
	if issuer.Root.Equal(issuer.Cert) || len(issuer.Chain) != 1 || !issuer.Root.Equal(root.Cert) {
		t.Fatalf("発行用の認証局 = %+v", issuer)
	}
	pub := func() ed25519.PublicKey { k, _ := keys.Generate(); return k.Public().(ed25519.PublicKey) }
	now := time.Now()
	for _, id := range []Identity{{RoleClient, "pc-001"}, {RoleController, "main"}, {RoleGW, "gw-1"}} {
		c, err := issuer.Issue(pub(), id, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := verify(root.Cert, issuer.ChainOf(c)); err != nil {
			t.Errorf("%s の証明書が検証に通らない: %v", id, err)
		}
	}
	// 発行用の認証局は管理者の証明書の発行を断る。鍵を盗んで直接署名しても、検証に通らない。
	if _, err := issuer.Issue(pub(), Identity{RoleAdmin, "evil"}, now); err == nil || issuer.CanIssue(RoleAdmin) || !root.CanIssue(RoleAdmin) {
		t.Error("発行用の認証局が管理者の証明書を発行した")
	}
	forged, err := issuer.issue(pub(), Identity{RoleAdmin, "evil"}, now, LeafValidity)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(root.Cert, issuer.ChainOf(forged)); err == nil {
		t.Error("発行用の認証局の鍵で署名した管理者の証明書が検証に通った")
	}
	admin, _ := root.Issue(pub(), Identity{RoleAdmin, "admin"}, now)
	if err := verify(root.Cert, []*x509.Certificate{admin}); err != nil {
		t.Errorf("ルートが発行した管理者の証明書が検証に通らない: %v", err)
	}
	// 発行用の認証局は、さらに下の認証局に署名できない。一段の認証局は発行用の認証局に署名できない。
	if _, err := issuer.SignIssuer(pub(), "孫", now, time.Hour); err == nil {
		t.Error("発行用の認証局が認証局に署名した")
	}
	single, _ := NewCA("一段", now)
	if _, err := single.SignIssuer(pub(), "x", now, time.Hour); err == nil {
		t.Error("一段の認証局が発行用の認証局に署名した")
	}
}

// TLS の相互認証でも、発行用の認証局の証明書を連ねて示せば通り、管理者を名乗る偽の証明書は断られる。
func TestTwoTierHandshake(t *testing.T) {
	root, issuer, _ := twoTier(t)
	now := time.Now()
	server, err := issuer.NewLeaf(Identity{RoleController, "main"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(server.Certificate) != 2 {
		t.Fatalf("サーバーの証明書の連なり = %d", len(server.Certificate))
	}
	pool := root.Pool()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{server},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); c.Write([]byte("x")); c.Close() }()
		}
	}()
	dial := func(cert tls.Certificate) error {
		c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert},
			ServerName: ServerName(RoleController)})
		if err != nil {
			return err
		}
		defer c.Close()
		_, err = c.Read(make([]byte, 1)) // サーバーが証明書を断ると、ここで分かる（TLS 1.3）
		return err
	}
	client, _ := issuer.NewLeaf(Identity{RoleClient, "pc-001"}, now)
	if err := dial(client); err != nil {
		t.Errorf("発行用の認証局の端末の証明書で接続できない: %v", err)
	}
	k, _ := keys.Generate()
	fc, err := issuer.issue(k.Public().(ed25519.PublicKey), Identity{RoleAdmin, "evil"}, now, LeafValidity)
	if err != nil {
		t.Fatal(err)
	}
	forged := TLSChain(issuer.ChainOf(fc), k)
	if err := dial(forged); err == nil {
		t.Error("発行用の認証局が発行した管理者の証明書で接続できた")
	}
	admin, _ := root.NewLeaf(Identity{RoleAdmin, "admin"}, now)
	if err := dial(admin); err != nil {
		t.Errorf("ルートの管理者の証明書で接続できない: %v", err)
	}
}

func TestChainFilesAndLoad(t *testing.T) {
	root, issuer, dir := twoTier(t)
	k, _ := keys.Generate()
	leaf, _ := issuer.Issue(k.Public().(ed25519.PublicKey), Identity{RoleClient, "pc-001"}, time.Now())
	path := filepath.Join(dir, "client.crt")
	if err := WriteChainFile(path, issuer.ChainOf(leaf)...); err != nil {
		t.Fatal(err)
	}
	chain, err := ReadChainFile(path)
	if err != nil || len(chain) != 2 || !chain[0].Equal(leaf) || !chain[1].Equal(issuer.Cert) {
		t.Fatalf("連なり = %d, %v", len(chain), err)
	}
	if first, err := ReadCertFile(path); err != nil || !first.Equal(leaf) {
		t.Errorf("先頭の証明書 = %v", err)
	}
	// 発行用の認証局の鍵と証明書が対応しない、ルートの署名でない場合は読まない。
	other, _ := keys.Generate()
	keys.SavePrivate(filepath.Join(dir, IssuerKeyFile+".other"), other)
	os.Rename(filepath.Join(dir, IssuerKeyFile+".other"), filepath.Join(dir, IssuerKeyFile))
	if _, err := LoadCA(dir); err == nil || !strings.Contains(err.Error(), "対応していません") {
		t.Errorf("鍵の違う発行用の認証局 = %v", err)
	}
	stranger, _ := NewRootCA("別のルート", time.Now())
	WriteCertFile(filepath.Join(dir, CACertFile), stranger.Cert)
	if err := CheckIssuer(stranger.Cert, issuer.Cert, issuer.Cert.PublicKey.(ed25519.PublicKey)); err == nil {
		t.Error("別のルートの署名とみなした")
	}
	_ = root
}
