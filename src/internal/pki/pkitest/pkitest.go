// Package pkitest は試験用に、認証局、証明書、署名の鍵をまとめて用意する。
package pkitest

import (
	"crypto/ed25519"
	"crypto/tls"
	"path/filepath"
	"testing"
	"time"

	"susanoo/internal/keys"
	"susanoo/internal/pki"
	"susanoo/internal/sign"
)

// Env は試験用の認証局と、CONTROLLER の署名の鍵。
type Env struct {
	CA     *pki.CA
	Root   *pki.CA // 二段構えのときのルートの認証局（管理者の証明書を発行する）。一段なら nil
	Signer *sign.Signer
}

// New は試験用の Env を作る。
func New(t testing.TB) *Env {
	t.Helper()
	ca, err := pki.NewCA("試験用CA", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	priv, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	s, err := sign.NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return &Env{CA: ca, Signer: s}
}

// NewTwoTier は、ルートの認証局と、その署名した発行用の認証局（CA）を持つ試験用の Env を作る。
func NewTwoTier(t testing.TB) *Env {
	t.Helper()
	e := New(t)
	now := time.Now()
	root, err := pki.NewRootCA("試験用ルート", now)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := root.SignIssuer(priv.Public().(ed25519.PublicKey), "試験用の発行用", now, pki.IssuerValidity)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, err := range []error{
		pki.WriteCertFile(filepath.Join(dir, pki.CACertFile), root.Cert),
		pki.WriteCertFile(filepath.Join(dir, pki.IssuerCertFile), cert),
		keys.SavePrivate(filepath.Join(dir, pki.IssuerKeyFile), priv),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if e.CA, err = pki.LoadCA(dir); err != nil {
		t.Fatal(err)
	}
	e.Root = root
	return e
}

// Leaf は役割 role、ID id の証明書を発行する。二段構えでは、管理者の証明書だけルートの認証局が発行する。
func (e *Env) Leaf(t testing.TB, role pki.Role, id string) tls.Certificate {
	t.Helper()
	ca := e.CA
	if role == pki.RoleAdmin && e.Root != nil {
		ca = e.Root
	}
	c, err := ca.NewLeaf(pki.Identity{Role: role, ID: id}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return c
}
