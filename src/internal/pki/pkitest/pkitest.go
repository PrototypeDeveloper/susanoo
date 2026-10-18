// Package pkitest は試験用に、認証局、証明書、署名の鍵をまとめて用意する。
package pkitest

import (
	"crypto/tls"
	"testing"
	"time"

	"susanoo/internal/keys"
	"susanoo/internal/pki"
	"susanoo/internal/sign"
)

// Env は試験用の認証局と、CONTROLLER の署名の鍵。
type Env struct {
	CA     *pki.CA
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

// Leaf は役割 role、ID id の証明書を発行する。
func (e *Env) Leaf(t testing.TB, role pki.Role, id string) tls.Certificate {
	t.Helper()
	c, err := e.CA.NewLeaf(pki.Identity{Role: role, ID: id}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return c
}
