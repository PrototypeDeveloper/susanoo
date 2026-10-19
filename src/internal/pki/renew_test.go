package pki

import (
	"crypto/ed25519"
	"crypto/x509"
	"testing"
	"time"

	"susanoo/internal/keys"
)

// 発行し直した認証局の証明書は同じ鍵と名前で期限が延び、前の証明書で発行した証明書もそのまま検証に通る。
func TestRenewSelf(t *testing.T) {
	now := time.Now()
	for _, newCA := range []func(string, time.Time) (*CA, error){NewCA, NewRootCA} {
		ca, err := newCA("試験の認証局", now.Add(-9*365*24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		priv, _ := keys.Generate()
		leaf, err := ca.Issue(priv.Public().(ed25519.PublicKey), Identity{Role: RoleClient, ID: "pc-001"}, now)
		if err != nil {
			t.Fatal(err)
		}
		old := ca.Cert
		renewed, err := ca.RenewSelf(now)
		if err != nil {
			t.Fatal(err)
		}
		if err := SameCA(old, renewed); err != nil || !renewed.NotAfter.After(old.NotAfter.Add(8*365*24*time.Hour)) || renewed.MaxPathLen != old.MaxPathLen {
			t.Errorf("発行し直した証明書 = 期限 %v、%v", renewed.NotAfter, err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(renewed)
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); err != nil {
			t.Errorf("前の認証局の証明書で発行した証明書が、新しい証明書で検証に通りません: %v", err)
		}
		// 新しい証明書で発行した証明書は、前の証明書でも（期限までは）検証に通る。
		leaf2, _ := ca.Issue(priv.Public().(ed25519.PublicKey), Identity{Role: RoleClient, ID: "pc-002"}, now)
		oldPool := x509.NewCertPool()
		oldPool.AddCert(old)
		if _, err := leaf2.Verify(x509.VerifyOptions{Roots: oldPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); err != nil {
			t.Errorf("新しい認証局の証明書で発行した証明書が、前の証明書で検証に通りません: %v", err)
		}
		if err := SameCA(renewed, old); err == nil {
			t.Error("期限の短い証明書を受け入れました")
		}
	}
	other, _ := NewCA("試験の認証局", now)
	ca, _ := NewCA("試験の認証局", now.Add(-time.Hour))
	if err := SameCA(ca.Cert, other.Cert); err == nil {
		t.Error("鍵の違う認証局の証明書を受け入れました")
	}
	issuerRoot, _ := NewRootCA("ルート", now)
	ipriv, _ := keys.Generate()
	issuerCert, err := issuerRoot.SignIssuer(ipriv.Public().(ed25519.PublicKey), "発行用", now, IssuerValidity)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &CA{Cert: issuerCert, Root: issuerRoot.Cert, Chain: []*x509.Certificate{issuerCert}, key: ipriv}
	if _, err := issuer.RenewSelf(now); err == nil {
		t.Error("発行用の認証局を自己署名で発行し直しました")
	}
}
