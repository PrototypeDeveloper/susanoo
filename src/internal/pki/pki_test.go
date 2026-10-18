package pki

import (
	"crypto/ed25519"
	"crypto/x509"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"susanoo/internal/keys"
)

var now = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func newCA(t *testing.T) *CA {
	t.Helper()
	ca, err := NewCA("susanoo 試験用CA", now)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestIssueAndVerify(t *testing.T) {
	ca := newCA(t)
	tests := []struct {
		id         Identity
		wantServer bool
	}{
		{Identity{RoleClient, "pc-001"}, false},
		{Identity{RoleAdmin, "admin"}, false},
		{Identity{RoleController, "main"}, true},
		{Identity{RoleGW, "gw-1"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.id.String(), func(t *testing.T) {
			leaf, err := ca.NewLeaf(tt.id, now)
			if err != nil {
				t.Fatal(err)
			}
			cert := leaf.Leaf

			_, err = cert.Verify(x509.VerifyOptions{
				Roots:       ca.Pool(),
				CurrentTime: now,
				KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			})
			if err != nil {
				t.Errorf("クライアント証明書として検証できない: %v", err)
			}

			_, err = cert.Verify(x509.VerifyOptions{
				Roots:       ca.Pool(),
				CurrentTime: now,
				DNSName:     ServerName(tt.id.Role),
				KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			if gotServer := err == nil; gotServer != tt.wantServer {
				t.Errorf("サーバー証明書として使えるか = %v, 期待値 %v（%v）", gotServer, tt.wantServer, err)
			}

			got, err := IdentityFromCert(cert)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.id {
				t.Errorf("持ち主 = %v, 期待値 %v", got, tt.id)
			}
		})
	}
}

func TestLeafValidity(t *testing.T) {
	ca := newCA(t)
	leaf, err := ca.NewLeaf(Identity{RoleClient, "pc-001"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := leaf.Leaf.NotAfter.Sub(now); got != LeafValidity {
		t.Errorf("有効期間 = %v, 期待値 %v", got, LeafValidity)
	}

	// 認証局の有効期限を超える証明書は発行しない。
	late := ca.Cert.NotAfter.Add(-24 * time.Hour)
	leaf, err = ca.NewLeaf(Identity{RoleClient, "pc-002"}, late)
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.Leaf.NotAfter.Equal(ca.Cert.NotAfter) {
		t.Errorf("有効期限 = %v, 認証局の期限 %v を超えている", leaf.Leaf.NotAfter, ca.Cert.NotAfter)
	}
}

func TestIssueRejectsInvalidIdentity(t *testing.T) {
	ca := newCA(t)
	priv, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	for _, id := range []Identity{
		{"router", "x"},
		{RoleClient, ""},
		{RoleClient, "PC-001"},
		{RoleClient, "pc/001"},
		{RoleClient, "-pc"},
	} {
		if _, err := ca.Issue(pub, id, now); err == nil {
			t.Errorf("不正な持ち主 %+v に発行した", id)
		}
	}
	if _, err := ca.Issue(pub[:10], Identity{RoleClient, "pc"}, now); err == nil {
		t.Error("長さが不正な公開鍵に発行した")
	}
}

func TestIdentityFromCertRejects(t *testing.T) {
	tests := []struct {
		name string
		uris []string
	}{
		{"URIなし", nil},
		{"2個", []string{"susanoo://client/a", "susanoo://client/b"}},
		{"不明な役割", []string{"susanoo://router/a"}},
		{"余計な階層", []string{"susanoo://client/a/b"}},
		{"問い合わせ付き", []string{"susanoo://client/a?x=1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{}
			for _, s := range tt.uris {
				u, err := url.Parse(s)
				if err != nil {
					t.Fatal(err)
				}
				cert.URIs = append(cert.URIs, u)
			}
			if id, err := IdentityFromCert(cert); err == nil {
				t.Errorf("不正な証明書から持ち主 %v を取り出した", id)
			}
		})
	}
}

func TestSaveLoadCA(t *testing.T) {
	ca := newCA(t)
	dir := t.TempDir()
	if err := ca.Save(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, CAKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("秘密鍵の権限 = %v, 期待値 0600", fi.Mode().Perm())
	}

	loaded, err := LoadCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Cert.Equal(ca.Cert) {
		t.Error("読み直した証明書が一致しない")
	}
	// 読み直した認証局で発行した証明書も、元の認証局で検証できる。
	leaf, err := loaded.NewLeaf(Identity{RoleClient, "pc-001"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{
		Roots: ca.Pool(), CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Error(err)
	}
}

func TestLoadCARejectsMismatchedKey(t *testing.T) {
	ca := newCA(t)
	other := newCA(t)
	dir := t.TempDir()
	if err := ca.Save(dir); err != nil {
		t.Fatal(err)
	}
	if err := keys.SavePrivate(filepath.Join(dir, CAKeyFile), other.key); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCA(dir); err == nil {
		t.Error("証明書と対応しない秘密鍵を受け付けた")
	}
}

func TestSerialsAreUnique(t *testing.T) {
	ca := newCA(t)
	var serials []string
	for range 20 {
		leaf, err := ca.NewLeaf(Identity{RoleClient, "pc"}, now)
		if err != nil {
			t.Fatal(err)
		}
		s := leaf.Leaf.SerialNumber.String()
		if slices.Contains(serials, s) {
			t.Fatalf("シリアル番号が重複した: %s", s)
		}
		serials = append(serials, s)
	}
}

// 更新の時期は有効期間の残りが 3 分の 1 を切ったとき。発行した時刻は有効期間の開始に時刻のずれを足したもの。
func TestRenewalDueAndIssuedAt(t *testing.T) {
	ca := newCA(t)
	priv, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	cert, err := ca.IssueFor(pub, Identity{RoleClient, "pc-001"}, now, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !IssuedAt(cert).Equal(now) {
		t.Errorf("発行した時刻 = %v、期待値 %v", IssuedAt(cert), now)
	}
	if cert.NotAfter.Sub(now) != 30*time.Minute {
		t.Errorf("有効期間 = %v", cert.NotAfter.Sub(now))
	}
	for _, c := range []struct {
		after time.Duration
		due   bool
	}{{0, false}, {19 * time.Minute, false}, {21 * time.Minute, true}, {40 * time.Minute, true}} {
		if got := RenewalDue(cert, now.Add(c.after)); got != c.due {
			t.Errorf("%v 後の更新の時期 = %v", c.after, got)
		}
	}
	for _, v := range []time.Duration{0, -time.Second, LeafValidity + time.Second} {
		if _, err := ca.IssueFor(pub, Identity{RoleClient, "pc-001"}, now, v); err == nil {
			t.Errorf("有効期間 %v で発行した", v)
		}
	}
}
