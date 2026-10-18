package keys

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateRoundTrip(t *testing.T) {
	priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "k.key")
	if err := SavePrivate(path, priv); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(priv) {
		t.Error("読み直した秘密鍵が一致しない")
	}
}

func TestPublicRoundTrip(t *testing.T) {
	priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	path := filepath.Join(t.TempDir(), "k.pub")
	if err := SavePublic(path, pub); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPublic(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(pub) {
		t.Error("読み直した公開鍵が一致しない")
	}
}

func TestLoadPrivateRejectsLoosePermissions(t *testing.T) {
	priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "k.key")
	if err := SavePrivate(path, priv); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivate(path); err == nil {
		t.Error("所有者以外も読める秘密鍵を受け付けた")
	}
}

func TestParseWrongType(t *testing.T) {
	priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := MarshalPrivatePEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicPEM(privPEM); err == nil {
		t.Error("秘密鍵の PEM を公開鍵として受け付けた")
	}
	if _, err := ParsePrivatePEM([]byte("not pem")); err == nil {
		t.Error("PEM ではないデータを受け付けた")
	}
}
