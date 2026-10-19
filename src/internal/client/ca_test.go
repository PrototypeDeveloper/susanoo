package client

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/platform/platformtest"
	"susanoo/internal/sign"
)

func sha(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// 指示で届いた、同じ鍵と名前で期限の延びた認証局の証明書だけを受け入れて保存し、CLIENT を起動し直させる。
func TestAcceptRenewedCA(t *testing.T) {
	env := pkitest.New(t)
	old := env.CA.Cert
	caPath := filepath.Join(t.TempDir(), "ca.crt")
	restarts := make(chan string, 4)
	l, err := NewLocal(LocalConfig{
		Cert: env.Leaf(t, pki.RoleClient, "pc-001"), CA: env.CA.Pool(), CACert: old, CAPath: caPath, CommandKey: env.Signer.PublicKey(),
		StateDir: t.TempDir(), Controller: netip.MustParseAddrPort("127.0.0.1:1"), Platform: platformtest.New(caps), Logger: quiet,
		OnRestart: func(reason string) { restarts <- reason },
	})
	if err != nil {
		t.Fatal(err)
	}
	hash := func() string {
		t.Helper()
		env, err := l.Heartbeat(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		v, _ := sign.NewVerifier(l.key.Public().(ed25519.PublicKey))
		payload, _ := v.Verify(sign.PurposeHeartbeat, env)
		var hb api.Heartbeat
		json.Unmarshal(payload, &hb)
		return hb.CAHash
	}
	if got := hash(); got != sha(old.Raw) {
		t.Fatalf("知らせた認証局のハッシュ = %s", got)
	}
	apply := func(version uint64, ca []byte) {
		t.Helper()
		if err := l.Apply(context.Background(), command(t, env.Signer, sign.PurposeCommand, api.Command{DeviceID: "pc-001", Version: version, CA: ca})); err != nil {
			t.Fatal(err)
		}
	}
	// 鍵の違う認証局の証明書は受け入れない。
	other := pkitest.New(t)
	apply(1, other.CA.Cert.Raw)
	select {
	case r := <-restarts:
		t.Fatalf("鍵の違う認証局で起動し直そうとしました: %s", r)
	case <-time.After(100 * time.Millisecond):
	}
	renewed, err := env.CA.RenewSelf(time.Now().Add(time.Minute)) // 作ったばかりの認証局より期限が延びるように
	if err != nil {
		t.Fatal(err)
	}
	apply(1, renewed.Raw)
	select {
	case <-restarts:
	case <-time.After(5 * time.Second):
		t.Fatal("発行し直した認証局の証明書で起動し直しません")
	}
	if got, err := pki.ReadCertFile(caPath); err != nil || !got.Equal(renewed) {
		t.Errorf("保存した認証局の証明書 = %v, %v", got, err)
	}
	if got := hash(); got != sha(renewed.Raw) {
		t.Errorf("置き換えた後のハッシュ = %s", got)
	}
	// 同じものが届いても、もう起動し直さない。
	apply(1, renewed.Raw)
	select {
	case r := <-restarts:
		t.Errorf("同じ証明書で起動し直そうとしました: %s", r)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := os.Stat(caPath); err != nil {
		t.Error(err)
	}
}
