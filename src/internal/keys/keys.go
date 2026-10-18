// Package keys は ed25519 の鍵の生成と、PEM 形式での読み書きをまとめる。
// 認証局の鍵、端末の鍵、署名用の鍵のすべてでこのパッケージを使う。
package keys

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"susanoo/internal/fsutil"
)

const (
	privatePEMType = "PRIVATE KEY"
	publicPEMType  = "PUBLIC KEY"
)

// Generate は新しい ed25519 の秘密鍵を作る。
func Generate() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	return priv, err
}

// MarshalPrivatePEM は秘密鍵を PKCS #8 の PEM 形式にする。
func MarshalPrivatePEM(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: privatePEMType, Bytes: der}), nil
}

// ParsePrivatePEM は PKCS #8 の PEM 形式から ed25519 の秘密鍵を読む。
func ParsePrivatePEM(data []byte) (ed25519.PrivateKey, error) {
	der, err := decodePEM(data, privatePEMType)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("keys: 秘密鍵を解析できません: %w", err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("keys: ed25519 ではない秘密鍵です（%T）", k)
	}
	return priv, nil
}

// MarshalPublicPEM は公開鍵を PKIX の PEM 形式にする。
func MarshalPublicPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: publicPEMType, Bytes: der}), nil
}

// ParsePublicPEM は PKIX の PEM 形式から ed25519 の公開鍵を読む。
func ParsePublicPEM(data []byte) (ed25519.PublicKey, error) {
	der, err := decodePEM(data, publicPEMType)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("keys: 公開鍵を解析できません: %w", err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("keys: ed25519 ではない公開鍵です（%T）", k)
	}
	return pub, nil
}

// SavePrivate は秘密鍵を所有者だけが読める権限（0600）で保存する。
func SavePrivate(path string, priv ed25519.PrivateKey) error {
	data, err := MarshalPrivatePEM(priv)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, data, 0o600)
}

// LoadPrivate は秘密鍵を読む。所有者以外も読める権限のファイルは、漏えいの恐れがあるため拒否する。
func LoadPrivate(path string) (ed25519.PrivateKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("keys: %s は所有者以外も読める権限（%v）です。0600 にしてください", path, fi.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivatePEM(data)
}

// SavePublic は公開鍵を保存する。
func SavePublic(path string, pub ed25519.PublicKey) error {
	data, err := MarshalPublicPEM(pub)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, data, 0o644)
}

// LoadPublic は公開鍵を読む。
func LoadPublic(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublicPEM(data)
}

func decodePEM(data []byte, typ string) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("keys: PEM 形式ではありません")
	}
	if block.Type != typ {
		return nil, fmt.Errorf("keys: PEM の種類が %q です（%q が必要）", block.Type, typ)
	}
	return block.Bytes, nil
}
