package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"path/filepath"

	"susanoo/internal/keys"
	"susanoo/internal/pki"
)

// 鍵と証明書のディレクトリに置くファイルの名前。
const (
	fileCACert         = pki.CACertFile // 内部の認証局の証明書
	fileCAKey          = pki.CAKeyFile  // 内部の認証局の秘密鍵（CONTROLLER だけ）
	fileControllerCert = "controller.crt"
	fileControllerKey  = "controller.key"
	fileSignKey        = "sign.key" // 指示とポリシーの署名の秘密鍵（CONTROLLER だけ）
	fileSignPub        = "sign.pub"
	filePolicyKey      = "policy.key" // ポリシーの署名の秘密鍵（管理者の ctl だけが使う。CONTROLLER のプロセスには渡さない）
	filePolicyPub      = "policy.pub"
	fileAdminCert      = "admin.crt"
	fileAdminKey       = "admin.key"
	fileClientCert     = "client.crt"
	fileClientKey      = "client.key"
	fileClientPub      = "client.pub"
	fileCommandPub     = "command.pub" // CLIENT が指示の検証に使う公開鍵（sign.pub と同じもの）
)

func loadPool(dir string) (*x509.CertPool, error) {
	ca, err := loadCA(dir)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool, nil
}

// loadCA は認証局の証明書を読む。
func loadCA(dir string) (*x509.Certificate, error) {
	return pki.ReadCertFile(filepath.Join(dir, fileCACert))
}

// loadLeaf は証明書と秘密鍵を読む。秘密鍵の権限が緩い場合は拒否する。
func loadLeaf(dir, certFile, keyFile string) (tls.Certificate, error) {
	cert, err := pki.ReadCertFile(filepath.Join(dir, certFile))
	if err != nil {
		return tls.Certificate{}, err
	}
	priv, err := keys.LoadPrivate(filepath.Join(dir, keyFile))
	if err != nil {
		return tls.Certificate{}, err
	}
	return pki.TLSCertificate(cert, priv), nil
}

func loadCommandKey(dir string) (ed25519.PublicKey, error) {
	return keys.LoadPublic(filepath.Join(dir, fileCommandPub))
}
