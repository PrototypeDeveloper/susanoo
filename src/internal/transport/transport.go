// Package transport は管理通信（相互TLS）の設定をまとめる。
//
// TLS 1.3 だけを使い、双方が内部の認証局の証明書を示す。証明書の検証に加えて、
// 相手の役割（pki.Role）が許可したものかどうかも確かめる。
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	"susanoo/internal/pki"
)

// ErrNoPeerCertificate は相手が証明書を示さなかったことを表す。
var ErrNoPeerCertificate = errors.New("transport: 相手の証明書がありません")

// ServerConfig は接続を受ける側の設定を返す。allow に含まれる役割の相手だけを受け付ける。
func ServerConfig(pool *x509.CertPool, cert tls.Certificate, allow ...pki.Role) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        pool,
		VerifyConnection: requireRole(slices.Clone(allow)),
	}
}

// ClientConfig は接続する側の設定を返す。相手が役割 server の証明書を示した場合だけ接続する。
func ClientConfig(pool *x509.CertPool, cert tls.Certificate, server pki.Role) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		RootCAs:          pool,
		ServerName:       pki.ServerName(server),
		VerifyConnection: requireRole([]pki.Role{server}),
	}
}

// PeerIdentity は接続の相手が誰かを返す。証明書の検証が済んだ接続に対して使う。
func PeerIdentity(cs tls.ConnectionState) (pki.Identity, error) {
	if len(cs.PeerCertificates) == 0 {
		return pki.Identity{}, ErrNoPeerCertificate
	}
	return pki.IdentityFromCert(cs.PeerCertificates[0])
}

// requireRole は、証明書の検証の後に相手の役割を確かめる関数を返す。
func requireRole(allow []pki.Role) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		id, err := PeerIdentity(cs)
		if err != nil {
			return err
		}
		if !slices.Contains(allow, id.Role) {
			return fmt.Errorf("transport: 役割 %q の相手は許可されていません", id.Role)
		}
		return nil
	}
}
