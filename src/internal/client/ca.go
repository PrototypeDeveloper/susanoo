package client

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"susanoo/internal/pki"
)

// 認証局の証明書の更新（2m-3）。CLIENT はハートビートで信頼している認証局の証明書のハッシュを知らせ、CONTROLLER は
// 違えば署名付きの指示に新しい証明書を入れる。執行部は、今の証明書と同じ鍵と名前で期限の延びたものだけを受け入れて
// 保存し、CLIENT を起動し直す（解析部も新しい証明書で CONTROLLER を確かめるように）。

// caHash は CONTROLLER に知らせる、信頼している認証局の証明書の SHA-256。l.mu を持って呼ぶ。
func (l *Local) caHash() string {
	if l.caCert == nil {
		return ""
	}
	return sha256Hex(l.caCert.Raw)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// acceptCA は、指示で届いた認証局の証明書 der を確かめて、受け入れたら保存して true を返す。l.mu を持って呼ぶ。
func (l *Local) acceptCA(der []byte) (bool, error) {
	if l.caCert == nil || bytes.Equal(der, l.caCert.Raw) {
		return false, nil
	}
	next, err := x509.ParseCertificate(der)
	if err != nil {
		return false, fmt.Errorf("認証局の証明書を解析できません: %w", err)
	}
	if err := pki.SameCA(l.caCert, next); err != nil {
		return false, err
	}
	if l.cfg.CAPath != "" {
		if err := pki.WriteCertFile(l.cfg.CAPath, next); err != nil {
			return false, err
		}
	}
	// 検証に使う集合（cfg.CA）は起動し直すまで今のままにする（同じ鍵なので、前の証明書の期限までは同じく検証できる）。
	l.caCert = next
	l.log.Warn("認証局の証明書を、発行し直されたものに置き換えました。CLIENT を起動し直します", "期限", next.NotAfter.Local().Format("2006-01-02"))
	return true, nil
}
