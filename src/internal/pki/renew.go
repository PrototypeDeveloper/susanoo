package pki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// 認証局の証明書の更新（2m-3）。自己署名の認証局（一段の認証局か、二段構えのルート）の証明書を、同じ鍵と名前で、
// 期限を延ばして発行し直す。発行済みの証明書は、同じ鍵と名前の新しい認証局の証明書でもそのまま検証に通る。

// CAWarning より期限が近い認証局の証明書は、更新を促す。
const CAWarning = 365 * 24 * time.Hour

// RenewSelf は、自己署名の認証局の証明書を、同じ鍵と名前で、今から CAValidity の期限で発行し直し、ca を新しい証明書に切り替える。
func (ca *CA) RenewSelf(now time.Time) (*x509.Certificate, error) {
	if ca.TwoTier() {
		return nil, errors.New("pki: 発行用の認証局の証明書はここでは更新できません（ルートの認証局で署名し直してください）")
	}
	old := ca.Cert
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		RawSubject:            old.RawSubject, // 名前は前と同じバイト列にする（発行済みの証明書の発行者の名前と一致させる）
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              later(now.Add(CAValidity), old.NotAfter.Add(time.Second)), // 証明書の時刻は秒単位なので、必ず前より延ばす
		KeyUsage:              old.KeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            old.MaxPathLen,
		MaxPathLenZero:        old.MaxPathLenZero,
		SubjectKeyId:          old.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, ca.key.Public(), ca.key)
	if err != nil {
		return nil, fmt.Errorf("pki: 認証局の証明書を発行し直せません: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if err := SameCA(old, cert); err != nil {
		return nil, err
	}
	ca.Cert, ca.Root = cert, cert
	return cert, nil
}

// SameCA は、next が cur と同じ鍵と名前の、期限の延びた自己署名の認証局の証明書（RenewSelf で発行し直したもの）かを確かめる。
func SameCA(cur, next *x509.Certificate) error {
	curKey, ok1 := cur.PublicKey.(ed25519.PublicKey)
	nextKey, ok2 := next.PublicKey.(ed25519.PublicKey)
	switch {
	case !next.IsCA || !next.BasicConstraintsValid:
		return errors.New("pki: 認証局の証明書ではありません")
	case !bytes.Equal(cur.RawSubject, next.RawSubject):
		return errors.New("pki: 認証局の名前が今のものと違います")
	case !ok1 || !ok2 || !curKey.Equal(nextKey):
		return errors.New("pki: 認証局の鍵が今のものと違います")
	case next.CheckSignatureFrom(next) != nil:
		return errors.New("pki: 自己署名の認証局の証明書ではありません")
	case !next.NotAfter.After(cur.NotAfter):
		return errors.New("pki: 認証局の証明書の期限が今のものより先ではありません")
	}
	return nil
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
