// Package enroll は、一回限りの登録コードによる端末の初回登録（M1）の、コードと証明の計算をまとめる。
//
// 管理者が CONTROLLER で端末 ID ごとにコードを作り、端末で入力する。端末はまだ内部の認証局を知らないので、
// 証明書なしの TLS で CONTROLLER につなぎ、TLS の鍵から導いた値（RFC 9266 の exporter）とコードで HMAC を計算して、
// コードを知っていることを示す。CONTROLLER も同じ値とコードで応答に HMAC を付けるので、端末は、応答が本物の
// CONTROLLER（コードを知っている者）から、この TLS の接続で届いたことを確かめてから、認証局の証明書を信頼する。
// 途中で TLS を終端する者がいれば、両側の exporter の値が違うので、どちらの HMAC も通らない。
// コードは 80 ビットあり、盗み見た HMAC からコードを総当たりで求めることはできない。
package enroll

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"strings"
)

const (
	// CodeChars はコードの文字数（区切りを除く）。1 文字 5 ビットで 80 ビット。
	CodeChars = 16
	// ExporterLabel は TLS の exporter のラベル。
	ExporterLabel = "EXPORTER-susanoo-enroll-v1"
	exporterLen   = 32
	// alphabet は Crockford の base32（I、L、O、U を使わない）。
	alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

// ErrCode はコードの形が正しくないことを表す。
var ErrCode = errors.New("enroll: 登録コードの形が正しくありません（16 文字の英数字。区切りの「-」は省けます）")

// NewCode は新しいコードを「XXXX-XXXX-XXXX-XXXX」の形で返す。
func NewCode() (string, error) {
	var b [CodeChars]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	var sb strings.Builder
	for i, v := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(alphabet[v&31]) // 256 は 32 で割り切れるので偏らない
	}
	return sb.String(), nil
}

// Normalize は入力されたコードを区切りのない大文字の形にする。読み違えやすい文字（O→0、I と L→1）は直す。
func Normalize(code string) (string, error) {
	var sb strings.Builder
	for _, r := range strings.ToUpper(code) {
		switch r {
		case '-', ' ':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		if !strings.ContainsRune(alphabet, r) {
			return "", ErrCode
		}
		sb.WriteRune(r)
	}
	if sb.Len() != CodeChars {
		return "", ErrCode
	}
	return sb.String(), nil
}

// Key はコードから HMAC の鍵を導く。CONTROLLER はコードそのものではなく、この鍵を保存する。
func Key(code string) ([]byte, error) {
	n, err := Normalize(code)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte("susanoo-enroll-v1\x00" + n))
	return sum[:], nil
}

// Exporter は TLS の接続から、登録の証明に使う値を導く。
func Exporter(cs tls.ConnectionState) ([]byte, error) {
	if cs.Version != tls.VersionTLS13 {
		return nil, errors.New("enroll: TLS 1.3 で接続してください")
	}
	return cs.ExportKeyingMaterial(ExporterLabel, nil, exporterLen)
}

// RequestProof は端末の要求の証明（端末 ID と公開鍵をこの接続に結び付ける）を計算する。
func RequestProof(key, exporter []byte, id string, pub []byte) []byte {
	return mac(key, []byte("request"), exporter, []byte(id), pub)
}

// ResponseProof は CONTROLLER の応答の証明（発行した証明書、連なり、認証局、指示の公開鍵をこの接続に結び付ける）を計算する。
func ResponseProof(key, exporter, cert []byte, chain [][]byte, ca, commandKey []byte) []byte {
	parts := [][]byte{[]byte("response"), exporter, cert, ca, commandKey}
	return mac(key, append(parts, chain...)...)
}

// mac は、それぞれの部分の前に長さを置いてつなげたものの HMAC-SHA256 を返す（部分の境目を取り違えないため）。
func mac(key []byte, parts ...[]byte) []byte {
	h := hmac.New(sha256.New, key)
	var n [4]byte
	for _, p := range parts {
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		h.Write(n[:])
		h.Write(p)
	}
	return h.Sum(nil)
}

// Equal は二つの証明を、かかる時間で中身が分からないように比べる。
func Equal(a, b []byte) bool { return hmac.Equal(a, b) }
