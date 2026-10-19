// Package sign はポリシー、検知ルール、命令などに ed25519 の署名を付け、検証する。
//
// 署名の対象は、用途（Purpose）と中身のバイト列そのものとする。JSON を正規化してから署名するのではなく、
// 署名したバイト列をそのまま運び、検証に通ってから解析する。用途を署名の対象に含めるので、
// ある用途の署名を別の用途に使い回すことはできない。
package sign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// Purpose は署名の用途。
type Purpose string

const (
	PurposePolicy    Purpose = "policy"    // ポリシー（M2）
	PurposeRules     Purpose = "rules"     // 検知ルール（M3）
	PurposeIntel     Purpose = "intel"     // 脅威情報（G7）
	PurposeCommand   Purpose = "command"   // 隔離や解除の命令（M6）
	PurposeHeartbeat Purpose = "heartbeat" // ハートビート（G10、C10）
	PurposeEvidence  Purpose = "evidence"  // 端末が集めた証拠（C11）
	PurposeRelease   Purpose = "release"   // リリースの目録（実行ファイルのハッシュ。管理者の手元の鍵で署名する）
)

// domain は署名の対象の先頭に付ける文字列。ほかの仕組みの署名と取り違えないようにする。
const domain = "susanoo-sign-v1"

// Envelope は署名付きのデータ。JSON にすると Payload と Signature は base64 になる。
type Envelope struct {
	Purpose   Purpose `json:"purpose"`
	KeyID     string  `json:"key_id"`
	Payload   []byte  `json:"payload"`
	Signature []byte  `json:"signature"`
}

var (
	ErrPurpose    = errors.New("sign: 用途が一致しません")
	ErrUnknownKey = errors.New("sign: 信頼していない鍵による署名です")
	ErrSignature  = errors.New("sign: 署名が正しくありません")
)

// KeyID は公開鍵の識別子（SHA-256 の先頭 8 バイトの 16 進表記）を返す。
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

func message(p Purpose, payload []byte) []byte {
	m := make([]byte, 0, len(domain)+len(p)+len(payload)+2)
	m = append(m, domain...)
	m = append(m, 0)
	m = append(m, p...)
	m = append(m, 0)
	return append(m, payload...)
}

// Signer は署名を作る。
type Signer struct {
	priv ed25519.PrivateKey
	id   string
}

// NewSigner は秘密鍵から Signer を作る。
func NewSigner(priv ed25519.PrivateKey) (*Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("sign: 秘密鍵の長さが %d バイトです（%d バイトが必要）", len(priv), ed25519.PrivateKeySize)
	}
	return &Signer{priv: priv, id: KeyID(priv.Public().(ed25519.PublicKey))}, nil
}

// KeyID は署名に使う鍵の識別子を返す。
func (s *Signer) KeyID() string { return s.id }

// PublicKey は検証に使う公開鍵を返す。
func (s *Signer) PublicKey() ed25519.PublicKey { return s.priv.Public().(ed25519.PublicKey) }

// Sign は payload に用途 p の署名を付ける。
func (s *Signer) Sign(p Purpose, payload []byte) Envelope {
	return Envelope{
		Purpose:   p,
		KeyID:     s.id,
		Payload:   bytes.Clone(payload),
		Signature: ed25519.Sign(s.priv, message(p, payload)),
	}
}

// Verifier は信頼する公開鍵の一覧で署名を検証する。
type Verifier struct {
	keys map[string]ed25519.PublicKey
}

// NewVerifier は信頼する公開鍵から Verifier を作る。
func NewVerifier(pubs ...ed25519.PublicKey) (*Verifier, error) {
	v := &Verifier{keys: make(map[string]ed25519.PublicKey, len(pubs))}
	for _, pub := range pubs {
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("sign: 公開鍵の長さが %d バイトです（%d バイトが必要）", len(pub), ed25519.PublicKeySize)
		}
		v.keys[KeyID(pub)] = bytes.Clone(pub)
	}
	return v, nil
}

// Verify は env が用途 want の正しい署名を持つか確かめ、正しければ中身を返す。
// 用途は env.Purpose を信用せず、呼び出し側が期待する値で検証する。
func (v *Verifier) Verify(want Purpose, env Envelope) ([]byte, error) {
	if env.Purpose != want {
		return nil, fmt.Errorf("%w: %q（%q が必要）", ErrPurpose, env.Purpose, want)
	}
	pub, ok := v.keys[env.KeyID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKey, env.KeyID)
	}
	if !ed25519.Verify(pub, message(want, env.Payload), env.Signature) {
		return nil, ErrSignature
	}
	return env.Payload, nil
}
