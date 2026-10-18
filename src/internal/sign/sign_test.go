package sign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"susanoo/internal/keys"
)

func newSigner(t *testing.T) *Signer {
	t.Helper()
	priv, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newVerifier(t *testing.T, pubs ...ed25519.PublicKey) *Verifier {
	t.Helper()
	v, err := NewVerifier(pubs...)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSignVerify(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(t, s.PublicKey())
	payload := []byte(`{"version":1}`)

	env := s.Sign(PurposePolicy, payload)

	// JSON を経由しても検証できる。
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var got Envelope
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	out, err := v.Verify(PurposePolicy, got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, payload) {
		t.Errorf("中身 = %q, 期待値 %q", out, payload)
	}
}

func TestVerifyRejects(t *testing.T) {
	s := newSigner(t)
	other := newSigner(t)
	v := newVerifier(t, s.PublicKey())
	env := s.Sign(PurposePolicy, []byte("payload"))

	tests := []struct {
		name    string
		purpose Purpose
		env     func() Envelope
		want    error
	}{
		{"中身の改ざん", PurposePolicy, func() Envelope {
			e := env
			e.Payload = []byte("PAYLOAD")
			return e
		}, ErrSignature},
		{"署名の改ざん", PurposePolicy, func() Envelope {
			e := env
			e.Signature = bytes.Clone(env.Signature)
			e.Signature[0] ^= 1
			return e
		}, ErrSignature},
		{"用途の書き換え", PurposeCommand, func() Envelope {
			e := env
			e.Purpose = PurposeCommand
			return e
		}, ErrSignature},
		{"期待と違う用途", PurposeCommand, func() Envelope { return env }, ErrPurpose},
		{"信頼していない鍵", PurposePolicy, func() Envelope {
			return other.Sign(PurposePolicy, []byte("payload"))
		}, ErrUnknownKey},
		{"鍵の識別子の偽装", PurposePolicy, func() Envelope {
			e := other.Sign(PurposePolicy, []byte("payload"))
			e.KeyID = s.KeyID()
			return e
		}, ErrSignature},
		{"署名が空", PurposePolicy, func() Envelope {
			e := env
			e.Signature = nil
			return e
		}, ErrSignature},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v.Verify(tt.purpose, tt.env())
			if !errors.Is(err, tt.want) {
				t.Errorf("エラー = %v, 期待値 %v", err, tt.want)
			}
		})
	}
}

func TestSignCopiesPayload(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(t, s.PublicKey())
	payload := []byte("payload")
	env := s.Sign(PurposeRules, payload)
	payload[0] = 'P'
	if _, err := v.Verify(PurposeRules, env); err != nil {
		t.Errorf("署名後に元のバイト列を変えると検証に失敗した: %v", err)
	}
}

func TestNewRejectsBadKeys(t *testing.T) {
	if _, err := NewSigner(make(ed25519.PrivateKey, 10)); err == nil {
		t.Error("長さが不正な秘密鍵を受け付けた")
	}
	if _, err := NewVerifier(make(ed25519.PublicKey, 10)); err == nil {
		t.Error("長さが不正な公開鍵を受け付けた")
	}
}

func FuzzVerify(f *testing.F) {
	priv, err := keys.Generate()
	if err != nil {
		f.Fatal(err)
	}
	s, err := NewSigner(priv)
	if err != nil {
		f.Fatal(err)
	}
	v, err := NewVerifier(s.PublicKey())
	if err != nil {
		f.Fatal(err)
	}
	valid, err := json.Marshal(s.Sign(PurposePolicy, []byte(`{"version":1}`)))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"purpose":"policy","key_id":"","payload":"","signature":""}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var env Envelope
		if json.Unmarshal(data, &env) != nil {
			return
		}
		out, err := v.Verify(PurposePolicy, env)
		if err != nil {
			return
		}
		// 検証に通るのは、本物の署名が付いたデータだけのはず。
		if !ed25519.Verify(s.PublicKey(), message(PurposePolicy, out), env.Signature) {
			t.Fatalf("不正な署名が検証に通った: %q", data)
		}
	})
}
