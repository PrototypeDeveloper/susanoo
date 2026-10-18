package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"susanoo/internal/keys"
	"susanoo/internal/sign"
)

func newSigner(t *testing.T) *sign.Signer {
	t.Helper()
	priv, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	s, err := sign.NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func signed(t *testing.T, s *sign.Signer, p sign.Purpose, version int, name string) sign.Envelope {
	t.Helper()
	set := Set{Version: version, Name: name, IssuedAt: now, Rules: []Rule{{ID: "honeytoken", Name: "x", Finding: "honeytoken", Mode: ModeMonitor}}}
	data, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return s.Sign(p, data)
}

func TestStore(t *testing.T) {
	signer := newSigner(t)
	dir := t.TempDir()
	st, err := OpenStore(dir, signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if st.Current() != nil || len(st.Versions()) != 0 {
		t.Fatal("空の保存先に版がある")
	}
	if _, err := st.Apply(signed(t, signer, sign.PurposeRules, 1, "一"), now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Apply(signed(t, signer, sign.PurposeRules, 3, "三"), now); err != nil {
		t.Fatal(err)
	}
	for name, env := range map[string]sign.Envelope{
		"古い版":     signed(t, signer, sign.PurposeRules, 2, "二"),
		"同じ版":     signed(t, signer, sign.PurposeRules, 3, "三"),
		"ポリシーの署名": signed(t, signer, sign.PurposePolicy, 4, "四"),
		"ほかの鍵":    signed(t, newSigner(t), sign.PurposeRules, 4, "四"),
	} {
		if _, err := st.Apply(env, now); err == nil {
			t.Errorf("%s を受け付けた", name)
		}
	}
	if st.Current().Version != 3 || len(st.Versions()) != 2 {
		t.Errorf("今の版 = %d、版の数 = %d", st.Current().Version, len(st.Versions()))
	}
	payload, err := st.Payload(1)
	if err != nil || !strings.Contains(string(payload), `"name":"一"`) {
		t.Errorf("版 1 の中身 = %s %v", payload, err)
	}
	if _, err := st.Payload(2); err == nil {
		t.Error("ない版の中身を返した")
	}

	// 開き直すと、署名を確かめ直して最新の版を使う。
	st2, err := OpenStore(dir, signer.PublicKey())
	if err != nil || st2.Current().Version != 3 || st2.Versions()[1].AppliedAt.IsZero() {
		t.Fatalf("開き直した保存先 = %v %v", st2, err)
	}
	if _, err := OpenStore(dir, newSigner(t).PublicKey()); err == nil {
		t.Error("ほかの鍵で開けた")
	}
	// 書き換えた版は開けない。
	path := filepath.Join(dir, "v3.json")
	data, _ := os.ReadFile(path)
	var env sign.Envelope
	json.Unmarshal(data, &env)
	env.Payload = []byte(strings.Replace(string(env.Payload), `"monitor"`, `"off"`, 1))
	data, _ = json.Marshal(env)
	os.WriteFile(path, data, 0o600)
	if _, err := OpenStore(dir, signer.PublicKey()); err == nil {
		t.Error("書き換えた版を開けた")
	}
}
