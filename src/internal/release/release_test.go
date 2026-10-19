package release

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/keys"
	"susanoo/internal/sign"
)

func TestCompare(t *testing.T) {
	// 古い順。
	order := []string{"dev", "0.1.0-dev", "0.1.0-lab", "0.1.0-rc.1", "0.1.0-rc.2", "0.1.0-rc.10", "0.1.0", "0.1.1", "0.2.0", "1.0.0", "10.0.0"}
	for i := range order {
		for j := range order {
			got := Compare(order[i], order[j])
			if (i < j && got >= 0) || (i == j && got != 0) || (i > j && got <= 0) {
				t.Errorf("Compare(%q, %q) = %d", order[i], order[j], got)
			}
		}
	}
	for _, bad := range []string{"", "1", "1.2", "v1.2.3", "01.2.3", "1.2.3-", "1.2.3-a b", "1.2.3/../x"} {
		if ValidVersion(bad) {
			t.Errorf("%q を正しい版数とした", bad)
		}
	}
}

func manifest() api.ReleaseManifest {
	return api.ReleaseManifest{Version: "0.2.0", IssuedAt: time.Now().UTC(), Files: []api.ReleaseFile{
		{OS: "linux", Arch: "amd64", SHA256: strings.Repeat("ab", 32), Size: 100},
		{OS: "linux", Arch: "arm64", SHA256: strings.Repeat("cd", 32), Size: 200},
	}}
}

// 目録は管理者の鍵の、リリースの用途の署名だけを受け付け、中身の形を確かめる。
func TestVerify(t *testing.T) {
	priv, _ := keys.Generate()
	s, _ := sign.NewSigner(priv)
	v, _ := sign.NewVerifier(s.PublicKey())
	data, _ := json.Marshal(manifest())
	m, err := Verify(v, s.Sign(sign.PurposeRelease, data))
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := File(m, "linux", "arm64"); !ok || f.Size != 200 {
		t.Errorf("arm64 のファイル = %+v %v", f, ok)
	}
	if _, ok := File(m, "linux", "riscv64"); ok {
		t.Error("ない CPU のファイルを返した")
	}
	if _, err := Verify(v, s.Sign(sign.PurposePolicy, data)); err == nil {
		t.Error("ポリシーの用途の署名を受け付けた")
	}
	other, _ := keys.Generate()
	os2, _ := sign.NewSigner(other)
	if _, err := Verify(v, os2.Sign(sign.PurposeRelease, data)); err == nil {
		t.Error("別の鍵の署名を受け付けた")
	}
	for name, mod := range map[string]func(*api.ReleaseManifest){
		"版数の形":     func(m *api.ReleaseManifest) { m.Version = "latest" },
		"ファイルなし":   func(m *api.ReleaseManifest) { m.Files = nil },
		"重なる CPU":  func(m *api.ReleaseManifest) { m.Files[1].Arch = "amd64" },
		"ハッシュの形":   func(m *api.ReleaseManifest) { m.Files[0].SHA256 = "xyz" },
		"大文字のハッシュ": func(m *api.ReleaseManifest) { m.Files[0].SHA256 = strings.Repeat("AB", 32) },
		"大きすぎる":    func(m *api.ReleaseManifest) { m.Files[0].Size = api.MaxReleaseBytes + 1 },
		"OS の名前":   func(m *api.ReleaseManifest) { m.Files[0].OS = "../x" },
		"発行の時刻なし":  func(m *api.ReleaseManifest) { m.IssuedAt = time.Time{} },
	} {
		m := manifest()
		mod(&m)
		data, _ := json.Marshal(m)
		if _, err := Verify(v, s.Sign(sign.PurposeRelease, data)); err == nil {
			t.Errorf("%s の不正な目録を受け付けた", name)
		}
	}
}
