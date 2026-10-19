// Package release は、署名付きのリリースの目録（api.ReleaseManifest）を確かめ、版数を比べる。
//
// リリースは、管理者の手元のポリシーの署名の鍵で目録に署名して配る（sign.PurposeRelease）。CONTROLLER を乗っ取られても、
// 署名のない実行ファイルや、目録のハッシュと合わない実行ファイルは配れない。CLIENT は今より新しい版数だけを受け付けるので、
// 古い（弱点のある）版に戻させる攻撃もできない。
package release

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"susanoo/internal/api"
	"susanoo/internal/sign"
)

const maxFiles = 16

var (
	versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(-[0-9A-Za-z.-]{1,64})?$`)
	namePattern    = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
)

// ValidVersion は版数が「数.数.数」か「数.数.数-印」の形かを返す（例 0.2.0、0.2.0-rc.1）。
func ValidVersion(v string) bool { return versionPattern.MatchString(v) }

// Compare は版数 a と b を比べ、a が古ければ負、同じなら 0、新しければ正を返す（セマンティックバージョニングの順）。
// 形の正しくない版数は、どの正しい版数よりも古いとみなす（ビルドの既定の dev など）。
func Compare(a, b string) int {
	ma, mb := versionPattern.FindStringSubmatch(a), versionPattern.FindStringSubmatch(b)
	switch {
	case ma == nil && mb == nil:
		return strings.Compare(a, b)
	case ma == nil:
		return -1
	case mb == nil:
		return 1
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(ma[i])
		y, _ := strconv.Atoi(mb[i])
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return comparePre(strings.TrimPrefix(ma[4], "-"), strings.TrimPrefix(mb[4], "-"))
}

// comparePre は印（プレリリース）を比べる。印のないほうが新しい。
func comparePre(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "":
		return 1
	case b == "":
		return -1
	}
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, ex := strconv.Atoi(pa[i])
		y, ey := strconv.Atoi(pb[i])
		switch {
		case ex == nil && ey == nil && x != y:
			if x < y {
				return -1
			}
			return 1
		case ex == nil && ey != nil:
			return -1 // 数だけの印は、文字を含む印より古い
		case ex != nil && ey == nil:
			return 1
		case pa[i] != pb[i]:
			return strings.Compare(pa[i], pb[i])
		}
	}
	switch {
	case len(pa) < len(pb):
		return -1
	case len(pa) > len(pb):
		return 1
	}
	return 0
}

// Verify は目録の署名を v で確かめ、中身を検証して返す。
func Verify(v *sign.Verifier, env sign.Envelope) (api.ReleaseManifest, error) {
	payload, err := v.Verify(sign.PurposeRelease, env)
	if err != nil {
		return api.ReleaseManifest{}, fmt.Errorf("release: 目録の署名を確かめられません: %w", err)
	}
	var m api.ReleaseManifest
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return api.ReleaseManifest{}, fmt.Errorf("release: 目録を解析できません: %w", err)
	}
	if err := Validate(m); err != nil {
		return api.ReleaseManifest{}, err
	}
	return m, nil
}

// Validate は目録の中身を確かめる。
func Validate(m api.ReleaseManifest) error {
	if !ValidVersion(m.Version) {
		return fmt.Errorf("release: 版数 %q は「数.数.数」の形にしてください", m.Version)
	}
	if m.IssuedAt.IsZero() {
		return errors.New("release: 目録に発行の時刻がありません")
	}
	if len(m.Files) == 0 || len(m.Files) > maxFiles {
		return fmt.Errorf("release: 実行ファイルは 1 個から %d 個にしてください", maxFiles)
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		key := f.OS + "/" + f.Arch
		if !namePattern.MatchString(f.OS) || !namePattern.MatchString(f.Arch) || seen[key] {
			return fmt.Errorf("release: OS と CPU %q が不正か、重なっています", key)
		}
		seen[key] = true
		if b, err := hex.DecodeString(f.SHA256); err != nil || len(b) != 32 || f.SHA256 != strings.ToLower(f.SHA256) {
			return fmt.Errorf("release: %s のハッシュが SHA-256 の 16 進数ではありません", key)
		}
		if f.Size <= 0 || f.Size > api.MaxReleaseBytes {
			return fmt.Errorf("release: %s の大きさ %d は 1 から %d バイトにしてください", key, f.Size, api.MaxReleaseBytes)
		}
	}
	return nil
}

// File は目録から OS と CPU の実行ファイルを探す。
func File(m api.ReleaseManifest, goos, goarch string) (api.ReleaseFile, bool) {
	for _, f := range m.Files {
		if f.OS == goos && f.Arch == goarch {
			return f, true
		}
	}
	return api.ReleaseFile{}, false
}
