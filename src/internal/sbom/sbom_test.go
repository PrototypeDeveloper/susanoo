package sbom

import (
	"encoding/json"
	"regexp"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

func testInfo() *debug.BuildInfo {
	return &debug.BuildInfo{
		GoVersion: "go1.26.8", Path: "susanoo/cmd/susanoo",
		Main: debug.Module{Path: "susanoo", Version: "(devel)"},
		Deps: []*debug.Module{
			{Path: "example.com/z", Version: "v1.2.3+incompatible", Sum: "h1:abc="},
			{Path: "example.com/a", Version: "v0.1.0", Replace: &debug.Module{Path: "example.com/a-fork", Version: "v0.1.1"}},
		},
		Settings: []debug.BuildSetting{
			{Key: "GOOS", Value: "linux"}, {Key: "GOARCH", Value: "amd64"}, {Key: "CGO_ENABLED", Value: "0"}, {Key: "-trimpath", Value: "true"},
			{Key: "vcs.revision", Value: "0123456789abcdef"}, {Key: "vcs.time", Value: "2026-10-19T05:03:21Z"}, {Key: "vcs.modified", Value: "false"},
		},
	}
}

// SPDX 2.3 の必須の項目を持ち、本体、標準ライブラリ、外部のモジュールを並べ、本体が依存する関係を書く。
func TestGenerate(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	data, err := Generate(testInfo(), Options{Name: "susanoo", Version: "0.1.0", License: "Apache-2.0", SHA256: sum})
	if err != nil {
		t.Fatal(err)
	}
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SPDXVersion != "SPDX-2.3" || doc.DataLicense != "CC0-1.0" || doc.SPDXID != "SPDXRef-DOCUMENT" || doc.Name != "susanoo-0.1.0" ||
		doc.CreationInfo.Created != "2026-10-19T05:03:21Z" || !strings.HasSuffix(doc.DocumentNamespace, "-"+sum) {
		t.Errorf("文書 = %+v", doc)
	}
	if len(doc.Packages) != 4 {
		t.Fatalf("部品 = %d 個", len(doc.Packages))
	}
	main, std := doc.Packages[0], doc.Packages[1]
	if main.VersionInfo != "0.1.0" || main.LicenseDeclared != "Apache-2.0" || main.Checksums[0].ChecksumValue != sum ||
		main.ExternalRefs[0].ReferenceLocator != "pkg:golang/susanoo@0.1.0" || !strings.Contains(main.Comment, "CGO_ENABLED=0") {
		t.Errorf("本体 = %+v", main)
	}
	if std.VersionInfo != "go1.26.8" || std.ExternalRefs[0].ReferenceLocator != "pkg:golang/stdlib@go1.26.8" || std.LicenseDeclared != "BSD-3-Clause" {
		t.Errorf("標準ライブラリ = %+v", std)
	}
	// 外部のモジュールは名前の順。置き換えたものは置き換え先。
	if a, z := doc.Packages[2], doc.Packages[3]; a.Name != "example.com/a-fork" || a.VersionInfo != "v0.1.1" ||
		z.ExternalRefs[0].ReferenceLocator != "pkg:golang/example.com/z@v1.2.3%2Bincompatible" {
		t.Errorf("外部のモジュール = %+v %+v", a, z)
	}
	idPattern := regexp.MustCompile(`^SPDXRef-[A-Za-z0-9.-]+$`)
	ids := map[string]bool{"SPDXRef-DOCUMENT": true}
	for _, p := range doc.Packages {
		if !idPattern.MatchString(p.SPDXID) || ids[p.SPDXID] {
			t.Errorf("識別子 %q が不正か重複しています", p.SPDXID)
		}
		ids[p.SPDXID] = true
	}
	for _, r := range doc.Relationships {
		if !ids[r.SPDXElementID] || !ids[r.RelatedSPDXElement] {
			t.Errorf("関係 %+v が知らない要素を指しています", r)
		}
	}
	if doc.Relationships[0].RelationshipType != "DESCRIBES" || len(doc.Relationships) != 4 {
		t.Errorf("関係 = %+v", doc.Relationships)
	}
	// 同じ入力からは同じ内容になる（再現できる）。
	again, _ := Generate(testInfo(), Options{Name: "susanoo", Version: "0.1.0", License: "Apache-2.0", SHA256: sum})
	if string(again) != string(data) {
		t.Error("同じ入力から違う SBOM ができました")
	}
}

func TestGenerateErrors(t *testing.T) {
	if _, err := Generate(nil, Options{Name: "susanoo", Version: "1"}); err == nil {
		t.Error("ビルドの情報がないのに作りました")
	}
	if _, err := Generate(testInfo(), Options{Name: "susanoo"}); err == nil {
		t.Error("版数がないのに作りました")
	}
	if _, err := Generate(testInfo(), Options{Name: "susanoo", Version: "1", SHA256: "xyz"}); err == nil {
		t.Error("不正なハッシュを受け付けました")
	}
	// コミットの時刻がなければ、渡した時計を使う。
	bi := testInfo()
	bi.Settings = nil
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	data, err := Generate(bi, Options{Name: "susanoo", Version: "1", Now: func() time.Time { return now }})
	if err != nil || !strings.Contains(string(data), `"created": "2026-01-02T03:04:05Z"`) {
		t.Errorf("作成の時刻 = %s %v", data, err)
	}
}
