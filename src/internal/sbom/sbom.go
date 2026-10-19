// Package sbom は、実行ファイルに埋め込まれたビルドの情報（runtime/debug.BuildInfo）から、SPDX 2.3 の SBOM（JSON）を作る。
//
// susanoo は標準ライブラリだけで作るので、部品は本体と Go の標準ライブラリ（ツールチェーンの版）になる。外部のモジュールを
// 使うようになったときのため、BuildInfo.Deps も部品として並べる。作るたびに同じ内容になるよう、作成の時刻はコミットの時刻
// （vcs.time）を使い、文書の名前空間は実行ファイルのハッシュから決める。
package sbom

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"
	"time"
)

// Options は SBOM に書く、BuildInfo にない情報。
type Options struct {
	Name     string    // 製品の名前（例: susanoo）
	Version  string    // 製品の版数（例: 0.1.0）
	License  string    // 製品のライセンス（SPDX の識別子。例: Apache-2.0）
	SHA256   string    // 実行ファイルの SHA-256（16 進。分からなければ空）
	Created  time.Time // 作成の時刻。ゼロならコミットの時刻（vcs.time）、それもなければ Now
	Now      func() time.Time
	ToolName string // 作った道具の名前（creators に書く）
}

// 文書の形（SPDX 2.3 の JSON のうち、使う項目）。
type document struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      creationInfo   `json:"creationInfo"`
	Packages          []pkg          `json:"packages"`
	Relationships     []relationship `json:"relationships"`
}

type creationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type pkg struct {
	Name                  string        `json:"name"`
	SPDXID                string        `json:"SPDXID"`
	VersionInfo           string        `json:"versionInfo,omitempty"`
	Supplier              string        `json:"supplier,omitempty"`
	DownloadLocation      string        `json:"downloadLocation"`
	FilesAnalyzed         bool          `json:"filesAnalyzed"`
	LicenseConcluded      string        `json:"licenseConcluded"`
	LicenseDeclared       string        `json:"licenseDeclared"`
	CopyrightText         string        `json:"copyrightText"`
	PrimaryPackagePurpose string        `json:"primaryPackagePurpose,omitempty"`
	Checksums             []checksum    `json:"checksums,omitempty"`
	ExternalRefs          []externalRef `json:"externalRefs,omitempty"`
	Comment               string        `json:"comment,omitempty"`
}

type checksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type externalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type relationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

const noAssertion = "NOASSERTION"

var (
	idUnsafe = regexp.MustCompile(`[^A-Za-z0-9.-]+`)
	hexSHA   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// spdxID は名前から SPDX の要素の識別子を作る（使える文字は英数字、「.」、「-」）。
func spdxID(prefix, name string) string {
	return "SPDXRef-" + prefix + "-" + strings.Trim(idUnsafe.ReplaceAllString(name, "-"), "-")
}

// purlVersion は版数を Package URL に書ける形にする。
func purlVersion(v string) string {
	if v == "" || v == "(devel)" {
		return ""
	}
	return "@" + strings.ReplaceAll(v, "+", "%2B")
}

// Generate は bi と opts から SPDX 2.3 の SBOM（JSON）を作る。
func Generate(bi *debug.BuildInfo, opts Options) ([]byte, error) {
	if bi == nil {
		return nil, errors.New("sbom: ビルドの情報がありません")
	}
	if opts.Name == "" || opts.Version == "" {
		return nil, errors.New("sbom: 製品の名前と版数が必要です")
	}
	if opts.SHA256 != "" && !hexSHA.MatchString(opts.SHA256) {
		return nil, fmt.Errorf("sbom: SHA-256 の形が正しくありません: %q", opts.SHA256)
	}
	settings := map[string]string{}
	for _, s := range bi.Settings {
		settings[s.Key] = s.Value
	}
	created := opts.Created
	if created.IsZero() {
		if t, err := time.Parse(time.RFC3339, settings["vcs.time"]); err == nil {
			created = t
		} else if opts.Now != nil {
			created = opts.Now()
		} else {
			created = time.Now()
		}
	}
	// 文書の名前空間は、同じ実行ファイルなら同じになるようにする（ハッシュ、なければコミットと版数）。
	unique := cmp.Or(opts.SHA256, settings["vcs.revision"], fmt.Sprint(created.Unix()))
	if settings["vcs.modified"] == "true" && opts.SHA256 == "" {
		unique += "-modified"
	}
	doc := document{
		SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT",
		Name:              opts.Name + "-" + opts.Version,
		DocumentNamespace: "https://spdx.org/spdxdocs/" + opts.Name + "-" + opts.Version + "-" + unique,
		CreationInfo:      creationInfo{Created: created.UTC().Format(time.RFC3339), Creators: []string{"Tool: " + cmp.Or(opts.ToolName, opts.Name+"-sbom")}},
	}

	// 本体。ビルドの設定（OS、CPU、cgo、-trimpath、コミット）を注記に残す。
	var notes []string
	for _, k := range []string{"GOOS", "GOARCH", "GOAMD64", "GOARM64", "CGO_ENABLED", "-trimpath", "-buildmode", "vcs.revision", "vcs.time", "vcs.modified"} {
		if v, ok := settings[k]; ok {
			notes = append(notes, k+"="+v)
		}
	}
	main := pkg{
		Name: opts.Name, SPDXID: spdxID("Package", opts.Name), VersionInfo: opts.Version, DownloadLocation: noAssertion,
		LicenseConcluded: cmp.Or(opts.License, noAssertion), LicenseDeclared: cmp.Or(opts.License, noAssertion), CopyrightText: noAssertion,
		PrimaryPackagePurpose: "APPLICATION",
		ExternalRefs:          []externalRef{{"PACKAGE-MANAGER", "purl", "pkg:golang/" + bi.Main.Path + purlVersion(opts.Version)}},
		Comment:               "Go のモジュール " + bi.Main.Path + "（パッケージ " + bi.Path + "）。ビルドの設定: " + strings.Join(notes, " "),
	}
	if opts.SHA256 != "" {
		main.Checksums = []checksum{{"SHA256", opts.SHA256}}
	}
	doc.Packages = append(doc.Packages, main)
	doc.Relationships = append(doc.Relationships, relationship{"SPDXRef-DOCUMENT", "DESCRIBES", main.SPDXID})

	// Go の標準ライブラリとランタイム（ツールチェーンの版）。
	stdlib := pkg{
		Name: "stdlib", SPDXID: spdxID("Package", "stdlib"), VersionInfo: bi.GoVersion, Supplier: "Organization: Go Authors",
		DownloadLocation: "https://go.dev/dl/", LicenseConcluded: "BSD-3-Clause", LicenseDeclared: "BSD-3-Clause", CopyrightText: noAssertion,
		PrimaryPackagePurpose: "LIBRARY",
		ExternalRefs:          []externalRef{{"PACKAGE-MANAGER", "purl", "pkg:golang/stdlib" + purlVersion(bi.GoVersion)}},
	}
	doc.Packages = append(doc.Packages, stdlib)
	doc.Relationships = append(doc.Relationships, relationship{main.SPDXID, "DEPENDS_ON", stdlib.SPDXID})

	// 外部のモジュール（今はない）。置き換えたモジュールは置き換え先を書く。
	deps := slices.Clone(bi.Deps)
	slices.SortFunc(deps, func(a, b *debug.Module) int { return strings.Compare(a.Path, b.Path) })
	for _, d := range deps {
		m := d
		if d.Replace != nil {
			m = d.Replace
		}
		p := pkg{
			Name: m.Path, SPDXID: spdxID("Package", m.Path+"-"+m.Version), VersionInfo: m.Version, DownloadLocation: noAssertion,
			LicenseConcluded: noAssertion, LicenseDeclared: noAssertion, CopyrightText: noAssertion, PrimaryPackagePurpose: "LIBRARY",
			ExternalRefs: []externalRef{{"PACKAGE-MANAGER", "purl", "pkg:golang/" + m.Path + purlVersion(m.Version)}},
		}
		if m.Sum != "" {
			p.Comment = "go.sum のハッシュ: " + m.Sum
		}
		doc.Packages = append(doc.Packages, p)
		doc.Relationships = append(doc.Relationships, relationship{main.SPDXID, "DEPENDS_ON", p.SPDXID})
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
