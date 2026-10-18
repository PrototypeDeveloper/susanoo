package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var pass = []byte("correct horse battery staple")

func files(t testing.TB) (string, []Entry) {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, content string, mode os.FileMode) string {
		p := filepath.Join(dir, rel)
		os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	big := strings.Repeat("0123456789abcdef", 20000) // 区切り（64 KiB）を何個かまたぐ大きさ
	return dir, []Entry{
		{Name: "config/gw.json", Path: write("gw.json", `{"listen":"192.168.10.1:8443"}`, 0o600)},
		{Name: "pki/ca.key", Path: write("pki/ca.key", "PRIVATE", 0o600)},
		{Name: "pki/ca.crt", Path: write("pki/ca.crt", "CERT", 0o644)},
		{Name: "state/controller/audit.log", Path: write("state/audit.log", "{\"seq\":1}\n{\"seq\":2}\n{\"seq\":3,\"partial", 0o600), Log: true},
		{Name: "state/controller/big.bin", Path: write("state/big.bin", big, 0o600)},
	}
}

func create(t *testing.T, entries []Entry, opt Options) []byte {
	t.Helper()
	var buf bytes.Buffer
	opt.Now = time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	if _, err := Create(&buf, entries, opt); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestRoundTrip(t *testing.T) {
	_, entries := files(t)
	for name, opt := range map[string]Options{"暗号化": {Passphrase: pass, Version: "test"}, "暗号化なし": {Plain: true, Version: "test"}} {
		t.Run(name, func(t *testing.T) {
			data := create(t, entries, opt)
			if !opt.Plain && bytes.Contains(data, []byte("PRIVATE")) {
				t.Fatal("暗号化したのに秘密鍵が読める")
			}
			out := t.TempDir()
			m, err := Extract(bytes.NewReader(data), opt.Passphrase, out)
			if err != nil {
				t.Fatal(err)
			}
			if m.Format != FormatVersion || m.Encrypted == opt.Plain || len(m.Files) != len(entries) || m.Version != "test" {
				t.Errorf("目録 = %+v", m)
			}
			for _, e := range entries {
				want, _ := os.ReadFile(e.Path)
				if e.Log {
					want = want[:bytes.LastIndexByte(want, '\n')+1] // 書き込み中の最後の行は入れない
				}
				got, err := os.ReadFile(filepath.Join(out, e.Name))
				if err != nil || !bytes.Equal(got, want) {
					t.Errorf("%s = %q（%v）", e.Name, got[:min(len(got), 40)], err)
				}
			}
			if st, _ := os.Stat(filepath.Join(out, "pki/ca.key")); st.Mode().Perm() != 0o600 {
				t.Errorf("秘密鍵の権限 = %v", st.Mode())
			}
			if st, _ := os.Stat(filepath.Join(out, "pki/ca.crt")); st.Mode().Perm() != 0o644 {
				t.Errorf("証明書の権限 = %v", st.Mode())
			}
			// 確かめるだけなら書かない。
			if _, err := Extract(bytes.NewReader(data), opt.Passphrase, ""); err != nil {
				t.Errorf("確かめるだけ: %v", err)
			}
		})
	}
}

func TestEncryptionFailures(t *testing.T) {
	_, entries := files(t)
	data := create(t, entries, Options{Passphrase: pass})
	if bytes.Contains(data, []byte("PRIVATE")) || bytes.Contains(data, []byte("192.168.10.1")) {
		t.Fatal("暗号化したのに中身が読める")
	}
	if _, err := Extract(bytes.NewReader(data), []byte("wrong passphrase!!"), ""); !errors.Is(err, ErrPassphrase) {
		t.Errorf("違うパスフレーズ = %v", err)
	}
	if _, err := Extract(bytes.NewReader(data), nil, ""); err == nil || !strings.Contains(err.Error(), "パスフレーズ") {
		t.Errorf("パスフレーズなし = %v", err)
	}
	tampered := bytes.Clone(data)
	tampered[len(tampered)/2] ^= 1
	if _, err := Extract(bytes.NewReader(tampered), pass, ""); !errors.Is(err, ErrPassphrase) {
		t.Errorf("書き換え = %v", err)
	}
	// 区切りの切れ目で切り捨てても、最後の区切りがないので分かる。
	for _, cut := range []int{len(data) - 1, len(data) - (chunkSize + 16 + 4) + 0} {
		if cut <= 0 {
			continue
		}
		if _, err := Extract(bytes.NewReader(data[:cut]), pass, ""); err == nil {
			t.Errorf("%d バイトに切り捨てたものを受け付けた", cut)
		}
	}
	extra := append(bytes.Clone(data), 0, 0, 0, 0)
	if _, err := Extract(bytes.NewReader(extra), pass, ""); err == nil {
		t.Error("最後の区切りの後ろのデータを受け付けた")
	}
	if _, err := Create(&bytes.Buffer{}, entries, Options{Passphrase: []byte("short")}); err == nil {
		t.Error("短いパスフレーズを受け付けた")
	}
	if _, err := Create(&bytes.Buffer{}, entries, Options{}); err == nil {
		t.Error("パスフレーズも暗号化なしの明示もないのに作った")
	}
}

// 細工したバックアップ（決めた場所の外を指す名前、シンボリックリンク、目録と違う中身）は取り出さない。
func TestRejectsCraftedArchives(t *testing.T) {
	build := func(add func(tw *tar.Writer)) []byte {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		add(tw)
		tw.Close()
		gz.Close()
		return buf.Bytes()
	}
	file := func(tw *tar.Writer, name, content string) {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg})
		tw.Write([]byte(content))
	}
	manifest := func(tw *tar.Writer, files string) {
		file(tw, manifestName, `{"format":1,"encrypted":false,"files":`+files+`}`)
	}
	for name, data := range map[string][]byte{
		"外を指す名前": build(func(tw *tar.Writer) { file(tw, "state/../../etc/passwd", "x"); manifest(tw, "[]") }),
		"絶対パス":   build(func(tw *tar.Writer) { file(tw, "/etc/passwd", "x"); manifest(tw, "[]") }),
		"知らない場所": build(func(tw *tar.Writer) { file(tw, "home/x", "x"); manifest(tw, "[]") }),
		"シンボリックリンク": build(func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "state/link", Linkname: "/etc/shadow", Typeflag: tar.TypeSymlink})
			manifest(tw, "[]")
		}),
		"目録がない": build(func(tw *tar.Writer) { file(tw, "state/a", "x") }),
		"目録と違う中身": build(func(tw *tar.Writer) {
			file(tw, "state/a", "x")
			manifest(tw, `[{"name":"state/a","size":1,"sha256":"00"}]`)
		}),
		"目録にないファイル":  build(func(tw *tar.Writer) { file(tw, "state/a", "x"); manifest(tw, "[]") }),
		"目録の後ろのファイル": build(func(tw *tar.Writer) { manifest(tw, "[]"); file(tw, "state/a", "x") }),
		"バックアップでない":  []byte("hello, world. this is not a backup file at all"),
	} {
		out := t.TempDir()
		if _, err := Extract(bytes.NewReader(data), nil, out); err == nil {
			t.Errorf("%s を受け付けた", name)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(out), "etc")); err == nil {
			t.Errorf("%s で外に書いた", name)
		}
	}
	if err := validName("state/controller/devices.json"); err != nil {
		t.Errorf("正しい名前 = %v", err)
	}
	for _, bad := range []string{"state/", "state/./x", "state//x", "pki/../x", "config\\gw.json", ""} {
		if validName(bad) == nil {
			t.Errorf("%q を受け付けた", bad)
		}
	}
}

func TestLastNewline(t *testing.T) {
	dir := t.TempDir()
	for content, want := range map[string]int64{"": 0, "no newline": 0, "a\nb": 2, "a\nb\n": 4, strings.Repeat("x", 70000) + "\ny": 70001} {
		p := filepath.Join(dir, "f")
		os.WriteFile(p, []byte(content), 0o600)
		f, _ := os.Open(p)
		got, err := lastNewline(f, int64(len(content)))
		f.Close()
		if err != nil || got != want {
			t.Errorf("%.10q = %d, %v（期待値 %d）", content, got, err, want)
		}
	}
}
