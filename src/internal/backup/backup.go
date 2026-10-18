// Package backup は GW（CONTROLLER を含む）の設定とポリシー、鍵、状態のバックアップと復元を扱う（M11）。
//
// バックアップは tar を gzip で縮めたもので、認証局とポリシーの署名の秘密鍵を含むため、既定ではパスフレーズで暗号化する
// （crypt.go）。最後に、すべてのファイルの大きさと SHA-256 を書いた manifest.json を入れ、取り出すときに確かめる。
// 書き込み中のログ（監査ログ、イベント）は、読み始めた時点の最後の改行までを入れる（途中の行を入れない）。
package backup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// FormatVersion はバックアップの形式の版。
const FormatVersion = 1

// manifestName は、すべてのファイルを書いた後に入れる目録の名前。
const manifestName = "manifest.json"

// 取り出すときの上限（壊れたファイルや、細工したファイルでディスクを使い切らないように）。
const (
	maxFileBytes  = 4 << 30
	maxTotalBytes = 16 << 30
	maxFiles      = 200000
)

// Prefixes はバックアップの中の場所の種類。config は設定ファイル、pki は鍵と証明書、state は状態のディレクトリ。
var Prefixes = []string{"config/", "pki/", "state/"}

// Entry はバックアップに入れる 1 つのファイル。
type Entry struct {
	Name string // バックアップの中の名前（config/gw.json など）
	Path string // ディスクの場所
	Log  bool   // 書き込み中かもしれないログ（最後の改行までを入れる）
}

// FileInfo は目録に書くファイルの情報。
type FileInfo struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
}

// Manifest はバックアップの目録。
type Manifest struct {
	Format    int        `json:"format"`
	Version   string     `json:"version"` // 作った susanoo の版
	Created   time.Time  `json:"created"`
	Encrypted bool       `json:"encrypted"`
	Files     []FileInfo `json:"files"`
	Excluded  []string   `json:"excluded,omitempty"` // 入れなかったもの（イベントなど）の説明
}

// Options はバックアップの作り方。
type Options struct {
	Passphrase []byte // 空なら暗号化しない（Plain が必要）
	Plain      bool   // 暗号化しないことを明示する
	Version    string
	Excluded   []string
	Now        time.Time
}

// Create は entries を w にバックアップとして書き、目録を返す。
func Create(w io.Writer, entries []Entry, opt Options) (Manifest, error) {
	m := Manifest{Format: FormatVersion, Version: opt.Version, Created: opt.Now.UTC(), Excluded: opt.Excluded}
	if opt.Now.IsZero() {
		m.Created = time.Now().UTC()
	}
	var sink io.Writer = w
	var enc *encryptWriter
	switch {
	case len(opt.Passphrase) > 0:
		var err error
		if enc, err = newEncryptWriter(w, opt.Passphrase); err != nil {
			return m, err
		}
		sink, m.Encrypted = enc, true
	case !opt.Plain:
		return m, errors.New("backup: パスフレーズがありません（暗号化しないなら、それを明示してください）")
	}
	gz := gzip.NewWriter(sink)
	tw := tar.NewWriter(gz)
	seen := map[string]bool{}
	for _, e := range entries {
		if err := validName(e.Name); err != nil {
			return m, err
		}
		if seen[e.Name] {
			return m, fmt.Errorf("backup: %s が重複しています", e.Name)
		}
		seen[e.Name] = true
		fi, err := addFile(tw, e, m.Created)
		if err != nil {
			return m, fmt.Errorf("backup: %s: %w", e.Path, err)
		}
		m.Files = append(m.Files, fi)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return m, err
	}
	if err := tw.WriteHeader(&tar.Header{Name: manifestName, Mode: 0o600, Size: int64(len(data)), ModTime: m.Created, Typeflag: tar.TypeReg}); err != nil {
		return m, err
	}
	if _, err := tw.Write(data); err != nil {
		return m, err
	}
	if err := tw.Close(); err != nil {
		return m, err
	}
	if err := gz.Close(); err != nil {
		return m, err
	}
	if enc != nil {
		return m, enc.Close()
	}
	return m, nil
}

// addFile はファイルを 1 つ入れる。ログは、読み始めた時点の最後の改行までを入れる。
func addFile(tw *tar.Writer, e Entry, at time.Time) (FileInfo, error) {
	f, err := os.Open(e.Path)
	if err != nil {
		return FileInfo{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return FileInfo{}, err
	}
	if !st.Mode().IsRegular() {
		return FileInfo{}, errors.New("通常のファイルではありません")
	}
	size := st.Size()
	if e.Log {
		if size, err = lastNewline(f, size); err != nil {
			return FileInfo{}, err
		}
	}
	mode := uint32(st.Mode().Perm())
	if err := tw.WriteHeader(&tar.Header{Name: e.Name, Mode: int64(mode), Size: size, ModTime: at, Typeflag: tar.TypeReg}); err != nil {
		return FileInfo{}, err
	}
	h := sha256.New()
	if _, err := io.CopyN(io.MultiWriter(tw, h), f, size); err != nil {
		return FileInfo{}, err
	}
	return FileInfo{Name: e.Name, Size: size, Mode: mode, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// lastNewline は、ファイルの先頭 size バイトのうち、最後の改行の直後の位置を返す（改行がなければ 0）。
func lastNewline(f *os.File, size int64) (int64, error) {
	buf := make([]byte, 64<<10)
	for end := size; end > 0; {
		start := max(end-int64(len(buf)), 0)
		n, err := f.ReadAt(buf[:end-start], start)
		if err != nil && err != io.EOF {
			return 0, err
		}
		if i := bytes.LastIndexByte(buf[:n], '\n'); i >= 0 {
			return start + int64(i) + 1, nil
		}
		end = start
	}
	return 0, nil
}

// validName はバックアップの中の名前が、決めた場所の下の、正規化された相対パスかを確かめる。
func validName(name string) error {
	if name != path.Clean(name) || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || slices.Contains(strings.Split(name, "/"), "..") ||
		!slices.ContainsFunc(Prefixes, func(p string) bool { return strings.HasPrefix(name, p) && len(name) > len(p) }) {
		return fmt.Errorf("backup: バックアップの中の名前 %q が不正です", name)
	}
	return nil
}

// Extract はバックアップを読み、dir の下に取り出す（dir が空なら書かずに確かめるだけ）。すべてのファイルの大きさとハッシュを
// 目録と比べ、目録にないファイル、足りないファイル、違うファイルがあればエラーを返す。
func Extract(r io.Reader, passphrase []byte, dir string) (Manifest, error) {
	br := bufio.NewReader(r)
	head, err := br.Peek(len(encMagic))
	if err != nil && !bytes.HasPrefix(head, []byte(plainMagic)) {
		return Manifest{}, errors.New("backup: susanoo のバックアップではありません")
	}
	var src io.Reader = br
	encrypted := false
	switch {
	case string(head) == encMagic:
		if len(passphrase) == 0 {
			return Manifest{}, errors.New("backup: 暗号化したバックアップです。パスフレーズを指定してください")
		}
		br.Discard(len(encMagic))
		d, err := newDecryptReader(br, passphrase)
		if err != nil {
			return Manifest{}, err
		}
		src, encrypted = d, true
	case bytes.HasPrefix(head, []byte(plainMagic)):
	default:
		return Manifest{}, errors.New("backup: susanoo のバックアップではありません")
	}
	gz, err := gzip.NewReader(src)
	if err != nil {
		return Manifest{}, wrapCrypt(err, encrypted)
	}
	tr := tar.NewReader(gz)
	got := map[string]FileInfo{}
	var m *Manifest
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, wrapCrypt(err, encrypted)
		}
		if m != nil {
			return Manifest{}, errors.New("backup: 目録の後ろにファイルがあります")
		}
		if h.Typeflag != tar.TypeReg {
			return Manifest{}, fmt.Errorf("backup: 通常のファイルでない %q は取り出しません", h.Name)
		}
		if h.Size < 0 || h.Size > maxFileBytes || total+h.Size > maxTotalBytes || len(got) >= maxFiles {
			return Manifest{}, errors.New("backup: 大きすぎるか、ファイルが多すぎます")
		}
		total += h.Size
		if h.Name == manifestName {
			data, err := io.ReadAll(io.LimitReader(tr, 64<<20))
			if err != nil {
				return Manifest{}, wrapCrypt(err, encrypted)
			}
			m = &Manifest{}
			if err := json.Unmarshal(data, m); err != nil {
				return Manifest{}, fmt.Errorf("backup: 目録を読めません: %w", err)
			}
			continue
		}
		if err := validName(h.Name); err != nil {
			return Manifest{}, err
		}
		if _, dup := got[h.Name]; dup {
			return Manifest{}, fmt.Errorf("backup: %s が重複しています", h.Name)
		}
		fi, err := extractFile(tr, h, dir)
		if err != nil {
			return Manifest{}, wrapCrypt(err, encrypted)
		}
		got[h.Name] = fi
	}
	if m == nil {
		return Manifest{}, errors.New("backup: 目録がありません（途中で切れています）")
	}
	if m.Format != FormatVersion {
		return Manifest{}, fmt.Errorf("backup: 対応していない形式の版 %d です", m.Format)
	}
	if m.Encrypted != encrypted {
		return Manifest{}, errors.New("backup: 目録の暗号化の有無が実際と違います")
	}
	if len(m.Files) != len(got) {
		return Manifest{}, fmt.Errorf("backup: 目録のファイルの数（%d）と、入っていた数（%d）が違います", len(m.Files), len(got))
	}
	for _, want := range m.Files {
		g, ok := got[want.Name]
		if !ok || g.Size != want.Size || g.SHA256 != want.SHA256 {
			return Manifest{}, fmt.Errorf("backup: %s が目録と違います", want.Name)
		}
	}
	return *m, nil
}

// wrapCrypt は、暗号化したバックアップの読み取りの失敗を ErrPassphrase にする。復号の途中で失敗すると、gzip や tar が
// 「壊れている」などの別のエラーを返すことがあるため。書き込みの失敗（ディスクの権限など）はそのまま返す。
func wrapCrypt(err error, encrypted bool) error {
	var pe *fs.PathError
	if encrypted && !errors.As(err, &pe) {
		return ErrPassphrase
	}
	return err
}

// extractFile はファイルを 1 つ取り出し、ハッシュを計算する。dir が空なら書かない。
func extractFile(tr *tar.Reader, h *tar.Header, dir string) (FileInfo, error) {
	hash := sha256.New()
	fi := FileInfo{Name: h.Name, Size: h.Size, Mode: uint32(h.Mode) & 0o755}
	if dir == "" {
		if _, err := io.CopyN(hash, tr, h.Size); err != nil {
			return fi, err
		}
		fi.SHA256 = hex.EncodeToString(hash.Sum(nil))
		return fi, nil
	}
	dst := filepath.Join(dir, filepath.FromSlash(h.Name))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fi, err
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(fi.Mode))
	if err != nil {
		return fi, err
	}
	if _, err := io.CopyN(io.MultiWriter(f, hash), tr, h.Size); err != nil {
		f.Close()
		return fi, err
	}
	if err := f.Close(); err != nil {
		return fi, err
	}
	fi.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return fi, nil
}
