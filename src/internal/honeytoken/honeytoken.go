// Package honeytoken はおとり（ハニートークン）の作成と管理を扱う（C5）。
//
// おとりは偽の認証情報や秘密鍵を本物らしい場所に置いたファイルで、正規の利用者が触ることはまずないため、
// 触られたら高い確度で不正な探索とみなせる。既存のファイルは決して上書きせず、
// 置いたおとりの一覧とハッシュを状態ファイルに記録する。触られたことの検知は OS ごとの Platform が行う。
package honeytoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"susanoo/internal/event"
	"susanoo/internal/fsutil"
)

// Spec は設定ファイルに書くおとりの指定。
type Spec struct {
	Path string `json:"path"`
	Kind Kind   `json:"kind"`
}

// Token は置いたおとり。
type Token struct {
	Path    string    `json:"path"`
	Kind    Kind      `json:"kind"`
	SHA256  string    `json:"sha256"`
	Created time.Time `json:"created"`
}

type state struct {
	Tokens []Token `json:"tokens"`
}

// Plant は specs のおとりを置き、監視すべきおとりの一覧を返す。
//
// 状態ファイル statePath に記録のないファイルが既にある場合は、本物のファイルを壊さないよう置かない。
// 記録のあるおとりが消えていたら置き直し、中身が変わっていたら警告して監視は続ける。
// 個々のおとりの問題は warnings で返し、状態ファイルを読み書きできないときだけ err を返す。
func Plant(specs []Spec, statePath string, now time.Time) (tokens []Token, warnings []error, err error) {
	known, err := loadState(statePath)
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]bool{}
	for _, s := range specs {
		if seen[s.Path] {
			warnings = append(warnings, fmt.Errorf("honeytoken: %s が重複しています", s.Path))
			continue
		}
		seen[s.Path] = true
		tok, warn := plantOne(s, known[s.Path], now)
		if warn != nil {
			warnings = append(warnings, warn)
		}
		if tok != nil {
			tokens = append(tokens, *tok)
		}
	}
	if err := saveState(statePath, tokens); err != nil {
		return nil, warnings, err
	}
	return tokens, warnings, nil
}

func plantOne(s Spec, known *Token, now time.Time) (*Token, error) {
	if !filepath.IsAbs(s.Path) {
		return nil, fmt.Errorf("honeytoken: %s は絶対パスで指定してください", s.Path)
	}
	path := filepath.Clean(s.Path)
	fi, err := os.Lstat(path)
	switch {
	case err == nil && known == nil:
		return nil, fmt.Errorf("honeytoken: %s には既存のファイルがあるため、おとりを置きません", path)
	case err == nil:
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("honeytoken: おとり %s が通常のファイルではなくなっています", path)
		}
		sum, err := fileSHA256(path)
		if err != nil {
			return known, fmt.Errorf("honeytoken: おとり %s を確認できません: %w", path, err)
		}
		if sum != known.SHA256 {
			return known, fmt.Errorf("honeytoken: おとり %s の中身が変わっています", path)
		}
		return known, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("honeytoken: %s を確認できません: %w", path, err)
	}

	content, err := Generate(s.Kind)
	if err != nil {
		return nil, err
	}
	if err := create(path, content); err != nil {
		return nil, fmt.Errorf("honeytoken: おとり %s を置けません: %w", path, err)
	}
	sum := sha256.Sum256(content)
	tok := &Token{Path: path, Kind: s.Kind, SHA256: hex.EncodeToString(sum[:]), Created: now.UTC()}
	if known != nil {
		return tok, fmt.Errorf("honeytoken: おとり %s が消えていたため、置き直しました", path)
	}
	return tok, nil
}

// create は親ディレクトリを作り、新しいファイルとして content を書く。
// 既にファイルやシンボリックリンクがあれば失敗する。root で動いているときは、
// 既存の最も近い親ディレクトリの持ち主に、作ったディレクトリとファイルの持ち主を合わせる。
func create(path string, content []byte) error {
	var created []string
	dir := filepath.Dir(path)
	for {
		if _, err := os.Lstat(dir); err == nil {
			break
		}
		created = append(created, dir)
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	owner, err := ownerOf(dir)
	if err != nil {
		return err
	}
	for i := len(created) - 1; i >= 0; i-- {
		if err := os.Mkdir(created[i], 0o700); err != nil {
			return err
		}
		if err := owner.chown(created[i]); err != nil {
			return err
		}
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return owner.chown(path)
}

type owner struct {
	uid, gid int
	apply    bool
}

func ownerOf(dir string) (owner, error) {
	if os.Geteuid() != 0 {
		return owner{}, nil
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return owner{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return owner{}, nil
	}
	return owner{uid: int(st.Uid), gid: int(st.Gid), apply: true}, nil
}

func (o owner) chown(path string) error {
	if !o.apply {
		return nil
	}
	return os.Lchown(path, o.uid, o.gid)
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func loadState(path string) (map[string]*Token, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]*Token{}, nil
	}
	if err != nil {
		return nil, err
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("honeytoken: 状態ファイル %s を解析できません: %w", path, err)
	}
	known := make(map[string]*Token, len(s.Tokens))
	for i := range s.Tokens {
		known[s.Tokens[i].Path] = &s.Tokens[i]
	}
	return known, nil
}

func saveState(path string, tokens []Token) error {
	data, err := json.MarshalIndent(state{Tokens: tokens}, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, append(data, '\n'), 0o600)
}

// 検知した操作の種類。
const (
	OpOpen   = "open"
	OpAccess = "access"
	OpModify = "modify"
	OpExec   = "exec"
	OpAttrib = "attrib"
	OpDelete = "delete"
	OpMove   = "move"
)

var opLabels = map[string]string{
	OpOpen:   "開かれました",
	OpAccess: "読まれました",
	OpModify: "書き換えられました",
	OpExec:   "実行されました",
	OpAttrib: "属性を変えられました",
	OpDelete: "削除されました",
	OpMove:   "移動されました",
}

// Finding はおとりへの接触を表す検知結果のイベントを作る。proc は分からなければ nil。
func Finding(t Token, op string, proc *event.Process, at time.Time) *event.Event {
	who := "不明なプロセス"
	if proc != nil && proc.Name != "" {
		who = fmt.Sprintf("%s（PID %d）", proc.Name, proc.PID)
	} else if proc != nil && proc.PID > 0 {
		who = fmt.Sprintf("PID %d", proc.PID)
	}
	label, ok := opLabels[op]
	if !ok {
		label = "操作されました"
	}
	msg := fmt.Sprintf("おとり %s が %s によって%s", t.Path, who, label)

	e := event.New(event.ClassDetectionFinding, event.FindingCreate, event.SeverityHigh, at)
	e.Message = msg
	e.FindingInfo = &event.FindingInfo{
		UID:   rand.Text(),
		Title: "おとりへの接触",
		Desc:  msg,
		Types: []string{event.FindingTypeHoneytoken},
	}
	e.Evidences = []event.Evidence{{
		File:    &event.File{Name: filepath.Base(t.Path), Path: t.Path},
		Process: proc,
	}}
	e.Unmapped = map[string]any{"honeytoken": map[string]any{"kind": string(t.Kind), "operation": op}}
	return e
}
