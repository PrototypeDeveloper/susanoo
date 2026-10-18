package rules

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"susanoo/internal/fsutil"
	"susanoo/internal/sign"
)

// Store は配布した検知ルールの版の保存先（M3）。
//
// 署名（管理者のポリシー専用の鍵、用途は sign.PurposeRules）と版数を確かめてから保存し、受け付けた最大の版を今の版にする。
// それ以下の版は受け付けない（古い版を送り直す巻き戻しを防ぐ）。古い内容に戻すときは、新しい版数を付けて配布し直す。
// 保存した版は、開くたびに署名を確かめ直す。
type Store struct {
	dir      string
	verifier *sign.Verifier

	mu      sync.Mutex
	index   []Version
	current *Set
}

// Version は保存した版の概要。
type Version struct {
	Version   int       `json:"version"`
	Name      string    `json:"name"`
	IssuedAt  time.Time `json:"issued_at"`
	AppliedAt time.Time `json:"applied_at"` // 受け付けた時刻
}

const indexFile = "index.json"

func versionFile(v int) string { return fmt.Sprintf("v%d.json", v) }

// OpenStore は dir の保存先を開く。pub は署名を確かめる公開鍵。
func OpenStore(dir string, pub ed25519.PublicKey) (*Store, error) {
	verifier, err := sign.NewVerifier(pub)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, verifier: verifier}
	data, err := os.ReadFile(filepath.Join(dir, indexFile))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(data, &s.index); err != nil {
		return nil, fmt.Errorf("rules: %s を解析できません: %w", indexFile, err)
	}
	if len(s.index) > 0 {
		if _, s.current, err = s.load(s.index[len(s.index)-1].Version); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// load は保存した版を、署名を確かめ直して読む。署名した中身（JSON）も返す。
func (s *Store) load(v int) ([]byte, *Set, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, versionFile(v)))
	if err != nil {
		return nil, nil, err
	}
	var env sign.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, nil, fmt.Errorf("rules: 版 %d を解析できません: %w", v, err)
	}
	payload, err := s.verifier.Verify(sign.PurposeRules, env)
	if err != nil {
		return nil, nil, fmt.Errorf("rules: 版 %d: %w", v, err)
	}
	set, err := Parse(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("rules: 版 %d: %w", v, err)
	}
	if set.Version != v {
		return nil, nil, fmt.Errorf("rules: %s の版数が %d です", versionFile(v), set.Version)
	}
	return payload, set, nil
}

// Current は今の版を返す（まだ配布していなければ nil）。
func (s *Store) Current() *Set {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}

// Versions は保存した版の一覧を古い順に返す。
func (s *Store) Versions() []Version {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.index)
}

// Payload は版 v の中身（署名を確かめた JSON。管理者が書いたまま）を返す。
func (s *Store) Payload(v int) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !slices.ContainsFunc(s.index, func(r Version) bool { return r.Version == v }) {
		return nil, fs.ErrNotExist
	}
	payload, _, err := s.load(v)
	return payload, err
}

// Apply は署名付きの版を確かめて保存し、今の版にする。
func (s *Store) Apply(env sign.Envelope, now time.Time) (*Set, error) {
	set, err := ParseSigned(s.verifier, env)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := len(s.index); n > 0 && set.Version <= s.index[n-1].Version {
		return nil, fmt.Errorf("rules: 版数 %d は受け付けた版数 %d より新しくありません", set.Version, s.index[n-1].Version)
	}
	data, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(s.dir, versionFile(set.Version)), data, 0o600); err != nil {
		return nil, err
	}
	index := append(slices.Clone(s.index), Version{Version: set.Version, Name: set.Name, IssuedAt: set.IssuedAt, AppliedAt: now.UTC()})
	data, err = json.MarshalIndent(index, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(s.dir, indexFile), append(data, '\n'), 0o600); err != nil {
		return nil, err
	}
	s.index, s.current = index, set
	return set, nil
}
