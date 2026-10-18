package intel

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"susanoo/internal/fsutil"
	"susanoo/internal/sign"
)

// Store は GW の執行部が持つ、脅威情報の保存先。
//
// 署名（管理者のポリシー専用の鍵、用途は sign.PurposeIntel）と版数を確かめてから保存し、受け付けた最大の版数より
// 新しい版だけを受け付ける（古い版を送り直す巻き戻しを防ぐ）。保存先は root だけが読み書きできるディレクトリに置き、
// 開くたびに署名を確かめ直す。一覧を戻すときは、管理者が取り込み直して新しい版として配布する。
type Store struct {
	dir      string
	verifier *sign.Verifier

	mu      sync.Mutex
	current *Set
	payload []byte
}

const currentFile = "current.json"

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
	data, err := os.ReadFile(filepath.Join(dir, currentFile))
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var env sign.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("intel: %s を解析できません: %w", currentFile, err)
	}
	if s.payload, s.current, err = s.verify(env); err != nil {
		return nil, fmt.Errorf("intel: 保存した脅威情報: %w", err)
	}
	return s, nil
}

func (s *Store) verify(env sign.Envelope) ([]byte, *Set, error) {
	payload, err := s.verifier.Verify(sign.PurposeIntel, env)
	if err != nil {
		return nil, nil, err
	}
	set, err := Parse(payload)
	if err != nil {
		return nil, nil, err
	}
	return payload, set, nil
}

// Current は今の版と、署名した中身（JSON）を返す（まだ配布していなければ nil）。
func (s *Store) Current() (*Set, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current, s.payload
}

// Check は署名付きの版を確かめる（保存はしない）。nftables への反映が通ってから Apply で保存するために使う。
func (s *Store) Check(env sign.Envelope) (*Set, error) {
	_, set, err := s.verify(env)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil && set.Version <= s.current.Version {
		return nil, fmt.Errorf("intel: 版数 %d は受け付けた版数 %d より新しくありません", set.Version, s.current.Version)
	}
	return set, nil
}

// Apply は署名付きの版を確かめて保存し、今の版にする。
func (s *Store) Apply(env sign.Envelope) (*Set, error) {
	payload, set, err := s.verify(env)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil && set.Version <= s.current.Version {
		return nil, fmt.Errorf("intel: 版数 %d は受け付けた版数 %d より新しくありません", set.Version, s.current.Version)
	}
	data, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(s.dir, currentFile), data, 0o600); err != nil {
		return nil, err
	}
	s.current, s.payload = set, payload
	return set, nil
}
