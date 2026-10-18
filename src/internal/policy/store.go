package policy

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

// Store は GW の執行部が持つ、ポリシーの版の保存先（M2）。
//
// 署名付きの版は、ポリシー専用の鍵（CONTROLLER のプロセスには渡さない）の署名と版数を確かめてから保存する。
// 受け付けた最大の版数を記録し、それ以下の版は受け付けない（古い版を送り直す巻き戻しを防ぐ。再起動しても続く）。
// 保存先は root だけが読み書きできるディレクトリに置く。最初は、設定のポリシーのファイル（署名なし。root だけが
// 書ける）を今の版とする。
type Store struct {
	dir      string
	verifier *sign.Verifier

	mu      sync.Mutex
	state   storeState
	current *Policy
	canary  *Policy
}

type storeState struct {
	Current   int `json:"current"`
	Canary    int `json:"canary,omitempty"` // 先行適用の版。0 ならない
	Max       int `json:"max"`              // 受け付けた最大の版数
	Bootstrap int `json:"bootstrap"`        // 設定のファイルから読んだ版
}

const (
	stateFile     = "state.json"
	bootstrapFile = "bootstrap.json"
)

func versionFile(v int) string { return fmt.Sprintf("v%d.json", v) }

// OpenStore は dir の保存先を開く。初めて開くときは bootstrap を今の版にする。
// pub はポリシー専用の署名の公開鍵。
func OpenStore(dir string, pub ed25519.PublicKey, bootstrap *Policy) (*Store, error) {
	verifier, err := sign.NewVerifier(pub)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, verifier: verifier}
	data, err := os.ReadFile(filepath.Join(dir, stateFile))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		raw, err := json.MarshalIndent(bootstrap, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := fsutil.WriteFileAtomic(filepath.Join(dir, bootstrapFile), append(raw, '\n'), 0o600); err != nil {
			return nil, err
		}
		s.state = storeState{Current: bootstrap.Version, Max: bootstrap.Version, Bootstrap: bootstrap.Version}
		s.current = bootstrap
		return s, s.saveState()
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(data, &s.state); err != nil {
		return nil, fmt.Errorf("policy: %s を解析できません: %w", stateFile, err)
	}
	if s.current, err = s.load(s.state.Current); err != nil {
		return nil, err
	}
	if s.state.Canary != 0 {
		if s.canary, err = s.load(s.state.Canary); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// load は保存した版を読む。署名付きの版は署名を確かめ直す。
func (s *Store) load(v int) (*Policy, error) {
	if v == s.state.Bootstrap {
		data, err := os.ReadFile(filepath.Join(s.dir, bootstrapFile))
		if err != nil {
			return nil, err
		}
		return Parse(data)
	}
	data, err := os.ReadFile(filepath.Join(s.dir, versionFile(v)))
	if err != nil {
		return nil, err
	}
	var env sign.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("policy: 版 %d を解析できません: %w", v, err)
	}
	p, err := ParseSigned(s.verifier, env)
	if err != nil {
		return nil, fmt.Errorf("policy: 版 %d: %w", v, err)
	}
	if p.Version != v {
		return nil, fmt.Errorf("policy: %s の版数が %d です", versionFile(v), p.Version)
	}
	return p, nil
}

func (s *Store) saveState() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(s.dir, stateFile), append(data, '\n'), 0o600)
}

// Apply は署名付きの版を確かめて保存する。canary なら先行適用の版にし（前の先行適用は置き換える）、
// そうでなければ今の版にする（先行適用は取り消す）。
func (s *Store) Apply(env sign.Envelope, canary bool) (*Policy, error) {
	p, err := ParseSigned(s.verifier, env)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.Version <= s.state.Max {
		return nil, fmt.Errorf("policy: 版数 %d は受け付けた版数 %d より新しくありません", p.Version, s.state.Max)
	}
	data, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(s.dir, versionFile(p.Version)), data, 0o600); err != nil {
		return nil, err
	}
	next := s.state
	next.Max = p.Version
	if canary {
		next.Canary = p.Version
	} else {
		next.Current, next.Canary = p.Version, 0
	}
	if err := s.commit(next); err != nil {
		return nil, err
	}
	if canary {
		s.canary = p
	} else {
		s.current, s.canary = p, nil
	}
	return p, nil
}

// Promote は先行適用の版を今の版にする。
func (s *Store) Promote() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.canary == nil {
		return errors.New("policy: 先行適用している版がありません")
	}
	next := s.state
	next.Current, next.Canary = next.Canary, 0
	if err := s.commit(next); err != nil {
		return err
	}
	s.current, s.canary = s.canary, nil
	return nil
}

// Abort は先行適用の版を取り消す。取り消した版の版数は使えない。
func (s *Store) Abort() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.canary == nil {
		return errors.New("policy: 先行適用している版がありません")
	}
	next := s.state
	next.Canary = 0
	if err := s.commit(next); err != nil {
		return err
	}
	s.canary = nil
	return nil
}

func (s *Store) commit(next storeState) error {
	prev := s.state
	s.state = next
	if err := s.saveState(); err != nil {
		s.state = prev
		return err
	}
	return nil
}

// Policies は今の版と、先行適用の版（なければ nil）を返す。
func (s *Store) Policies() (current, canary *Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current, s.canary
}

// Effective は GW で使うポリシー（先行適用のグループを並べたもの）を返す。
func (s *Store) Effective() *Policy {
	current, canary := s.Policies()
	return WithCanary(current, canary)
}

// Max は受け付けた最大の版数を返す。
func (s *Store) Max() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Max
}
