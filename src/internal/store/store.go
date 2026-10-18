// Package store はイベントなどを JSON Lines のファイルに保存する（M4）。
//
// ファイルは日付ごとに分け（<prefix>-YYYYMMDD.jsonl）、合計の大きさが上限を超えたら古いファイルから消す。
package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// JSONL は日付ごとのファイルに追記する。複数のゴルーチンから同時に使える。
type JSONL struct {
	mu       sync.Mutex
	dir      string
	prefix   string
	maxTotal int64
	now      func() time.Time

	f    *os.File
	day  string
	size int64 // 今のファイルの大きさ
	rest int64 // 今のファイル以外の合計
}

// Open は dir に prefix で始まるファイルを作って追記する。maxTotal は全ファイルの合計の上限（バイト）。
func Open(dir, prefix string, maxTotal int64) (*JSONL, error) {
	if maxTotal <= 0 {
		return nil, errors.New("store: 容量の上限は正の値にしてください")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &JSONL{dir: dir, prefix: prefix, maxTotal: maxTotal, now: time.Now}, nil
}

// Append は v を JSON にして 1 行追記する。
func (s *JSONL) Append(v any) error {
	line, err := json.Marshal(v)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == "" {
		return errors.New("store: 閉じられています")
	}
	if err := s.rotate(); err != nil {
		return err
	}
	n, err := s.f.Write(line)
	s.size += int64(n)
	if err != nil {
		return err
	}
	if s.size+s.rest > s.maxTotal {
		return s.prune()
	}
	return nil
}

// rotate は日付が変わっていたら新しいファイルに切り替える。
func (s *JSONL) rotate() error {
	day := s.now().Format("20060102")
	if s.f != nil && day == s.day {
		return nil
	}
	if s.f != nil {
		if err := s.f.Close(); err != nil {
			return err
		}
		s.f = nil
	}
	f, err := os.OpenFile(filepath.Join(s.dir, s.fileName(day)), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	s.f, s.day, s.size = f, day, fi.Size()
	return s.prune()
}

// prune は合計が上限を超えている間、今のファイル以外の古いファイルを消す。
func (s *JSONL) prune() error {
	files, err := s.Files()
	if err != nil {
		return err
	}
	current := s.fileName(s.day)
	var others []string
	var sizes []int64
	s.rest = 0
	for _, name := range files {
		if filepath.Base(name) == current {
			continue
		}
		fi, err := os.Stat(name)
		if err != nil {
			continue
		}
		others = append(others, name)
		sizes = append(sizes, fi.Size())
		s.rest += fi.Size()
	}
	for i := 0; i < len(others) && s.size+s.rest > s.maxTotal; i++ {
		if err := os.Remove(others[i]); err != nil {
			return err
		}
		s.rest -= sizes[i]
	}
	return nil
}

func (s *JSONL) fileName(day string) string { return fmt.Sprintf("%s-%s.jsonl", s.prefix, day) }

// Files は保存しているファイルの一覧を古い順に返す。
func (s *JSONL) Files() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.Type().IsRegular() && strings.HasPrefix(name, s.prefix+"-") && strings.HasSuffix(name, ".jsonl") {
			files = append(files, filepath.Join(s.dir, name))
		}
	}
	slices.Sort(files)
	return files, nil
}

// Query は、match が真を返す行を、新しいものから limit 件まで集めて、古い順に返す。
// 行を記録した日はイベントの発生した日より前にならないので、since の前日までのファイルは読まない。
// 索引は持たず、ファイルを読んで探す。追記の途中の行（改行で終わらないもの）は読まない。
func (s *JSONL) Query(since time.Time, limit int, match func(line []byte) bool) ([][]byte, error) {
	files, err := s.Files()
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for i := len(files) - 1; i >= 0 && len(out) < limit; i-- {
		if !since.IsZero() {
			day := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(files[i]), s.prefix+"-"), ".jsonl")
			if t, err := time.ParseInLocation("20060102", day, time.Local); err == nil && !t.AddDate(0, 0, 1).After(since) {
				break
			}
		}
		lines, err := matchFile(files[i], match, limit-len(out))
		if err != nil {
			return nil, err
		}
		out = append(lines, out...)
	}
	return out, nil
}

// matchFile はファイルのうち match が真を返す行を、新しいものから n 件まで、古い順に返す。
func matchFile(path string, match func([]byte) bool, n int) ([][]byte, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil // 古いファイルを消した後
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64<<10)
	var found [][]byte
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return found, nil // 終わり、または追記の途中の行
		}
		line = line[:len(line)-1]
		if match(line) {
			found = append(found, line)
			if len(found) > n {
				found = found[1:]
			}
		}
	}
}

// Close はファイルを閉じる。
func (s *JSONL) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dir = ""
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}
