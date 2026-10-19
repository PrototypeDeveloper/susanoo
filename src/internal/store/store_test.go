package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func open(t *testing.T, maxTotal int64) (*JSONL, *clock) {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "events"), "events", maxTotal)
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{time.Date(2026, 10, 18, 23, 59, 0, 0, time.Local)}
	s.now = c.now
	t.Cleanup(func() { s.Close() })
	return s, c
}

func readAll(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func TestAppendAndRotate(t *testing.T) {
	s, c := open(t, 1<<20)
	if err := s.Append(map[string]int{"n": 1}); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(2 * time.Minute) // 日付が変わる
	if err := s.Append(map[string]int{"n": 2}); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(map[string]int{"n": 3}); err != nil {
		t.Fatal(err)
	}

	files, err := s.Files()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || filepath.Base(files[0]) != "events-20261018.jsonl" || filepath.Base(files[1]) != "events-20261019.jsonl" {
		t.Fatalf("ファイル = %v", files)
	}
	if got := readAll(t, files[0]); len(got) != 1 || got[0]["n"] != 1.0 {
		t.Errorf("1 日目 = %v", got)
	}
	if got := readAll(t, files[1]); len(got) != 2 {
		t.Errorf("2 日目 = %v", got)
	}
	fi, err := os.Stat(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("権限 = %v", fi.Mode().Perm())
	}
}

func TestPruneOldFiles(t *testing.T) {
	s, c := open(t, 400)
	// 1 行は 91 バイトで、1 日に 2 行（182 バイト）書く。上限に収まるのは今日と前日の分まで。
	big := map[string]string{"pad": strings.Repeat("x", 80)}
	for range 5 {
		for range 2 {
			if err := s.Append(big); err != nil {
				t.Fatal(err)
			}
		}
		c.t = c.t.Add(24 * time.Hour)
	}
	files, err := s.Files()
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		total += fi.Size()
	}
	if total > 400 {
		t.Errorf("合計 %d バイトが上限を超えている: %v", total, files)
	}
	if len(files) != 2 || filepath.Base(files[1]) != "events-20261022.jsonl" {
		t.Errorf("最新のファイルが残っていない: %v", files)
	}
}

func TestReopenAppends(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "events")
	for i := range 2 {
		s, err := Open(dir, "events", 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Append(map[string]int{"n": i}); err != nil {
			t.Fatal(err)
		}
		s.Close()
	}
	s, _ := Open(dir, "events", 1<<20)
	files, _ := s.Files()
	if len(files) != 1 || len(readAll(t, files[0])) != 2 {
		t.Errorf("開き直すと追記されない: %v", files)
	}
}

func TestClosed(t *testing.T) {
	s, _ := open(t, 1<<20)
	s.Close()
	if err := s.Append(1); err == nil {
		t.Error("閉じた後に追記できた")
	}
	if _, err := Open(t.TempDir(), "x", 0); err == nil {
		t.Error("上限 0 を受け付けた")
	}
}

// Query は条件に合う行を、新しいものから指定の件数まで、古い順に返す。since の前日までのファイルは読まない。
func TestQuery(t *testing.T) {
	s, c := open(t, 1<<20)
	for day := range 3 {
		c.t = time.Date(2026, 10, 16+day, 12, 0, 0, 0, time.Local)
		for i := range 4 {
			s.Append(map[string]any{"day": 16 + day, "i": i, "kind": []string{"a", "b"}[i%2]})
		}
	}
	match := func(kind string) func([]byte) bool {
		return func(line []byte) bool { return strings.Contains(string(line), `"kind":"`+kind+`"`) }
	}
	got := func(lines [][]byte) []string {
		var out []string
		for _, l := range lines {
			var m struct{ Day, I int }
			json.Unmarshal(l, &m)
			out = append(out, fmt.Sprintf("%d/%d", m.Day, m.I))
		}
		return out
	}
	lines, err := s.Query(Filter{}, 3, match("a"))
	if err != nil {
		t.Fatal(err)
	}
	// a は各日の 0 番目と 2 番目。新しいものから 3 件を古い順に。
	if g := got(lines); !slices.Equal(g, []string{"17/2", "18/0", "18/2"}) {
		t.Errorf("新しいものから 3 件 = %v", g)
	}
	lines, _ = s.Query(Filter{Since: time.Date(2026, 10, 17, 18, 0, 0, 0, time.Local)}, 100, match("b"))
	if g := got(lines); !slices.Equal(g, []string{"17/1", "17/3", "18/1", "18/3"}) {
		t.Errorf("17 日以降の b = %v（16 日のファイルは読まない）", g)
	}
	// 追記の途中の行（改行で終わらないもの）は読まない。
	files, _ := s.Files()
	f, _ := os.OpenFile(files[len(files)-1], os.O_WRONLY|os.O_APPEND, 0o600)
	f.WriteString(`{"day":18,"i":9,"kind":"a"`)
	f.Close()
	lines, _ = s.Query(Filter{}, 1, match("a"))
	if g := got(lines); !slices.Equal(g, []string{"18/2"}) {
		t.Errorf("途中の行を読んだ: %v", g)
	}
}
