package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type rec struct {
	N      int    `json:"n"`
	Time   int64  `json:"time"`
	Device string `json:"device"`
}

func recIndex(v any) (int64, []string) {
	r := v.(rec)
	return r.Time, []string{"d:" + r.Device}
}

func openIndexed(t *testing.T, dir string) (*JSONL, *clock) {
	t.Helper()
	s, err := OpenIndexed(dir, "events", 1<<30, recIndex)
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{time.Date(2026, 10, 18, 12, 0, 0, 0, time.Local)}
	s.now = c.now
	return s, c
}

func deviceOf(n int) string {
	if n >= 1500 && n < 1510 {
		return "rare" // 2 つ目のブロックにだけ現れる
	}
	return fmt.Sprintf("pc-%d", n%20)
}

func numbers(lines [][]byte) []int {
	var out []int
	for _, l := range lines {
		var r rec
		json.Unmarshal(l, &r)
		out = append(out, r.N)
	}
	return out
}

func matchDevice(d string) func([]byte) bool {
	return func(line []byte) bool { return strings.Contains(string(line), `"device":"`+d+`"`) }
}

// 索引で、条件に合い得ないブロックを読まずに、索引なしで読んだときと同じ結果を返す。
func TestIndexedQuery(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "events")
	s, _ := openIndexed(t, dir)
	base := time.Date(2026, 10, 18, 0, 0, 0, 0, time.Local).UnixMilli()
	for n := range 3500 {
		if err := s.Append(rec{N: n, Time: base + int64(n)*1000, Device: deviceOf(n)}); err != nil {
			t.Fatal(err)
		}
	}
	total := s.size
	s.scanned.Store(0)
	lines, err := s.Query(Filter{Tags: [][]string{{"d:rare"}}}, 100, matchDevice("rare"))
	if err != nil {
		t.Fatal(err)
	}
	if got := numbers(lines); !slices.Equal(got, []int{1500, 1501, 1502, 1503, 1504, 1505, 1506, 1507, 1508, 1509}) {
		t.Errorf("結果 = %v", got)
	}
	// 2 つ目のブロックと、索引に書いていない最後のブロックだけを読む。
	if scanned := s.scanned.Load(); scanned > total/2 {
		t.Errorf("読んだ量 = %d バイト（全体 %d バイト）", scanned, total)
	}
	// 時刻の範囲で絞り込む。
	s.scanned.Store(0)
	since := time.UnixMilli(base + 3200*1000)
	lines, _ = s.Query(Filter{Since: since, Tags: [][]string{{"d:pc-3"}}}, 100, func(l []byte) bool {
		var r rec
		json.Unmarshal(l, &r)
		return r.Device == "pc-3" && r.Time >= since.UnixMilli()
	})
	if got := numbers(lines); len(got) != 15 || got[0] != 3203 {
		t.Errorf("時刻で絞った結果 = %v", got)
	}
	if scanned := s.scanned.Load(); scanned > total/2 {
		t.Errorf("時刻で絞ったときに読んだ量 = %d バイト（全体 %d バイト）", scanned, total)
	}
	// 新しいものから件数まで。組の中のどれかの印を持てばよい。索引なしで読んだときと同じ結果になる。
	either := func(l []byte) bool { return matchDevice("pc-1")(l) || matchDevice("pc-2")(l) }
	indexed, _ := s.Query(Filter{Tags: [][]string{{"d:pc-1", "d:pc-2"}}}, 3, either)
	full, _ := s.Query(Filter{}, 3, either)
	if got, want := numbers(indexed), numbers(full); !slices.Equal(got, want) || len(got) != 3 {
		t.Errorf("新しいものから 3 件 = %v（%v のはず）", got, want)
	}
	if _, err := s.Query(Filter{Tags: [][]string{{"d:nobody"}}}, 10, matchDevice("nobody")); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := os.Stat(filepath.Join(dir, "events-20261018.idx")); err != nil {
		t.Errorf("索引のファイルがありません: %v", err)
	}
}

// 異常終了で索引を書けなかった部分（索引のない部分）と、壊れた索引の行があっても、すべての行を見つける。
func TestIndexGaps(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "events")
	s, _ := openIndexed(t, dir)
	for n := range 1200 {
		s.Append(rec{N: n, Time: int64(n), Device: deviceOf(n)})
	}
	s.Close() // 200 行の途中のブロックも索引に書く
	path := filepath.Join(dir, "events-20261018.jsonl")
	// 異常終了：索引を書かずに追記した行。
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	fmt.Fprintln(f, `{"n":5000,"time":5000,"device":"rare"}`)
	f.Close()
	idx, _ := os.OpenFile(indexName(path), os.O_WRONLY|os.O_APPEND, 0o600)
	fmt.Fprintln(idx, `{"off":-1}`)
	fmt.Fprintln(idx, `壊れた行`)
	idx.Close()
	s, _ = openIndexed(t, dir)
	defer s.Close()
	for n := 6000; n < 7100; n++ {
		s.Append(rec{N: n, Time: int64(n), Device: deviceOf(n % 1000)})
	}
	s.Append(rec{N: 7100, Time: 7100, Device: "rare"})
	lines, err := s.Query(Filter{Tags: [][]string{{"d:rare"}}}, 100, matchDevice("rare"))
	if err != nil {
		t.Fatal(err)
	}
	var want []int
	for n := range 1200 {
		if deviceOf(n) == "rare" {
			want = append(want, n)
		}
	}
	want = append(want, 5000, 7100)
	if got := numbers(lines); !slices.Equal(got, want) {
		t.Errorf("結果 = %v（%v のはず）", got, want)
	}
	// 重なる索引は信用せず、ファイルをすべて読む。
	idx, _ = os.OpenFile(indexName(path), os.O_WRONLY|os.O_APPEND, 0o600)
	fmt.Fprintln(idx, `{"off":0,"len":10,"min":0,"max":0,"bloom":""}`)
	idx.Close()
	if lines, _ := s.Query(Filter{Tags: [][]string{{"d:rare"}}}, 100, matchDevice("rare")); !slices.Equal(numbers(lines), want) {
		t.Errorf("重なる索引のときの結果 = %v", numbers(lines))
	}
}

// 古いファイルを消すときは、索引も消す。
func TestIndexPruned(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "events")
	s, err := OpenIndexed(dir, "events", 20000, recIndex)
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{time.Date(2026, 10, 17, 12, 0, 0, 0, time.Local)}
	s.now = c.now
	defer s.Close()
	for n := range 300 {
		s.Append(rec{N: n, Device: "pc-1"})
	}
	c.t = c.t.AddDate(0, 0, 1)
	for n := range 300 {
		s.Append(rec{N: n, Device: "pc-1"})
	}
	if _, err := os.Stat(filepath.Join(dir, "events-20261017.jsonl")); err == nil {
		t.Fatal("古いファイルが消えていません")
	}
	if _, err := os.Stat(filepath.Join(dir, "events-20261017.idx")); err == nil {
		t.Error("古いファイルの索引が消えていません")
	}
}
