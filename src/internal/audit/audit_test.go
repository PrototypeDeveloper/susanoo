package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func openLog(t *testing.T, path string) *Log {
	t.Helper()
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	n := 0
	l.now = func() time.Time { n++; return base.Add(time.Duration(n) * time.Second) }
	return l
}

func writeLog(t *testing.T, n int) (path string, head Head) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "audit.log")
	l := openLog(t, path)
	for i := range n {
		if _, err := l.Append(Entry{
			Actor:  "admin/admin",
			Action: "device.isolate",
			Target: fmt.Sprintf("pc-%03d", i),
			Detail: map[string]any{"level": "full", "理由": "おとりへの接触"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	head = l.Head()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return path, head
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// 各行は改行で終わる。末尾の改行の後にできる空の要素は除く。
	lines := strings.SplitAfter(string(data), "\n")
	return lines[:len(lines)-1]
}

func TestAppendAndVerify(t *testing.T) {
	path, head := writeLog(t, 3)
	if head.Seq != 3 || head.Hash == genesis {
		t.Errorf("末尾 = %+v", head)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := Verify(f)
	if err != nil {
		t.Fatal(err)
	}
	if got != head {
		t.Errorf("検証した末尾 = %+v, 期待値 %+v", got, head)
	}
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("権限 = %v, 期待値 0600", fi.Mode().Perm())
	}
}

func TestReopenContinuesChain(t *testing.T) {
	path, head := writeLog(t, 2)
	l := openLog(t, path)
	if l.Head() != head {
		t.Errorf("開き直した末尾 = %+v, 期待値 %+v", l.Head(), head)
	}
	rec, err := l.Append(Entry{Actor: "admin/admin", Action: "device.release", Target: "pc-000"})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Seq != 3 || rec.PrevHash != head.Hash {
		t.Errorf("追記した記録 = %+v", rec)
	}
	l.Close()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := Verify(f); err != nil {
		t.Error(err)
	}
}

func TestTamperDetection(t *testing.T) {
	tests := []struct {
		name     string
		edit     func([]string) []string
		wantLine int
	}{
		{"内容の書き換え", func(l []string) []string {
			l[1] = strings.Replace(l[1], "pc-001", "pc-999", 1)
			return l
		}, 2},
		{"途中の削除", func(l []string) []string { return append(l[:1], l[2:]...) }, 2},
		{"順序の入れ替え", func(l []string) []string {
			l[1], l[2] = l[2], l[1]
			return l
		}, 2},
		{"記録の複製", func(l []string) []string { return append(l[:2], l[1:]...) }, 3},
		{"知らない項目の追加", func(l []string) []string {
			l[0] = strings.Replace(l[0], `{"seq"`, `{"x":1,"seq"`, 1)
			return l
		}, 1},
		{"壊れた行", func(l []string) []string {
			l[2] = "{\n"
			return l
		}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, _ := writeLog(t, 4)
			lines := tt.edit(readLines(t, path))
			_, err := Verify(strings.NewReader(strings.Join(lines, "")))
			var ce *ChainError
			if !errors.As(err, &ce) {
				t.Fatalf("改ざんを検知できない: %v", err)
			}
			if ce.Line != tt.wantLine {
				t.Errorf("検知した行 = %d, 期待値 %d（%v）", ce.Line, tt.wantLine, err)
			}
		})
	}
}

func TestRehashedTamperBreaksNextRecord(t *testing.T) {
	path, _ := writeLog(t, 3)
	lines := readLines(t, path)

	// 2 件目を書き換え、その記録のハッシュは正しく計算し直す。
	var r Record
	if err := json.Unmarshal([]byte(strings.Replace(lines[1], "pc-001", "pc-999", 1)), &r); err != nil {
		t.Fatal(err)
	}
	hash, err := computeHash(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Hash = hash
	fixed, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	lines[1] = string(fixed) + "\n"

	// 3 件目の prev_hash と合わなくなるので、3 行目で検知できる。
	_, err = Verify(strings.NewReader(strings.Join(lines, "")))
	var ce *ChainError
	if !errors.As(err, &ce) || ce.Line != 3 {
		t.Errorf("ハッシュを計算し直した改ざんを、次の記録で検知できない: %v", err)
	}
}

func TestOpenRejectsTamperedLog(t *testing.T) {
	path, _ := writeLog(t, 2)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.Replace(data, []byte("pc-000"), []byte("pc-999"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Error("改ざんされたログを開けた")
	}
}

func TestAppendValidation(t *testing.T) {
	l := openLog(t, filepath.Join(t.TempDir(), "audit.log"))
	defer l.Close()
	if _, err := l.Append(Entry{Action: "x"}); err == nil {
		t.Error("actor なしで記録できた")
	}
	if _, err := l.Append(Entry{Actor: "x"}); err == nil {
		t.Error("action なしで記録できた")
	}
	if _, err := l.Append(Entry{Actor: "x", Action: "y", Detail: func() {}}); err == nil {
		t.Error("JSON にできない detail を記録できた")
	}
	l.Close()
	if _, err := l.Append(Entry{Actor: "x", Action: "y"}); err == nil {
		t.Error("閉じたログに記録できた")
	}
}

func TestConcurrentAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l := openLog(t, path)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 10 {
				if _, err := l.Append(Entry{Actor: "x", Action: "y", Target: fmt.Sprint(i, j)}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	l.Close()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	head, err := Verify(f)
	if err != nil {
		t.Fatal(err)
	}
	if head.Seq != 80 {
		t.Errorf("件数 = %d, 期待値 80", head.Seq)
	}
}

func FuzzVerify(f *testing.F) {
	dir := f.TempDir()
	path := filepath.Join(dir, "audit.log")
	l, err := Open(path)
	if err != nil {
		f.Fatal(err)
	}
	for i := range 3 {
		if _, err := l.Append(Entry{Actor: "a", Action: "b", Target: fmt.Sprint(i), Detail: []int{i}}); err != nil {
			f.Fatal(err)
		}
	}
	l.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte("{}\n"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		head, err := Verify(bytes.NewReader(data))
		if err != nil {
			return
		}
		// 検証に通ったログの件数は、行数を超えない。
		if lines := uint64(bytes.Count(data, []byte("\n")) + 1); head.Seq > lines {
			t.Fatalf("件数 %d が行数 %d を超えている", head.Seq, lines)
		}
	})
}
