package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.txt")

	if err := WriteFileAtomic(path, []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("2"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "2" {
		t.Errorf("中身 = %q, 期待値 %q", got, "2")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("権限 = %v, 期待値 %v", fi.Mode().Perm(), os.FileMode(0o644))
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("一時ファイルが残っている: %v", entries)
	}
}

func TestWriteFileAtomicMissingDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no", "such", "a.txt")
	if err := WriteFileAtomic(path, []byte("x"), 0o600); err == nil {
		t.Error("存在しないディレクトリへの書き込みが成功した")
	}
}
