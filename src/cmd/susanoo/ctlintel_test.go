package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"susanoo/internal/api"
)

// 脅威情報の一覧の取り込み、置き換え、照合、削除。
func TestIntelCommands(t *testing.T) {
	dir := t.TempDir()
	ctrlDir, addr := startTestGW(t, dir)
	ctl := func(args ...string) (int, string, string) {
		t.Helper()
		return runCmd(t, append(append([]string{"ctl", "intel"}, args...), "-dir", ctrlDir, "-server", addr)...)
	}
	info := func() api.IntelInfo {
		t.Helper()
		code, out, errOut := ctl("list", "-json")
		var info api.IntelInfo
		if code != exitOK || json.Unmarshal([]byte(out), &info) != nil {
			t.Fatalf("ctl intel list: %s %s", out, errOut)
		}
		return info
	}
	if code, out, _ := ctl("list"); code != exitOK || !strings.Contains(out, "まだ配布していません") {
		t.Errorf("配布前の一覧 = %s", out)
	}
	phish := filepath.Join(dir, "phish.txt")
	os.WriteFile(phish, []byte("# 例\n0.0.0.0 login.phish.test\nhttp://evil.test/x\n203.0.113.66\nnot valid line\n"), 0o600)
	watch := filepath.Join(dir, "watch.txt")
	os.WriteFile(watch, []byte("watch.test\n198.51.100.0/24\n"), 0o600)

	if code, out, errOut := ctl("push", "-name", "phishing", "-action", "block", "-source", "https://feeds.example/phish", phish); code != exitOK || !strings.Contains(out, "読み飛ばした行 1") {
		t.Fatalf("取り込み: %s %s", out, errOut)
	}
	if code, out, errOut := ctl("push", watch, "-name", "watch"); code != exitOK || !strings.Contains(out, "版 2") {
		t.Fatalf("2 つ目の取り込み: %s %s", out, errOut)
	}
	i := info()
	if i.Version != 2 || len(i.Lists) != 2 || i.Lists[0].Name != "phishing" || i.Lists[0].Action != "block" || i.Lists[0].Domains != 2 || i.Lists[0].CIDRs != 1 ||
		i.Lists[1].Action != "alert" || i.Lists[0].Source != "https://feeds.example/phish" {
		t.Errorf("取り込んだ後 = %+v", i)
	}
	if code, out, _ := ctl("check", "a.login.phish.test"); code != exitOK || !strings.Contains(out, "phishing") || !strings.Contains(out, "login.phish.test") {
		t.Errorf("照合 = %s", out)
	}
	if code, out, _ := ctl("check", "198.51.100.20"); code != exitOK || !strings.Contains(out, "watch") {
		t.Errorf("アドレスの照合 = %s", out)
	}
	if code, out, _ := ctl("check", "clean.test"); code == exitOK || !strings.Contains(out, "どの一覧にもありません") {
		t.Errorf("当てはまらない照合 = %d %s", code, out)
	}
	// 同じ名前の一覧は置き換える。
	os.WriteFile(phish, []byte("other.test\n"), 0o600)
	if code, _, errOut := ctl("push", "-name", "phishing", "-action", "block", phish); code != exitOK {
		t.Fatalf("置き換え: %s", errOut)
	}
	if i := info(); i.Version != 3 || len(i.Lists) != 2 || i.Lists[0].Domains != 1 || i.Lists[0].CIDRs != 0 {
		t.Errorf("置き換えた後 = %+v", i)
	}
	if code, out, errOut := ctl("remove", "-name", "watch"); code != exitOK || !strings.Contains(out, "版 4") {
		t.Fatalf("削除: %s %s", out, errOut)
	}
	if i := info(); len(i.Lists) != 1 || i.Lists[0].Name != "phishing" {
		t.Errorf("削除した後 = %+v", i)
	}
	if code, out, _ := runCmd(t, "ctl", "status", "-dir", ctrlDir, "-server", addr); code != exitOK || !strings.Contains(out, "脅威情報") {
		t.Errorf("全体の状態 = %s", out)
	}
	// 不正な指定。
	for name, args := range map[string][]string{
		"名前がない":   {"push", phish},
		"不正な扱い":   {"push", "-name", "x", "-action", "drop", phish},
		"ファイルがない": {"push", "-name", "x"},
		"空のファイル":  {"push", "-name", "x", watch + ".none"},
		"ない一覧の削除": {"remove", "-name", "none"},
	} {
		if code, _, _ := ctl(args...); code == exitOK {
			t.Errorf("%s が通った", name)
		}
	}
}
