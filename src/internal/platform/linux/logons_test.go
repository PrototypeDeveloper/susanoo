//go:build linux

package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"susanoo/internal/event"
)

func TestParseAuthMessage(t *testing.T) {
	tests := []struct {
		msg  string
		want *authRecord // nil ならログオンに関係しない行
	}{
		{"Failed password for alice from 192.0.2.10 port 52314 ssh2", &authRecord{user: "alice", host: "192.0.2.10", port: 52314, method: "password", service: "sshd"}},
		{"Failed publickey for root from 2001:db8::1 port 22 ssh2: ED25519 SHA256:abc", &authRecord{user: "root", host: "2001:db8::1", port: 22, method: "publickey", service: "sshd"}},
		{"Failed password for invalid user admin from 192.0.2.11 port 1 ssh2", nil},
		{"Invalid user admin from 192.0.2.11 port 50000", &authRecord{user: "admin", invalid: true, host: "192.0.2.11", port: 50000, service: "sshd"}},
		{"Invalid user oracle from 192.0.2.14", &authRecord{user: "oracle", invalid: true, host: "192.0.2.14", service: "sshd"}},
		// 利用者の名前に「from」を入れても、本当の接続元（行の最後）を取る。
		{"Invalid user x from 9.9.9.9 port 1 from 192.0.2.12 port 22", &authRecord{user: "x from 9.9.9.9 port 1", invalid: true, host: "192.0.2.12", port: 22, service: "sshd"}},
		{"Invalid user  from 192.0.2.13 port 22", &authRecord{user: emptyUser, invalid: true, host: "192.0.2.13", port: 22, service: "sshd"}},
		{"Accepted publickey for bob from 192.0.2.20 port 4444 ssh2: ED25519 SHA256:xyz", &authRecord{success: true, user: "bob", host: "192.0.2.20", port: 4444, method: "publickey", service: "sshd"}},
		{"pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=alice", &authRecord{user: "alice", method: "password", service: "sudo"}},
		{"pam_unix(login:auth): authentication failure; logname=LOGIN uid=0 euid=0 tty=/dev/tty1 ruser= rhost= user=root", &authRecord{user: "root", method: "password", service: "login"}},
		{"pam_unix(su:auth): authentication failure; logname=alice uid=1000 euid=0 tty=pts/0 ruser=alice rhost=", &authRecord{user: "alice", method: "password", service: "su"}},
		{"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.10  user=alice", nil},
		{"Connection closed by 192.0.2.1 port 22 [preauth]", nil},
		{"pam_unix(sshd:session): session opened for user alice(uid=1000) by alice(uid=0)", nil},
	}
	for _, tc := range tests {
		got := parseAuthMessage("sshd", 100, tc.msg)
		if tc.want == nil {
			if got != nil {
				t.Errorf("%q をログオンとして読んだ: %+v", tc.msg, got)
			}
			continue
		}
		tc.want.ident, tc.want.pid = "sshd", 100
		if got == nil || *got != *tc.want {
			t.Errorf("%q\n  = %+v\nwant %+v", tc.msg, got, tc.want)
		}
	}
	// イベントにすると、失敗は重大度が低、遠隔、接続元の端点が入る。
	e := parseAuthMessage("sshd", 7, "Invalid user admin from 192.0.2.11 port 50000").event(time.Now())
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	if e.ClassUID != event.ClassAuthentication || e.StatusID != event.StatusFailure || e.SeverityID != event.SeverityLow || !*e.IsRemote ||
		e.SrcEndpoint.IP != "192.0.2.11" || e.SrcEndpoint.Port != 50000 || e.StatusDetail != "存在しない利用者" || e.LogonProcess.PID != 7 {
		t.Errorf("イベント = %+v", e)
	}
	if e := parseAuthMessage("unix_chkpwd", 0, "pam_unix(sudo:auth): authentication failure; logname=a uid=1 euid=0 tty=x ruser=a rhost=  user=a").event(time.Now()); *e.IsRemote || e.LogonTypeID != event.LogonInteractive {
		t.Errorf("端末の前の失敗 = %+v", e)
	}
}

func TestParseSyslogLine(t *testing.T) {
	tests := []struct {
		line, ident, msg string
		pid              int
	}{
		{"Oct 19 10:00:00 pc-001 sshd[100]: Failed password for a from 192.0.2.1 port 1 ssh2", "sshd", "Failed password for a from 192.0.2.1 port 1 ssh2", 100},
		{"Oct  9 08:01:02 pc-001 sudo: pam_unix(sudo:auth): authentication failure; user=a", "sudo", "pam_unix(sudo:auth): authentication failure; user=a", 0},
		{"2026-10-19T10:00:00.123456+09:00 pc-001 sshd-session[2345]: Invalid user x from 192.0.2.2 port 3", "sshd-session", "Invalid user x from 192.0.2.2 port 3", 2345},
	}
	for _, tc := range tests {
		ident, pid, msg, ok := parseSyslogLine(tc.line)
		if !ok || ident != tc.ident || pid != tc.pid || msg != tc.msg {
			t.Errorf("%q = %q %d %q %v", tc.line, ident, pid, msg, ok)
		}
	}
	for _, bad := range []string{"", "garbage", "Oct 19 10:00:00 host"} {
		if _, _, _, ok := parseSyslogLine(bad); ok {
			t.Errorf("%q を読んだ", bad)
		}
	}
}

func TestParseJournalLine(t *testing.T) {
	ident, pid, msg, ok := parseJournalLine([]byte(`{"MESSAGE":"Invalid user a from 192.0.2.1 port 2","SYSLOG_IDENTIFIER":"sshd-session","_PID":"42","_COMM":"sshd-session"}`))
	if !ok || ident != "sshd-session" || pid != 42 || msg != "Invalid user a from 192.0.2.1 port 2" {
		t.Errorf("= %q %d %q %v", ident, pid, msg, ok)
	}
	// 文字として表せない本文は、バイトの配列になる。
	_, _, msg, ok = parseJournalLine([]byte(`{"MESSAGE":[73,110,118,97,108,105,100],"_COMM":"sshd"}`))
	if !ok || msg != "Invalid" {
		t.Errorf("バイトの配列の本文 = %q %v", msg, ok)
	}
	if _, _, _, ok := parseJournalLine([]byte(`{"_COMM":"sshd"}`)); ok {
		t.Error("本文のない行を読んだ")
	}
	if _, _, _, ok := parseJournalLine([]byte(`not json`)); ok {
		t.Error("JSON でない行を読んだ")
	}
}

func TestParseEnvFile(t *testing.T) {
	got := parseEnvFile([]byte("# コメント\nUSER=alice\nREMOTE_HOST=\"host with \\\"quote\\\"\"\nEMPTY=\nbroken\n=x\nUID=1000\n"))
	if got["USER"] != "alice" || got["REMOTE_HOST"] != `host with "quote"` || got["UID"] != "1000" || len(got) != 4 {
		t.Errorf("= %q", got)
	}
}

func writeSession(t *testing.T, dir, id string, kv ...string) {
	t.Helper()
	tmp := filepath.Join(dir, ".#"+id)
	if err := os.WriteFile(tmp, []byte(strings.Join(kv, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, id)); err != nil { // logind と同じく、書いてから名前を変える
		t.Fatal(err)
	}
}

// 起動した後の利用者のセッションだけをログオンとし、閉じ始めるかなくなったらログオフにする（一度だけ）。
func TestSessionWatcher(t *testing.T) {
	dir := t.TempDir()
	writeSession(t, dir, "1", "UID=1000", "USER=alice", "STATE=active", "CLASS=user", "SERVICE=gdm-password", "TYPE=wayland")
	w, err := newSessionWatcher(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if evs := w.poll(now); len(evs) != 0 {
		t.Fatalf("起動する前からのセッションを記録した: %v", evs)
	}
	writeSession(t, dir, "c2", "UID=0", "USER=root", "STATE=online", "CLASS=user", "REMOTE=1", "REMOTE_HOST=192.0.2.5", "SERVICE=sshd",
		"TTY=pts/1", "LEADER=1", "REALTIME=1760000000000000", "TYPE=tty")
	writeSession(t, dir, "c3", "UID=120", "USER=gdm", "STATE=online", "CLASS=greeter", "SERVICE=gdm-launch-environment")
	os.WriteFile(filepath.Join(dir, ".#c4"), []byte("USER=half\n"), 0o644)
	evs := w.poll(now)
	if len(evs) != 1 {
		t.Fatalf("イベント = %d 件 %v", len(evs), evs)
	}
	e := evs[0]
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	if e.ActivityID != event.AuthLogon || e.User.Name != "root" || e.User.UID != "0" || !*e.IsRemote || e.LogonTypeID != event.LogonRemoteInteractive ||
		e.Service.Name != "sshd" || e.Session.UID != "c2" || e.Session.Terminal != "pts/1" || e.Session.CreatedTime != 1760000000000 ||
		e.SrcEndpoint.IP != "192.0.2.5" || e.LogonProcess.PID != 1 || !strings.Contains(e.Message, "192.0.2.5 から") {
		t.Errorf("ログオン = %+v %+v", e, e.Session)
	}
	writeSession(t, dir, "c2", "UID=0", "USER=root", "STATE=closing", "CLASS=user", "REMOTE=1", "REMOTE_HOST=192.0.2.5", "SERVICE=sshd", "TTY=pts/1")
	if evs := w.poll(now); len(evs) != 1 || evs[0].ActivityID != event.AuthLogoff || evs[0].User.Name != "root" {
		t.Fatalf("閉じ始めたセッション = %v", evs)
	}
	os.Remove(filepath.Join(dir, "c2"))
	if evs := w.poll(now); len(evs) != 0 {
		t.Fatalf("ログオフを二度記録した: %v", evs)
	}
	// 端末を割り当てない遠隔のセッションが、閉じ始める前に消えても、ログオフにする。
	writeSession(t, dir, "c5", "UID=1000", "USER=alice", "STATE=online", "REMOTE=1", "REMOTE_HOST=host.example", "SERVICE=sshd")
	if evs := w.poll(now); len(evs) != 1 || evs[0].LogonTypeID != event.LogonNetwork || evs[0].SrcEndpoint.Hostname != "host.example" {
		t.Fatalf("命令だけの遠隔ログオン = %v", evs)
	}
	os.Remove(filepath.Join(dir, "c5"))
	if evs := w.poll(now); len(evs) != 1 || evs[0].ActivityID != event.AuthLogoff {
		t.Fatalf("消えたセッション = %v", evs)
	}
	// 起動する前からのセッションが消えても、ログオフは記録しない（ログオンを記録していない）。
	os.Remove(filepath.Join(dir, "1"))
	if evs := w.poll(now); len(evs) != 0 {
		t.Fatalf("記録していないセッションのログオフ = %v", evs)
	}
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

// 認証のログは起動した後の分だけを読み、書きかけの行は待つ。名前を変えて新しいファイルにする切り替えでは古いファイルの残りを
// 読んでから新しいファイルを先頭から読み、切り詰めでは先頭から読み直す。長すぎる行は捨てる。
func TestAuthTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	appendFile(t, path, "old\n")
	tail, err := openTail(path)
	if err != nil {
		t.Fatal(err)
	}
	defer tail.close()
	if got := tail.poll(); len(got) != 0 {
		t.Fatalf("起動する前の行を読んだ: %q", got)
	}
	appendFile(t, path, "a\nb-part")
	if got := tail.poll(); strings.Join(got, ",") != "a" {
		t.Fatalf("= %q", got)
	}
	appendFile(t, path, "ial\n")
	os.Rename(path, path+".1")
	appendFile(t, path+".1", "c\n")
	appendFile(t, path, "dddddddd\n")
	if got := tail.poll(); strings.Join(got, ",") != "b-partial,c,dddddddd" {
		t.Fatalf("切り替えの後 = %q", got)
	}
	os.Truncate(path, 0)
	appendFile(t, path, "e\n")
	if got := tail.poll(); strings.Join(got, ",") != "e" {
		t.Fatalf("切り詰めの後 = %q", got)
	}
	appendFile(t, path, strings.Repeat("x", maxAuthLine+10)+"\nf\n")
	if got := tail.poll(); strings.Join(got, ",") != "f" {
		t.Fatalf("長すぎる行の後 = %d 行", len(got))
	}
	appendFile(t, path, strings.Repeat("y", maxAuthLine+10))
	tail.poll()
	appendFile(t, path, "rest\ng\n")
	if got := tail.poll(); strings.Join(got, ",") != "g" {
		t.Fatalf("分かれて届いた長すぎる行の後 = %q", got)
	}
}

// collect は監視 m を動かし、届いたイベントを返す関数を返す。
func collect(t *testing.T, m *logonMonitor) func() []*event.Event {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var got []*event.Event
	done := make(chan struct{})
	go func() {
		m.run(ctx, func(e *event.Event) { mu.Lock(); got = append(got, e); mu.Unlock() })
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done; m.close() })
	return func() []*event.Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]*event.Event(nil), got...)
	}
}

func waitEvents(t *testing.T, get func() []*event.Event, n int) []*event.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if evs := get(); len(evs) >= n {
			return evs
		}
		if time.Now().After(deadline) {
			t.Fatalf("イベントが %d 件届かない（%d 件）", n, len(get()))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// セッションと認証のログを読むときは、認証のログの成功したログオンを記録しない（セッションと重ねない）。失敗したログオンの
// イベントは上限までにし、記録しなかった数を後のイベントに添える。
func TestLogonMonitor(t *testing.T) {
	dir := t.TempDir()
	sessions := filepath.Join(dir, "sessions")
	os.Mkdir(sessions, 0o755)
	authLog := filepath.Join(dir, "auth.log")
	appendFile(t, authLog, "")
	m, err := newLogonMonitor(LogonConfig{Enabled: true, SessionsDir: sessions, AuthLogs: []string{authLog, filepath.Join(dir, "none")}, Poll: 20 * time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	get := collect(t, m)
	writeSession(t, sessions, "7", "UID=1000", "USER=alice", "STATE=active", "REMOTE=0", "SERVICE=login", "TTY=tty1")
	appendFile(t, authLog, "Oct 19 10:00:00 pc sshd[1]: Accepted password for alice from 192.0.2.1 port 1 ssh2\n")
	var lines strings.Builder
	for i := range authFailureBurst + 30 {
		fmt.Fprintf(&lines, "Oct 19 10:00:00 pc sshd[2]: Invalid user u%d from 192.0.2.66 port %d\n", i, 1000+i)
	}
	appendFile(t, authLog, lines.String())
	evs := waitEvents(t, get, 1+authFailureBurst)
	time.Sleep(100 * time.Millisecond)
	evs = get()
	logons, failures := 0, 0
	for _, e := range evs {
		if err := e.Validate(); err != nil {
			t.Fatal(err)
		}
		switch e.StatusID {
		case event.StatusSuccess:
			logons++
			if e.Service.Name != "login" {
				t.Errorf("成功したログオンの情報源 = %+v", e)
			}
		case event.StatusFailure:
			failures++
		}
	}
	if logons != 1 || failures > authFailureBurst+1 || failures < authFailureBurst {
		t.Errorf("ログオン %d、失敗 %d", logons, failures)
	}
	// 少し待ってから失敗が届くと、記録しなかった数を添える。
	time.Sleep(600 * time.Millisecond)
	appendFile(t, authLog, "Oct 19 10:00:05 pc sshd[2]: Invalid user last from 192.0.2.66 port 9\n")
	deadline := time.Now().Add(5 * time.Second)
	for {
		evs := get()
		last := evs[len(evs)-1]
		if last.User.Name == "last" {
			if n, _ := last.Unmapped["suppressed"].(int); n < 25 {
				t.Errorf("記録しなかった数 = %v", last.Unmapped)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("上限の後の失敗が届かない")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// セッションを読めないときは、認証のログの成功したログオンも記録する。認証のログのファイルがなければ journalctl を使う。
func TestLogonMonitorJournal(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "journalctl")
	os.WriteFile(script, []byte(`#!/bin/sh
for a in "$@"; do echo "$a" >> "$0.args"; done
echo '{"MESSAGE":"Accepted publickey for bob from 192.0.2.7 port 22 ssh2","SYSLOG_IDENTIFIER":"sshd","_PID":"9"}'
echo '{"MESSAGE":"pam_unix(su:auth): authentication failure; logname=bob uid=1000 euid=0 tty=pts/0 ruser=bob rhost=  user=bob","SYSLOG_IDENTIFIER":"su"}'
echo '{"MESSAGE":"unrelated","SYSLOG_IDENTIFIER":"cron"}'
exec sleep 60
`), 0o755)
	m, err := newLogonMonitor(LogonConfig{Enabled: true, SessionsDir: filepath.Join(dir, "none"), AuthLogs: []string{}, Journal: true, Journalctl: script, Poll: 20 * time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	evs := waitEvents(t, collect(t, m), 2)
	if evs[0].StatusID != event.StatusSuccess || evs[0].User.Name != "bob" || evs[0].SrcEndpoint.IP != "192.0.2.7" ||
		evs[1].StatusID != event.StatusFailure || evs[1].Service.Name != "su" || evs[1].Unmapped["auth_log"].(map[string]any)["source"] != "journal" {
		t.Errorf("ジャーナルのイベント = %+v / %+v", evs[0], evs[1])
	}
	args, _ := os.ReadFile(script + ".args")
	if !strings.Contains(string(args), "--follow") || !strings.Contains(string(args), "SYSLOG_FACILITY=10") {
		t.Errorf("journalctl の引数 = %s", args)
	}
	// 情報源が 1 つもなければ使えない。
	if _, err := newLogonMonitor(LogonConfig{Enabled: true, SessionsDir: filepath.Join(dir, "none"), AuthLogs: []string{}, Journal: false}, nil); err == nil {
		t.Error("情報源がないのに使えるとした")
	}
}

// 認証のログ、ジャーナル、セッションのファイルの読み取りは、どんな入力でも止まらず、作ったイベントは正しい形になる。
func FuzzParseLogons(f *testing.F) {
	f.Add("Oct 19 10:00:00 pc sshd[1]: Invalid user admin from 192.0.2.11 port 50000")
	f.Add("2026-10-19T10:00:00+09:00 pc sshd-session[2]: Failed password for alice from 2001:db8::1 port 22 ssh2")
	f.Add("Oct 19 10:00:00 pc sudo: pam_unix(sudo:auth): authentication failure; logname=a uid=1 euid=0 tty=x ruser=a rhost=  user=a")
	f.Add(`{"MESSAGE":[65,99],"SYSLOG_IDENTIFIER":"sshd","_PID":"1"}`)
	f.Add("USER=\"a\\\"b\"\nREMOTE=1\nREMOTE_HOST=192.0.2.1\nTTY=pts/0\nREALTIME=1\nLEADER=0")
	f.Fuzz(func(t *testing.T, s string) {
		now := time.Unix(1760000000, 0)
		if ident, pid, msg, ok := parseSyslogLine(s); ok {
			if r := parseAuthMessage(ident, pid, msg); r != nil {
				if err := r.event(now).Validate(); err != nil {
					t.Fatalf("%q: %v", s, err)
				}
			}
		}
		if ident, pid, msg, ok := parseJournalLine([]byte(s)); ok {
			if r := parseAuthMessage(ident, pid, msg); r != nil {
				if err := r.event(now).Validate(); err != nil {
					t.Fatalf("%q: %v", s, err)
				}
			}
		}
		if r := parseAuthMessage("sshd", 1, s); r != nil {
			if err := r.event(now).Validate(); err != nil {
				t.Fatalf("%q: %v", s, err)
			}
		}
		info := parseEnvFile([]byte(s))
		if userSession(info) {
			if err := sessionEvent("1", info, event.AuthLogon, now).Validate(); err != nil {
				t.Fatalf("%q: %v", s, err)
			}
		}
	})
}
