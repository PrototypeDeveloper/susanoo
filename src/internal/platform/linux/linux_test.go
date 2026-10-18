//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"susanoo/internal/event"
	"susanoo/internal/honeytoken"
	"susanoo/internal/platform"
	"susanoo/internal/policy"
)

func plant(t *testing.T) []honeytoken.Token {
	t.Helper()
	dir := t.TempDir()
	tokens, warnings, err := honeytoken.Plant([]honeytoken.Spec{
		{Path: filepath.Join(dir, "home", ".aws", "credentials"), Kind: honeytoken.KindAWS},
		{Path: filepath.Join(dir, "home", ".env"), Kind: honeytoken.KindEnv},
	}, filepath.Join(dir, "state.json"), time.Now())
	if err != nil || len(warnings) != 0 {
		t.Fatal(err, warnings)
	}
	return tokens
}

// readByOtherProcess は別のプロセスにおとりを読ませる。自分自身の接触は無視されるため。
func readByOtherProcess(t *testing.T, path string) {
	t.Helper()
	p, err := os.StartProcess("/bin/cat", []string{"cat", path}, &os.ProcAttr{Files: []*os.File{nil, nil, nil}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestWatchHoneytoken(t *testing.T) {
	tokens := plant(t)
	p := New(Config{Tokens: tokens})
	if !p.Capabilities().Has(platform.CapHoneytoken) {
		t.Fatalf("おとりの監視が使えない: %+v", p.Capabilities())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out := make(chan event.Event, 8)
	done := make(chan error, 1)
	go func() { done <- p.Watch(ctx, out) }()
	time.Sleep(100 * time.Millisecond) // 監視の開始を待つ

	readByOtherProcess(t, tokens[1].Path)

	select {
	case e := <-out:
		if err := e.Validate(); err != nil {
			t.Fatal(err)
		}
		if !e.FindingInfo.HasType(event.FindingTypeHoneytoken) {
			t.Errorf("検知の種類 = %v", e.FindingInfo.Types)
		}
		if got := e.Evidences[0].File.Path; got != tokens[1].Path {
			t.Errorf("おとり = %s, 期待値 %s", got, tokens[1].Path)
		}
		if e.Device == nil || e.Device.Hostname == "" {
			t.Errorf("端末の情報がない: %+v", e.Device)
		}
	case <-ctx.Done():
		t.Fatal("おとりへの接触を検知できない")
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Watch の戻り値 = %v", err)
	}
}

func TestWatchDedupe(t *testing.T) {
	tokens := plant(t)
	p := New(Config{Tokens: tokens})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out := make(chan event.Event, 8)
	go p.Watch(ctx, out)
	time.Sleep(100 * time.Millisecond)

	// 1 回の読み込みで open と access が届くが、検知結果は 1 件になる。
	readByOtherProcess(t, tokens[0].Path)
	<-out
	select {
	case e := <-out:
		t.Errorf("同じ接触が 2 件届いた: %s", e.Message)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestFanotifyWhenPrivileged(t *testing.T) {
	tokens := plant(t)
	w, err := newFanotify([]string{tokens[0].Path, tokens[1].Path})
	if errors.Is(err, syscall.EPERM) {
		t.Skip("fanotify には root 権限が必要")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out := make(chan fileEvent, 64)
	go w.run(ctx, out)

	// 別のプロセスの操作を、操作の種類と PID とともに検知する。
	expect := func(token int, op string, name string, args ...string) {
		t.Helper()
		p, err := os.StartProcess(name, append([]string{filepath.Base(name)}, args...), &os.ProcAttr{Files: []*os.File{nil, nil, nil}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Wait(); err != nil {
			t.Fatal(err)
		}
		for {
			select {
			case fe := <-out:
				if fe.token != token || fe.op != op {
					continue
				}
				if fe.pid != p.Pid {
					t.Errorf("%s: 触ったプロセスの PID = %d（%d のはず）", op, fe.pid, p.Pid)
				}
				return
			case <-ctx.Done():
				t.Fatalf("fanotify で %s を検知できない", op)
			}
		}
	}
	expect(0, honeytoken.OpOpen, "/bin/cat", tokens[0].Path)
	expect(1, honeytoken.OpAttrib, "/bin/chmod", "0644", tokens[1].Path)
	expect(1, honeytoken.OpMove, "/bin/mv", tokens[1].Path, tokens[1].Path+".bak")
	expect(0, honeytoken.OpDelete, "/bin/rm", tokens[0].Path)
}

// おとりの親ディレクトリの監視（FID 方式）は root でなくても使える。root でなければ、ほかのプロセスの PID は 0 になる。
func TestTokenDirEvents(t *testing.T) {
	tokens := plant(t)
	fid, names := watchTokenDirs([]string{tokens[0].Path, tokens[1].Path})
	if fid == nil {
		t.Skip("FID 方式の fanotify を使えない")
	}
	w := &fanotifyWatcher{fid: fid, names: names}
	defer fid.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out := make(chan fileEvent, 8)
	go w.readDirs(ctx, out)

	other := filepath.Join(filepath.Dir(tokens[1].Path), "other")
	os.WriteFile(other, []byte("x"), 0o600)
	p, err := os.StartProcess("/bin/rm", []string{"rm", other, tokens[1].Path}, &os.ProcAttr{Files: []*os.File{nil, nil, nil}})
	if err != nil {
		t.Fatal(err)
	}
	p.Wait()
	select {
	case fe := <-out:
		if fe.token != 1 || fe.op != honeytoken.OpDelete || (fe.pid != p.Pid && fe.pid != 0) {
			t.Errorf("イベント = %+v（PID %d）", fe, p.Pid)
		}
	case <-ctx.Done():
		t.Fatal("おとりの削除を検知できない")
	}
	select {
	case fe := <-out:
		t.Errorf("おとりでないファイルのイベント = %+v", fe)
	case <-time.After(100 * time.Millisecond):
	}
}

type recorder struct{ scripts []string }

func (r *recorder) Run(_ context.Context, script string) error {
	r.scripts = append(r.scripts, script)
	return nil
}

func TestIsolate(t *testing.T) {
	r := &recorder{}
	p := New(Config{NFT: r})
	mgmt := []netip.AddrPort{netip.MustParseAddrPort("10.77.0.1:8443")}
	updates := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}

	steps := []struct {
		level       policy.IsolationLevel
		wantUpdates bool
	}{
		{policy.IsolateFull, false}, // 全遮断でも管理通信は残す
		{policy.IsolateManagement, false},
		{policy.IsolateManagementAndUpdates, true},
	}
	for _, s := range steps {
		r.scripts = nil
		if err := p.Isolate(context.Background(), platform.Isolation{Level: s.level, Management: mgmt, Updates: updates}); err != nil {
			t.Fatal(err)
		}
		script := r.scripts[0]
		if !strings.Contains(script, "ip daddr 10.77.0.1 tcp dport 8443 accept") {
			t.Errorf("%s: 管理通信が許可されていない\n%s", s.level, script)
		}
		if got := strings.Contains(script, "192.0.2.0/24"); got != s.wantUpdates {
			t.Errorf("%s: 更新サーバーの許可 = %v, 期待値 %v", s.level, got, s.wantUpdates)
		}
	}

	r.scripts = nil
	if err := p.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.scripts[0], "delete table inet susanoo_client") {
		t.Errorf("解除のスクリプト = %q", r.scripts[0])
	}

	none := New(Config{})
	if none.Isolate(context.Background(), platform.Isolation{Management: mgmt}) == nil || none.Release(context.Background()) == nil {
		t.Error("nft の設定なしで自己隔離できた")
	}
	if none.Capabilities().Has(platform.CapIsolation) {
		t.Error("nft の設定なしで自己隔離を申告した")
	}
}

func TestProcessInfo(t *testing.T) {
	p := processInfo(os.Getpid())
	if p == nil || p.Name == "" || p.CmdLine == "" || p.File == nil || p.Parent == nil || p.User == nil {
		t.Errorf("情報が足りない: %+v", p)
	}
	if processInfo(0) != nil {
		t.Error("PID 0 の情報を返した")
	}
	if p := processInfo(1 << 30); p == nil || p.PID != 1<<30 || p.Name != "" {
		t.Errorf("存在しないプロセス: %+v", p)
	}
}

func fanBytes(eventLen uint32, vers byte, metaLen uint16, mask uint64, fd, pid int32) []byte {
	b := make([]byte, 24)
	binary.NativeEndian.PutUint32(b[0:], eventLen)
	b[4] = vers
	binary.NativeEndian.PutUint16(b[6:], metaLen)
	binary.NativeEndian.PutUint64(b[8:], mask)
	binary.NativeEndian.PutUint32(b[16:], uint32(fd))
	binary.NativeEndian.PutUint32(b[20:], uint32(pid))
	return b
}

func TestParseFanotify(t *testing.T) {
	buf := append(fanBytes(24, 3, 24, fanOpen, 7, 100), fanBytes(24, 3, 24, fanModify|fanAccess, -1, 200)...)
	evs, err := parseFanotify(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 || evs[0] != (fanMeta{fanOpen, 7, 100}) || evs[1].fd != -1 || evs[1].pid != 200 {
		t.Errorf("イベント = %+v", evs)
	}
	if fanotifyOp(evs[1].mask) != honeytoken.OpModify {
		t.Errorf("操作 = %s", fanotifyOp(evs[1].mask))
	}

	for name, b := range map[string][]byte{
		"途中で切れている": fanBytes(24, 3, 24, fanOpen, 1, 1)[:20],
		"版が違う":     fanBytes(24, 2, 24, fanOpen, 1, 1),
		"長さが短い":    fanBytes(8, 3, 24, fanOpen, 1, 1),
		"長さが長い":    fanBytes(48, 3, 24, fanOpen, 1, 1),
	} {
		if _, err := parseFanotify(b); err == nil {
			t.Errorf("%s: エラーにならない", name)
		}
	}
}

func inoBytes(wd int32, mask uint32, name string) []byte {
	b := make([]byte, 16+len(name))
	binary.NativeEndian.PutUint32(b[0:], uint32(wd))
	binary.NativeEndian.PutUint32(b[4:], mask)
	binary.NativeEndian.PutUint32(b[12:], uint32(len(name)))
	copy(b[16:], name)
	return b
}

func TestParseInotify(t *testing.T) {
	buf := append(inoBytes(1, syscall.IN_OPEN, ""), inoBytes(2, syscall.IN_DELETE_SELF|syscall.IN_ATTRIB, "name\x00\x00\x00\x00")...)
	evs, err := parseInotify(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 || evs[0].wd != 1 || inotifyOp(evs[0].mask) != honeytoken.OpOpen || inotifyOp(evs[1].mask) != honeytoken.OpDelete {
		t.Errorf("イベント = %+v", evs)
	}
	if _, err := parseInotify(inoBytes(1, syscall.IN_OPEN, "abc")[:17]); err == nil {
		t.Error("途中で切れたイベントがエラーにならない")
	}
}

func FuzzParseFanotify(f *testing.F) {
	f.Add(fanBytes(24, 3, 24, fanOpen, 7, 100))
	f.Add(append(fanBytes(32, 3, 24, fanOpen, 7, 100), make([]byte, 8)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		evs, _ := parseFanotify(b)
		if len(evs)*fanEventMetadataLen > len(b) {
			t.Fatalf("入力より多くのイベントを返した: %d", len(evs))
		}
	})
}

func FuzzParseInotify(f *testing.F) {
	f.Add(inoBytes(1, syscall.IN_OPEN, ""))
	f.Add(inoBytes(1, syscall.IN_OPEN, "abcd"))
	f.Fuzz(func(t *testing.T, b []byte) {
		evs, _ := parseInotify(b)
		if len(evs)*inotifyHeaderLen > len(b) {
			t.Fatalf("入力より多くのイベントを返した: %d", len(evs))
		}
	})
}
