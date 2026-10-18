//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"susanoo/internal/event"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type collector struct {
	mu  sync.Mutex
	evs []*event.Event
}

func (c *collector) emit(e *event.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evs = append(c.evs, e)
}

func (c *collector) find(t *testing.T, what string, cond func(*event.Event) bool) *event.Event {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		for _, e := range c.evs {
			if cond(e) {
				c.mu.Unlock()
				return e
			}
		}
		c.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s のイベントが届かない", what)
	return nil
}

// loopbackUp は lo が down なら up にする。unshare --net で作ったばかりの名前空間では lo が down のため。
func loopbackUp(t *testing.T) {
	t.Helper()
	ifi, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("lo がない: %v", err)
	}
	if ifi.Flags&net.FlagUp != 0 {
		return
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	var req [40]byte // struct ifreq（名前 16 バイトと、ifr_flags を含む共用体）
	copy(req[:], "lo")
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&req[0]))); e != 0 {
		t.Fatalf("SIOCGIFFLAGS: %v", e)
	}
	binary.NativeEndian.PutUint16(req[16:18], binary.NativeEndian.Uint16(req[16:18])|syscall.IFF_UP)
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&req[0]))); e != 0 {
		t.Skipf("lo を up にできない（root 権限が必要）: %v", e)
	}
}

func TestConnMonitor(t *testing.T) {
	loopbackUp(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	m, err := newConnMonitor(time.Second, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.loopback, m.self = true, -1 // 試験では、自分のループバックの接続も記録する
	var col collector
	m.poll(time.Now(), col.emit)
	local := netip.MustParseAddrPort(c.LocalAddr().String())
	e := col.find(t, "接続", func(e *event.Event) bool {
		return e.SrcEndpoint != nil && e.SrcEndpoint.Port == int(local.Port()) && e.Connection.DirectionID == 2
	})
	if e.Actor == nil || e.Actor.Process == nil || e.Actor.Process.PID != os.Getpid() || e.Connection.ProtocolName != "tcp" {
		t.Errorf("接続のイベント = %+v（プロセス %+v）", e, e.Actor)
	}
	// 待ち受けている側（受け入れた接続）は内向き。
	col.find(t, "内向きの接続", func(e *event.Event) bool {
		return e.DstEndpoint != nil && e.DstEndpoint.Port == int(local.Port()) && e.Connection.DirectionID == 1
	})

	// 同じ接続は 2 回記録しない。
	n := len(col.evs)
	m.poll(time.Now(), col.emit)
	if len(col.evs) != n {
		t.Error("同じ接続を 2 回記録した")
	}
}

// 自分が起動した解析部の通信（CONTROLLER との管理通信）は記録しない。
func TestConnMonitorSkipsOwnChildren(t *testing.T) {
	m := &connMonitor{self: os.Getpid()}
	cmd := exec.Command("/bin/sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	if !m.isChild(cmd.Process.Pid) {
		t.Error("子プロセスを見分けられない")
	}
	for _, pid := range []int{os.Getpid(), os.Getppid(), 0, -1} {
		if m.isChild(pid) {
			t.Errorf("PID %d を子プロセスとした", pid)
		}
	}
}

func TestFileMonitorImportantPaths(t *testing.T) {
	dir := t.TempDir()
	watchedFile := filepath.Join(dir, "single", "authorized_keys")
	os.MkdirAll(filepath.Dir(watchedFile), 0o700)
	os.WriteFile(watchedFile, []byte("x"), 0o600)
	m, err := newFileMonitor(FileConfig{Paths: []string{dir, watchedFile}}, nil, nil, quiet)
	if err != nil {
		t.Skipf("FID 方式の fanotify を使えない: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var col collector
	go m.run(ctx, col.emit)
	go func() { <-ctx.Done(); m.close() }()

	// 別のプロセスに変更させる（自分自身の変更は記録しない）。
	sh := func(script string) {
		if out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v %s", script, err, out)
		}
	}
	sh("echo a > " + filepath.Join(dir, "cron-job"))
	col.find(t, "作成", func(e *event.Event) bool {
		return e.ClassUID == event.ClassFileSystemActivity && e.ActivityID == event.FileCreate && e.File.Path == filepath.Join(dir, "cron-job")
	})
	col.find(t, "更新", func(e *event.Event) bool { return e.ActivityID == event.FileUpdate && e.File.Name == "cron-job" })
	sh("echo b >> " + watchedFile + "; echo c > " + filepath.Join(filepath.Dir(watchedFile), "other"))
	col.find(t, "指定したファイルの更新", func(e *event.Event) bool { return e.File.Path == watchedFile })
	time.Sleep(200 * time.Millisecond)
	col.mu.Lock()
	for _, e := range col.evs {
		if e.File != nil && e.File.Name == "other" {
			t.Error("指定していないファイルの変更を記録した")
		}
	}
	col.mu.Unlock()
}

// fanotify が 1 件にまとめたイベントは、操作ごとに記録する。
func TestMergedFileEvents(t *testing.T) {
	dir := t.TempDir()
	m, err := newFileMonitor(FileConfig{Paths: []string{dir}}, nil, nil, quiet)
	if err != nil {
		t.Skipf("FID 方式の fanotify を使えない: %v", err)
	}
	defer m.close()
	key, err := dirKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	es := m.handle(fidEvent{mask: fanCreate | fanCloseWrite, pid: 1, dir: key, name: "job"}, now)
	if len(es) != 2 || es[0].ActivityID != event.FileCreate || es[1].ActivityID != event.FileUpdate {
		t.Fatalf("イベント = %+v", es)
	}
	// 続けて届いた同じ操作はまとめるが、ほかの操作は記録する。
	es = m.handle(fidEvent{mask: fanCloseWrite | fanDelete, pid: 1, dir: key, name: "job"}, now.Add(time.Second))
	if len(es) != 1 || es[0].ActivityID != event.FileDelete {
		t.Fatalf("イベント = %+v", es)
	}
}

func TestMassChange(t *testing.T) {
	dir := t.TempDir()
	protected := filepath.Join(dir, "Documents")
	os.Mkdir(protected, 0o700)
	m, err := newFileMonitor(FileConfig{Paths: []string{dir}, Protect: []string{protected}, MassFiles: 5, MassWindow: time.Second}, nil, nil, quiet)
	if err != nil {
		t.Skipf("FID 方式の fanotify を使えない: %v", err)
	}
	defer m.close()
	key, err := dirKey(protected)
	if err != nil {
		t.Fatal(err)
	}
	if m.protected[key] != protected {
		t.Fatalf("守る場所を洗い出していない: %v", m.protected)
	}
	now := time.Now()
	var findings []*event.Event
	// 同じファイルへの作成と書き込みは 1 つと数える。4 個のファイルではまだ検知しない。
	for i := range 4 {
		for _, mask := range []uint64{fanCreate, fanCloseWrite, fanCloseWrite} {
			if es := m.handle(fidEvent{mask: mask, pid: 4242, dir: key, name: "f" + string(rune('a'+i))}, now); len(es) > 0 {
				t.Fatalf("%d 個のファイルで検知した", i+1)
			}
		}
	}
	for i := 4; i < 12; i++ {
		for _, e := range m.handle(fidEvent{mask: fanCloseWrite, pid: 4242, dir: key, name: "f" + string(rune('a'+i))}, now) {
			findings = append(findings, e)
		}
	}
	if len(findings) != 1 || !findings[0].FindingInfo.HasType(event.FindingTypeMassChange) || !strings.Contains(findings[0].Message, "5 個以上") {
		t.Fatalf("検知結果 = %+v", findings)
	}
	// 時間枠を過ぎれば数え直すが、5 分間は同じプロセスを検知結果にしない。
	for i := range 6 {
		if es := m.handle(fidEvent{mask: fanCloseWrite, pid: 4242, dir: key, name: "g" + string(rune('a'+i))}, now.Add(2*time.Second)); len(es) > 0 {
			t.Fatal("続けて検知結果にした")
		}
	}
	// ほかのプロセスや、守る場所の外の変更は数えない。
	if es := m.handle(fidEvent{mask: fanCloseWrite, pid: 1, dir: "other", name: "x"}, now); len(es) != 0 {
		t.Error("守る場所の外の変更を数えた")
	}
	// 新しく作られたディレクトリも守る。
	sub := filepath.Join(protected, "sub")
	os.Mkdir(sub, 0o700)
	m.handle(fidEvent{mask: fanCreate | fanOnDir, pid: 1, dir: key, name: "sub"}, now)
	if subKey, _ := dirKey(sub); m.protected[subKey] != sub {
		t.Error("新しいディレクトリを守る場所に加えていない")
	}
}

func TestExecMonitorWhenPrivileged(t *testing.T) {
	m, err := newExecMonitor(newProcCache(), nil, quiet)
	if err != nil {
		t.Skipf("プロセスの監視には root 権限が必要: %v", err)
	}
	m.self = -1 // 試験では、自分が起動した子プロセスも記録する
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var col collector
	go m.run(ctx, col.emit)
	go func() { <-ctx.Done(); m.close() }()
	time.Sleep(100 * time.Millisecond)

	sleep, _ := exec.LookPath("sleep")
	real, _ := filepath.EvalSymlinks(sleep)
	cmd := exec.Command(sleep, "0.5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	e := col.find(t, "起動", func(e *event.Event) bool { return launchOf(e) && e.Process.PID == pid })
	if e.Process.File == nil || e.Process.File.Path != real || len(e.Process.File.Hashes) != 1 || !strings.Contains(e.Process.CmdLine, "0.5") {
		t.Errorf("起動のイベント = %+v（ファイル %+v）", e.Process, e.Process.File)
	}
	cmd.Wait()
	col.find(t, "終了", func(e *event.Event) bool {
		return e.ClassUID == event.ClassProcessActivity && e.ActivityID == event.ProcessTerminate && e.Process.PID == pid
	})
}

// launchOf はプロセスの起動のイベントかを返す。検知結果（FindingCreate）も activity_id が 1 なので、クラスで見分ける。
func launchOf(e *event.Event) bool {
	return e.ClassUID == event.ClassProcessActivity && e.ActivityID == event.ProcessLaunch && e.Process != nil
}

// すぐ終わるプロセスでも、名前（実行ファイルから）、利用者、祖先（先に読んだもの）が記録され、AI エージェントの帰属が付く。
func TestExecMonitorShortLived(t *testing.T) {
	m, err := newExecMonitor(newProcCache(), newAgentMatcher(DefaultAgents()), quiet)
	if err != nil {
		t.Skipf("プロセスの監視には root 権限が必要: %v", err)
	}
	m.self = -1
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var col collector
	go m.run(ctx, col.emit)
	go func() { <-ctx.Done(); m.close() }()
	time.Sleep(100 * time.Millisecond)

	// 名前を claude にした bash の子として、5 ミリ秒で終わる sleep を起動する（bash は「; sleep」があると fork する）。
	// 5 ミリ秒は、イベントを読んで親を読むには足り、/proc を読む 30 ミリ秒後には終わっている長さ。
	cmd := exec.Command("/bin/bash", "-c", `exec -a claude /bin/bash -c '/bin/sleep 0.005; /bin/sleep 0.5'`)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	sleepPath, _ := filepath.EvalSymlinks("/bin/sleep")
	// root で動かすと、sudo（実 UID は利用者）の配下なので権限昇格の検知結果も届く。起動のイベントだけを探す。
	// 終わったプロセスはコマンドラインを取れないので、コマンドラインが空のもの（5 ミリ秒の sleep）を探す。
	e := col.find(t, "短命なプロセスの起動", func(e *event.Event) bool {
		return launchOf(e) && e.Process.File != nil && e.Process.File.Path == sleepPath && e.Process.CmdLine == ""
	})
	p := e.Process
	if p.Name != commOf(sleepPath) || p.User == nil || p.User.UID == "" || p.Parent == nil || p.Parent.Name != "bash" || len(p.Lineage) == 0 {
		t.Fatalf("プロセス = %+v（親 %+v）", p, p.Parent)
	}
	if tag, _ := e.Unmapped["agent"].(agentTag); tag.Name != "claude" || tag.PID != p.Parent.PID {
		t.Errorf("帰属 = %v（親 %d）", e.Unmapped, p.Parent.PID)
	}
}

// プロセスがもう終わっていたら、イベントを読んだ直後に読んだ実 UID と親から、名前、利用者、親、系譜、帰属を補う（root は不要）。
func TestLaunchedFallback(t *testing.T) {
	// 名前を claude にした bash を親の役にする（「; :」で bash を残す）。
	parent := exec.Command("/bin/bash", "-c", `exec -a claude /bin/bash -c 'sleep 3; :'`)
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { parent.Process.Kill(); parent.Wait() }()
	time.Sleep(100 * time.Millisecond) // exec -a の後の bash に切り替わるのを待つ

	m := &execMonitor{hashing: make(chan struct{}, 1), self: os.Getpid(), procs: newProcCache(), agents: newAgentMatcher(DefaultAgents()),
		tracked: map[int]tracked{}, escalations: map[int]time.Time{}}
	var col collector
	gone := 1 << 30 // 存在しないプロセス（もう終わったプロセスの役）
	m.launched(context.Background(), gone, "/usr/lib/cargo/bin/coreutils/whoami", -1, execStatus{uid: "1000", ppid: parent.Process.Pid}, col.emit)
	if len(col.evs) != 1 {
		t.Fatalf("イベント = %d 件", len(col.evs))
	}
	e := col.evs[0]
	p := e.Process
	if p.PID != gone || p.Name != "whoami" || p.User == nil || p.User.UID != "1000" || p.CmdLine != "" {
		t.Errorf("プロセス = %+v", p)
	}
	if p.Parent == nil || p.Parent.PID != parent.Process.Pid || p.Parent.Name != "bash" || len(p.Lineage) == 0 {
		t.Errorf("親 = %+v、系譜 = %v", p.Parent, p.Lineage)
	}
	if tag, _ := e.Unmapped["agent"].(agentTag); tag.Name != "claude" || tag.PID != parent.Process.Pid {
		t.Errorf("帰属 = %v", e.Unmapped)
	}
	// 覚えておいた情報で、後から（ファイルの操作などで）引ける。
	if q, _ := m.procs.inspect(gone); q == nil || q.Name != "whoami" {
		t.Errorf("覚えた情報 = %+v", q)
	}
}

func fidRecord(mask uint64, pid int32, handle []byte, name string) []byte {
	return fidRecordOf(infoTypeDFIDName, mask, pid, handle, name)
}

// fidRecordOf は情報の種類 typ（DFID_NAME か FID）の fanotify のイベントを組み立てる。FID では name を付けない。
func fidRecordOf(typ byte, mask uint64, pid int32, handle []byte, name string) []byte {
	info := make([]byte, 4+8+8)
	info[0] = typ
	copy(info[4:12], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	binary.NativeEndian.PutUint32(info[12:16], uint32(len(handle)))
	binary.NativeEndian.PutUint32(info[16:20], 1)
	info = append(info, handle...)
	if typ == infoTypeDFIDName {
		info = append(info, name...)
		info = append(info, 0)
	}
	for len(info)%4 != 0 {
		info = append(info, 0)
	}
	binary.NativeEndian.PutUint16(info[2:4], uint16(len(info)))
	meta := make([]byte, 24)
	binary.NativeEndian.PutUint32(meta[0:], uint32(24+len(info)))
	meta[4] = fanotifyMetadataVersion
	binary.NativeEndian.PutUint16(meta[6:], 24)
	binary.NativeEndian.PutUint64(meta[8:], mask)
	binary.NativeEndian.PutUint32(meta[16:], uint32(0xffffffff))
	binary.NativeEndian.PutUint32(meta[20:], uint32(pid))
	return append(meta, info...)
}

func TestParseFIDEvents(t *testing.T) {
	buf := append(fidRecord(fanCreate, 100, []byte{9, 9, 9, 9}, "file.txt"), fidRecord(fanCloseWrite, 101, []byte{8, 8}, "b")...)
	evs, err := parseFIDEvents(buf)
	if err != nil || len(evs) != 2 {
		t.Fatalf("イベント = %+v, %v", evs, err)
	}
	if evs[0].mask != fanCreate || evs[0].pid != 100 || evs[0].name != "file.txt" || evs[0].dir == evs[1].dir {
		t.Errorf("イベント = %+v", evs[0])
	}
	bad := fidRecord(fanCreate, 1, []byte{1}, "x")
	binary.NativeEndian.PutUint32(bad[24+12:], 1000) // ハンドルの長さが大きすぎる
	if _, err := parseFIDEvents(bad); err == nil {
		t.Error("不正なハンドルの長さを受け付けた")
	}
	// ファイルの印のイベント（FAN_REPORT_FID）は、ファイルそのものの識別子を持ち、名前はない。
	evs, err = parseFIDEvents(fidRecordOf(infoTypeFID, fanOpen, 7, []byte{5, 5, 5, 5}, ""))
	if err != nil || len(evs) != 1 || evs[0].file == "" || evs[0].dir != "" || evs[0].name != "" {
		t.Errorf("FID のイベント = %+v, %v", evs, err)
	}
}

func FuzzParseFIDEvents(f *testing.F) {
	f.Add(fidRecord(fanCreate, 100, []byte{9, 9, 9, 9}, "file.txt"))
	f.Fuzz(func(t *testing.T, b []byte) {
		evs, _ := parseFIDEvents(b)
		if len(evs)*fanEventMetadataLen > len(b) {
			t.Fatal("入力より多くのイベントを返した")
		}
	})
}

func TestMountHelpers(t *testing.T) {
	if got := unescapeMount(`/media/my\040disk`); got != "/media/my disk" {
		t.Errorf("unescapeMount = %q", got)
	}
	mps, err := mountPoints()
	if err != nil || len(mps) == 0 {
		t.Fatalf("マウント位置 = %v, %v", mps, err)
	}
	for _, mp := range mps {
		if mp == "/proc" || mp == "/sys" {
			t.Errorf("疑似ファイルシステム %s を含んでいる", mp)
		}
	}
	if st, ok := startTime(os.Getpid()); !ok || st == 0 {
		t.Error("自分の起動時刻を読めない")
	}
	if _, ok := startTime(1 << 30); ok {
		t.Error("存在しないプロセスの起動時刻を返した")
	}
}

func TestLimiterAndHasher(t *testing.T) {
	l := newLimiter(1, 3)
	now := time.Now()
	allowed := 0
	for range 10 {
		if l.allow(now) {
			allowed++
		}
	}
	if allowed != 3 || l.takeDropped() != 7 || l.takeDropped() != 0 {
		t.Errorf("通した数 = %d", allowed)
	}
	if !l.allow(now.Add(time.Second)) {
		t.Error("1 秒後に回復しない")
	}

	path := filepath.Join(t.TempDir(), "bin")
	os.WriteFile(path, []byte("hello"), 0o755)
	f, _ := os.Open(path)
	defer f.Close()
	h := newHasher()
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got := h.hashFD(int(f.Fd())); got != want {
		t.Errorf("ハッシュ = %s", got)
	}
	if len(h.cache) != 1 || h.hashFD(int(f.Fd())) != want {
		t.Error("ハッシュを使い回していない")
	}
}

type fakeChecker struct {
	recorder
	exists bool
}

func (f *fakeChecker) TableExists(context.Context, string) (bool, error) { return f.exists, nil }

func TestIsolationActive(t *testing.T) {
	c := &fakeChecker{exists: true}
	p := New(Config{NFT: c})
	if ok, err := p.IsolationActive(context.Background()); err != nil || !ok {
		t.Errorf("IsolationActive = %v, %v", ok, err)
	}
	c.exists = false
	if ok, _ := p.IsolationActive(context.Background()); ok {
		t.Error("テーブルがないのに有効と返した")
	}
	if _, err := New(Config{NFT: &recorder{}}).IsolationActive(context.Background()); err == nil {
		t.Error("確かめられないのにエラーを返さない")
	}
}
