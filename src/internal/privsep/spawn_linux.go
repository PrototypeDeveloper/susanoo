//go:build linux

package privsep

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// 執行部に残す capability（linux/capability.h の番号）。
const (
	capDacReadSearch = 2  // 利用者のディレクトリの下の監視、/proc の読み取り
	capNetAdmin      = 12 // nft による自己隔離（nft のプロセスにも引き継がれる）
	capSysPtrace     = 19 // ほかの利用者のプロセスの /proc/<pid>/fd と exe の読み取り
	capSysAdmin      = 21 // fanotify
)

// ExecutorCaps は CLIENT の執行部に残す capability。
var ExecutorCaps = []int{capDacReadSearch, capNetAdmin, capSysPtrace, capSysAdmin}

// GWExecutorCaps は GW の執行部に残す capability。ソケットは非特権のプロセスを起動する前に開いて渡すので、
// nft のための CAP_NET_ADMIN だけでよい。
var GWExecutorCaps = []int{capNetAdmin}

// CapMask は capability の番号の一覧をビットの集合にする（/proc/<pid>/status の CapEff と同じ形）。
func CapMask(caps []int) uint64 {
	var m uint64
	for _, c := range caps {
		m |= 1 << c
	}
	return m
}

const (
	prSetDumpable        = 4
	prSetName            = 15
	prCapbsetDrop        = 24
	prSetNoNewPrivs      = 38
	prCapAmbient         = 47
	prCapAmbientClearAll = 4
	capVersion3          = 0x20080522 // _LINUX_CAPABILITY_VERSION_3
)

type capHeader struct {
	version uint32
	pid     int32
}

type capData struct {
	effective, permitted, inheritable uint32
}

// Child は起動し直した非特権のプロセス（CLIENT の解析部、GW の CONTROLLER と LAN 側の処理）。
type Child struct {
	Pid    int
	Exited <-chan error // 終わると、終わり方を 1 回送る
}

// Spawn は、自分自身を利用者 name の権限で、引数 args で起動し直す。socketpair の片方を fd 3（ConnFD）として、
// extra を fd 4 から順に渡し、こちら側の端を返す。補助グループは外し、作業ディレクトリは / にし、環境変数は渡さない。
// こちらのプロセスが終わると、起動したプロセスも SIGKILL で終わる。CAP_SETUID と CAP_SETGID が必要。
func Spawn(name string, extra []*os.File, args ...string) (*Child, *os.File, error) {
	uid, gid, err := lookupUser(name)
	if err != nil {
		return nil, nil, err
	}
	if uid == 0 {
		return nil, nil, errors.New("privsep: 非特権のプロセスを root で動かすことはできません")
	}
	ours, theirs, err := Socketpair()
	if err != nil {
		return nil, nil, err
	}
	defer theirs.Close()

	// 実行ファイルは /proc/self/exe で指す。途中のディレクトリ（ホームなど）を解析部の利用者が辿れなくても起動できる。
	cmd := exec.Command("/proc/self/exe", args...)
	cmd.Args[0] = os.Args[0]
	cmd.ExtraFiles = append([]*os.File{theirs}, extra...)
	cmd.Stderr = os.Stderr
	cmd.Dir = "/"
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}},
		Pdeathsig:  syscall.SIGKILL,
	}
	started := make(chan error, 1)
	exited := make(chan error, 1)
	go func() {
		// Pdeathsig は起動したスレッドが終わったときに送られるので、起動したプロセスが終わるまでこのスレッドを保つ。
		runtime.LockOSThread()
		if err := cmd.Start(); err != nil {
			started <- err
			return
		}
		started <- nil
		exited <- cmd.Wait()
	}()
	if err := <-started; err != nil {
		ours.Close()
		return nil, nil, fmt.Errorf("privsep: 非特権のプロセスを起動できません: %w", err)
	}
	return &Child{Pid: cmd.Process.Pid, Exited: exited}, ours, nil
}

// Socketpair は、プロセスどうしをつなぐ socketpair を作る。非ブロッキングにして Go のポーラーで待つ
// （そうしないと Close で読み込みを止められない）。
func Socketpair() (*os.File, *os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("privsep: socketpair: %w", err)
	}
	return os.NewFile(uintptr(fds[0]), "privsep"), os.NewFile(uintptr(fds[1]), "privsep-peer"), nil
}

// ConnFD は、起動し直したプロセスが執行部とつながる fd。
const ConnFD = 3

// OpenConnFD は、起動し直したプロセスの側で、執行部とつながる fd を開く。
func OpenConnFD() (*os.File, error) { return InheritedFile(ConnFD, "privsep") }

// InheritedFile は、起動し直したプロセスの側で、受け継いだ fd を開く。Go のポーラーで待てるよう非ブロッキングにする。
// Spawn の extra の i 番目は fd ConnFD+1+i になる。
func InheritedFile(fd int, name string) (*os.File, error) {
	if err := syscall.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("privsep: 受け継いだ fd %d（%s）がありません: %w", fd, name, err)
	}
	return os.NewFile(uintptr(fd), name), nil
}

// LookupUser は利用者の名前か番号から UID と GID を返す。番号で指定したときは GID も同じ番号にする。
func LookupUser(name string) (uid, gid uint32, err error) { return lookupUser(name) }

// lookupUser は利用者の名前か番号から UID と GID を返す。
func lookupUser(name string) (uint32, uint32, error) {
	if n, err := strconv.ParseUint(name, 10, 32); err == nil {
		return uint32(n), uint32(n), nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, fmt.Errorf("privsep: 解析部の利用者 %q が見つかりません: %w", name, err)
	}
	uid, err1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, err2 := strconv.ParseUint(u.Gid, 10, 32)
	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("privsep: 利用者 %q の番号を解釈できません", name)
	}
	return uint32(uid), uint32(gid), nil
}

// DropCapabilities は、keep 以外の capability を、すべてのスレッドで、取り戻せないように手放す。
// 上限の集合（bounding set）からも外すので、実行するプログラム（nft）も keep を超える権限を持たない。
// 解析部を起動した後に呼ぶ。CGO_ENABLED=0 で作った実行ファイルでだけ使える。
func DropCapabilities(keep []int) error {
	mask := CapMask(keep)
	last := 63
	if b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n < 64 {
			last = n
		}
	}
	for c := 0; c <= last; c++ {
		if mask&(1<<c) != 0 {
			continue
		}
		if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, prCapbsetDrop, uintptr(c), 0); e != 0 && e != syscall.EINVAL {
			return capError("PR_CAPBSET_DROP", e)
		}
	}
	if _, _, e := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, prCapAmbient, prCapAmbientClearAll, 0, 0, 0, 0); e != 0 && e != syscall.EINVAL {
		return capError("PR_CAP_AMBIENT", e)
	}
	hdr := capHeader{version: capVersion3}
	data := [2]capData{
		{effective: uint32(mask), permitted: uint32(mask)},
		{effective: uint32(mask >> 32), permitted: uint32(mask >> 32)},
	}
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return capError("capset", e)
	}
	return nil
}

func capError(op string, e syscall.Errno) error {
	if e == syscall.ENOTSUP {
		return fmt.Errorf("privsep: %s: cgo を使った実行ファイルではすべてのスレッドの権限を変えられません（CGO_ENABLED=0 で作ってください）", op)
	}
	return fmt.Errorf("privsep: %s: %w", op, e)
}

// Harden は、プロセスがこれ以上の権限を得られないようにし（no_new_privs）、ほかのプロセスから
// メモリを読まれないようにする（dumpable を 0 にする。ptrace と /proc/<pid>/mem を防ぎ、コアダンプも残さない）。
func Harden() error {
	if _, _, e := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); e != 0 {
		return capError("PR_SET_NO_NEW_PRIVS", e)
	}
	if _, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetDumpable, 0, 0, 0, 0, 0); e != 0 {
		return fmt.Errorf("privsep: PR_SET_DUMPABLE: %w", e)
	}
	return nil
}

// SetName は、すべてのスレッドのプロセス名（comm、15 バイトまで）を name にする。
// /proc/self/exe で起動し直したプロセスの名前は「exe」になるため、ps などで見分けられるようにする。
func SetName(name string) error {
	b := make([]byte, 16)
	copy(b[:15], name)
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, prSetName, uintptr(unsafe.Pointer(&b[0])), 0); e != 0 {
		return capError("PR_SET_NAME", e)
	}
	return nil
}
