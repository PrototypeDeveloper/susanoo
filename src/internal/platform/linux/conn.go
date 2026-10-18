//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"susanoo/internal/event"
)

// 通信とプロセスの結び付け（C2）。sock_diag で TCP（接続中、接続処理中）と、相手を決めた UDP のソケットの一覧を
// 定期的に取り、新しいソケットを i ノード番号から /proc/*/fd でプロセスに結び付けて記録する。
// 一覧を取る間隔より短い接続は記録できないことがある。

const (
	sockDiagByFamily = 20
	nlmFDump         = 0x300
	nlmsgDone        = 3
	inetDiagReqLen   = 56
	inetDiagMsgLen   = 72
	tcpEstablished   = 1
	tcpSynSent       = 2
	tcpListen        = 10
	connDedupe       = time.Minute
	DefaultConnPoll  = 2 * time.Second
)

// sockInfo はソケットの情報。
type sockInfo struct {
	proto       uint8 // syscall.IPPROTO_TCP か IPPROTO_UDP
	state       uint8
	local, peer netip.AddrPort
	uid, inode  uint32
}

// parseDiagMsg は inet_diag_msg を読む。
func parseDiagMsg(b []byte, proto uint8) (sockInfo, bool) {
	if len(b) < inetDiagMsgLen {
		return sockInfo{}, false
	}
	var src, dst netip.Addr
	switch b[0] {
	case syscall.AF_INET:
		src, dst = netip.AddrFrom4([4]byte(b[8:12])), netip.AddrFrom4([4]byte(b[24:28]))
	case syscall.AF_INET6:
		src, dst = netip.AddrFrom16([16]byte(b[8:24])).Unmap(), netip.AddrFrom16([16]byte(b[24:40])).Unmap()
	default:
		return sockInfo{}, false
	}
	return sockInfo{
		proto: proto,
		state: b[1],
		local: netip.AddrPortFrom(src, binary.BigEndian.Uint16(b[4:6])),
		peer:  netip.AddrPortFrom(dst, binary.BigEndian.Uint16(b[6:8])),
		uid:   binary.NativeEndian.Uint32(b[64:68]),
		inode: binary.NativeEndian.Uint32(b[68:72]),
	}, true
}

// dumpSockets は family と proto のソケットのうち、states（ビットの集合）の状態のものを返す。
func dumpSockets(family, proto uint8, states uint32) ([]sockInfo, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_INET_DIAG)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	tv := syscall.Timeval{Sec: 2}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	req := make([]byte, nlmsgHdrLen+inetDiagReqLen)
	binary.NativeEndian.PutUint32(req[0:4], uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:6], sockDiagByFamily)
	binary.NativeEndian.PutUint16(req[6:8], syscall.NLM_F_REQUEST|nlmFDump)
	binary.NativeEndian.PutUint32(req[8:12], 1)
	body := req[nlmsgHdrLen:]
	body[0], body[1] = family, proto
	binary.NativeEndian.PutUint32(body[4:8], states)
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, err
	}

	var out []sockInfo
	buf := make([]byte, 1<<16)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return out, err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return out, err
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case nlmsgDone:
				return out, nil
			case syscall.NLMSG_ERROR:
				return out, errors.New("sock_diag: エラーの応答")
			case sockDiagByFamily:
				if s, ok := parseDiagMsg(m.Data, proto); ok {
					out = append(out, s)
				}
			}
		}
	}
}

const nlmsgHdrLen = 16

// socketOwners は /proc/*/fd を調べ、ソケットの i ノード番号からプロセスの番号への対応を返す。
func socketOwners() map[uint32]int {
	owners := map[uint32]int{}
	dirs, _ := filepath.Glob("/proc/[0-9]*/fd")
	for _, d := range dirs {
		pid, err := strconv.Atoi(filepath.Base(filepath.Dir(d)))
		if err != nil {
			continue
		}
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			link, err := os.Readlink(filepath.Join(d, e.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			if ino, err := strconv.ParseUint(strings.TrimSuffix(link[len("socket:["):], "]"), 10, 32); err == nil {
				if _, ok := owners[uint32(ino)]; !ok {
					owners[uint32(ino)] = pid
				}
			}
		}
	}
	return owners
}

type connKey struct {
	pid   int
	proto uint8
	peer  netip.AddrPort
}

type connMonitor struct {
	interval time.Duration
	self     int
	loopback bool // 試験用。ループバックの通信も記録する
	limiter  *limiter
	procs    *procCache
	agents   *agentMatcher
	known    map[uint32]bool // 記録済みのソケット
	recent   map[connKey]time.Time
	owners   map[uint32]int
}

func newConnMonitor(interval time.Duration, procs *procCache, agents *agentMatcher) (*connMonitor, error) {
	if _, err := dumpSockets(syscall.AF_INET, syscall.IPPROTO_TCP, 1<<tcpListen); err != nil {
		return nil, fmt.Errorf("sock_diag: %w", err)
	}
	if interval <= 0 {
		interval = DefaultConnPoll
	}
	return &connMonitor{interval: interval, self: os.Getpid(), limiter: newLimiter(50, 200), procs: procs, agents: agents,
		known: map[uint32]bool{}, recent: map[connKey]time.Time{}, owners: map[uint32]int{}}, nil
}

func (m *connMonitor) close() error { return nil }

func (m *connMonitor) run(ctx context.Context, emit func(*event.Event)) error {
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		m.poll(time.Now(), emit)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// poll はソケットの一覧を取り、新しい接続を記録する。
func (m *connMonitor) poll(now time.Time, emit func(*event.Event)) {
	listening := map[uint16]bool{}
	var socks []sockInfo
	for _, fam := range []uint8{syscall.AF_INET, syscall.AF_INET6} {
		ls, _ := dumpSockets(fam, syscall.IPPROTO_TCP, 1<<tcpListen)
		for _, s := range ls {
			listening[s.local.Port()] = true
		}
		tcp, _ := dumpSockets(fam, syscall.IPPROTO_TCP, 1<<tcpEstablished|1<<tcpSynSent)
		udp, _ := dumpSockets(fam, syscall.IPPROTO_UDP, 1<<tcpEstablished)
		socks = append(append(socks, tcp...), udp...)
	}

	present := map[uint32]bool{}
	var fresh []sockInfo
	for _, s := range socks {
		if s.inode == 0 || !m.interesting(s.peer.Addr()) {
			continue
		}
		present[s.inode] = true
		if !m.known[s.inode] {
			fresh = append(fresh, s)
		}
	}
	for ino := range m.known {
		if !present[ino] {
			delete(m.known, ino)
		}
	}
	if len(fresh) == 0 {
		return
	}
	for _, s := range fresh {
		if _, ok := m.owners[s.inode]; !ok {
			m.owners = socketOwners() // 知らないソケットがあるときだけ調べ直す
			break
		}
	}
	for k, t := range m.recent {
		if now.Sub(t) > connDedupe {
			delete(m.recent, k)
		}
	}
	for _, s := range fresh {
		m.known[s.inode] = true
		pid := m.owners[s.inode]
		if pid == m.self || m.isChild(pid) {
			continue // 自分と、自分が起動した解析部の通信（CONTROLLER との管理通信）は記録しない
		}
		key := connKey{pid, s.proto, s.peer}
		if _, dup := m.recent[key]; dup || !m.limiter.allow(now) {
			continue
		}
		m.recent[key] = now
		emit(m.connEvent(s, pid, listening[s.local.Port()] && s.proto == syscall.IPPROTO_TCP, now))
	}
}

// isChild は pid が自分の子プロセスかを返す。
func (m *connMonitor) isChild(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, ppid := readStatus(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	return ppid == m.self
}

func (m *connMonitor) interesting(a netip.Addr) bool {
	if !a.IsValid() || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsMulticast() {
		return false
	}
	return m.loopback || !a.IsLoopback()
}

// connEvent は接続のイベントを作る。発信元のプロセスが AI エージェントの配下なら、unmapped.agent を付ける（C9）。
func (m *connMonitor) connEvent(s sockInfo, pid int, inbound bool, now time.Time) *event.Event {
	e := event.New(event.ClassNetworkActivity, event.NetworkOpen, event.SeverityInformational, now)
	e.SrcEndpoint = &event.Endpoint{IP: s.local.Addr().String(), Port: int(s.local.Port())}
	e.DstEndpoint = &event.Endpoint{IP: s.peer.Addr().String(), Port: int(s.peer.Port())}
	proto := "tcp"
	if s.proto == syscall.IPPROTO_UDP {
		proto = "udp"
	}
	direction := 2 // 外向き
	if inbound {
		direction = 1
	}
	e.Connection = &event.Connection{ProtocolName: proto, DirectionID: direction}
	if pid > 0 {
		proc, anc := m.procs.inspect(pid)
		e.Actor = &event.Actor{Process: proc}
		m.agents.annotate(e, proc, anc)
	} else {
		e.Actor = &event.Actor{User: &event.User{UID: strconv.Itoa(int(s.uid))}}
	}
	return e
}
