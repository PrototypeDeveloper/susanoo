//go:build linux

package flow

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"syscall"
	"time"
)

// DefaultLogGroup は nftables が最初の数パケットを渡す NFLOG のグループ。
const DefaultLogGroup = 100

// DefaultBlockGroup は nftables が落としたパケットの一部を渡す NFLOG のグループ（脅威情報のアドレスの遮断）。
const DefaultBlockGroup = 101

const (
	recvBufSize   = 8 << 20
	copyRange     = 4096
	expireEvery   = 10 * time.Second
	soRcvbufForce = 33 // SO_RCVBUFFORCE
)

// Config は通信の記録の設定。
type Config struct {
	LAN        netip.Prefix // LAN のネットワーク
	Gateway    netip.Addr   // GW の LAN 側のアドレス
	LAN6       netip.Prefix // LAN の IPv6 のネットワーク（IPv6 を転送しないなら無効）
	Gateway6   netip.Addr   // GW の LAN 側の IPv6 アドレス
	LogGroup   uint16       // 最初の数パケットの NFLOG のグループ
	BlockGroup uint16       // 落としたパケットの NFLOG のグループ（0 なら受け取らない）
	OnRecord   func(Record)
	Logger     *slog.Logger
}

// Sockets は通信の記録に使う netlink のソケット。
type Sockets struct {
	Conntrack *os.File // conntrack の接続の終わりのイベント
	NFLOG     *os.File // NFLOG のグループに結び付けたソケット
}

// Close はソケットを閉じる。
func (s *Sockets) Close() {
	s.Conntrack.Close()
	s.NFLOG.Close()
}

// OpenSockets は conntrack のイベントのソケットを開き、NFLOG のグループ groups（省略すると DefaultLogGroup）に
// 結び付けたソケットを開く。CAP_NET_ADMIN が必要。権限を分けるとき（G12）は、執行部が開いて非特権の側に渡す。
// 開いた後の受信には権限は要らない。
func OpenSockets(groups ...uint16) (*Sockets, error) {
	if len(groups) == 0 {
		groups = []uint16{DefaultLogGroup}
	}
	ct, err := openNetlink(1 << (groupCTDestr - 1))
	if err != nil {
		return nil, fmt.Errorf("flow: conntrack のイベントを受け取れません: %w", err)
	}
	nl, err := openNetlink(0)
	if err != nil {
		ct.Close()
		return nil, fmt.Errorf("flow: NFLOG を受け取れません: %w", err)
	}
	for _, group := range groups {
		for _, m := range nflogBindMessages(group, copyRange) {
			if err := request(nl, m); err != nil {
				ct.Close()
				nl.Close()
				return nil, fmt.Errorf("flow: NFLOG のグループ %d に結び付けません: %w", group, err)
			}
		}
	}
	return &Sockets{Conntrack: ct, NFLOG: nl}, nil
}

// Run は ctx が終わるまで、conntrack と NFLOG のイベントを受け取って記録する（OpenSockets と RunSockets をまとめたもの）。
// conntrack の通信量と時刻は、nf_conntrack_acct と nf_conntrack_timestamp が有効なときだけ記録できる（EnableAccounting）。
func Run(ctx context.Context, cfg Config) error {
	groups := []uint16{cmp.Or(cfg.LogGroup, DefaultLogGroup)}
	if cfg.BlockGroup != 0 {
		groups = append(groups, cfg.BlockGroup)
	}
	socks, err := OpenSockets(groups...)
	if err != nil {
		return err
	}
	return RunSockets(ctx, cfg, socks)
}

// RunSockets は OpenSockets で開いたソケットで、ctx が終わるまでイベントを受け取って記録する。socks は閉じる。
func RunSockets(ctx context.Context, cfg Config, socks *Sockets) error {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.LogGroup == 0 {
		cfg.LogGroup = DefaultLogGroup
	}
	ct, nl := socks.Conntrack, socks.NFLOG
	defer socks.Close()

	type item struct {
		ct      *conntrack
		packet  []byte
		blocked bool
	}
	items := make(chan item, 1024)
	push := func(it item) {
		select {
		case items <- it:
		case <-ctx.Done():
		}
	}
	errc := make(chan error, 2)
	read := func(f *os.File, name string, handle func(nlMsg)) {
		buf := make([]byte, 1<<16)
		dropped := 0
		for {
			n, err := recv(f, buf)
			if errors.Is(err, syscall.ENOBUFS) {
				if dropped++; dropped%100 == 1 {
					cfg.Logger.Warn("通信の記録が追いつかず、イベントを取りこぼしました", "種類", name, "回数", dropped)
				}
				continue
			}
			if err != nil {
				errc <- err
				return
			}
			msgs, _ := parseMessages(buf[:n])
			for _, m := range msgs {
				handle(m)
			}
		}
	}
	go read(ct, "conntrack", func(m nlMsg) {
		if m.typ != msgCTDelete {
			return
		}
		if c, err := parseConntrack(m.data); err == nil {
			push(item{ct: &c})
		}
	})
	go read(nl, "NFLOG", func(m nlMsg) {
		if m.typ != msgULogPkt {
			return
		}
		group, p, err := parseNFLog(m.data)
		switch {
		case err != nil:
		case group == cfg.LogGroup:
			push(item{packet: append([]byte(nil), p...)})
		case cfg.BlockGroup != 0 && group == cfg.BlockGroup:
			push(item{packet: append([]byte(nil), p...), blocked: true})
		}
	})
	go func() { <-ctx.Done(); ct.Close(); nl.Close() }()

	p := newProcessor([]netip.Prefix{cfg.LAN, cfg.LAN6}, []netip.Addr{cfg.Gateway, cfg.Gateway6}, cfg.OnRecord)
	tick := time.NewTicker(expireEvery)
	defer tick.Stop()
	cfg.Logger.Info("通信の記録を始めました", "LAN", cfg.LAN, "NFLOG のグループ", cfg.LogGroup)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errc:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		case it := <-items:
			switch {
			case it.ct != nil:
				p.destroyed(*it.ct, time.Now())
			case it.blocked:
				p.blocked(it.packet, time.Now())
			default:
				p.packet(it.packet, time.Now())
			}
		case now := <-tick.C:
			p.tracker.expire(now)
		}
	}
}

// EnableAccounting は conntrack の通信量と時刻の記録を有効にする（このネットワーク名前空間の sysctl）。
func EnableAccounting() error {
	for _, name := range []string{"nf_conntrack_acct", "nf_conntrack_timestamp"} {
		if err := os.WriteFile("/proc/sys/net/netfilter/"+name, []byte("1\n"), 0o644); err != nil {
			return fmt.Errorf("flow: %s を有効にできません: %w", name, err)
		}
	}
	return nil
}

func openNetlink(groups uint32) (*os.File, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, syscall.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soRcvbufForce, recvBufSize); err != nil {
		syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, recvBufSize)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: groups}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "netlink"), nil
}

func recv(f *os.File, buf []byte) (int, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var rerr error
	if err := rc.Read(func(fd uintptr) bool {
		n, _, rerr = syscall.Recvfrom(int(fd), buf, 0)
		return rerr != syscall.EAGAIN
	}); err != nil {
		return 0, err
	}
	return n, rerr
}

// request は設定のメッセージを送り、応答を確かめる。
func request(f *os.File, msg []byte) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Write(func(fd uintptr) bool {
		serr = syscall.Sendto(int(fd), msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
		return serr != syscall.EAGAIN
	}); err != nil {
		return err
	}
	if serr != nil {
		return serr
	}
	f.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer f.SetReadDeadline(time.Time{})
	buf := make([]byte, 4096)
	for {
		n, err := recv(f, buf)
		if err != nil {
			return err
		}
		msgs, _ := parseMessages(buf[:n])
		for _, m := range msgs {
			if m.typ == nlmsgError {
				if code := ackError(m); code != 0 {
					return syscall.Errno(-code)
				}
				return nil
			}
		}
	}
}
