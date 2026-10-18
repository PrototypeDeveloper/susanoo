//go:build linux

package dhcp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
)

// Serve は LAN のインターフェース iface で要求を受け付け、ctx が終わるまで応答する（Listen と ServeConn をまとめたもの）。
func (s *Server) Serve(ctx context.Context, iface string) error {
	pc, err := Listen(iface)
	if err != nil {
		return err
	}
	return s.ServeConn(ctx, pc)
}

// Listen は、インターフェース iface だけに結び付けた DHCP のソケット（UDP 67）を開く
// （CAP_NET_RAW と CAP_NET_BIND_SERVICE が必要）。権限を分けるとき（G12）は、執行部が開いて非特権の側に渡す。
func Listen(iface string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); serr != nil {
				return
			}
			if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); serr != nil {
				return
			}
			serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		})
		if err != nil {
			return err
		}
		return serr
	}}
	return lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:67")
}

// ServeConn は Listen で開いたソケット pc で要求を受け付け、ctx が終わるまで応答する。pc は閉じる。
func (s *Server) ServeConn(ctx context.Context, pc net.PacketConn) error {
	defer pc.Close()
	go func() { <-ctx.Done(); pc.Close() }()
	s.log.Info("DHCP サーバーを起動しました", "範囲", s.cfg.RangeStart.String()+"-"+s.cfg.RangeEnd.String())

	buf := make([]byte, 1500)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			return err
		}
		req, err := Parse(buf[:n])
		if err != nil {
			s.log.Debug("DHCP: 不正なメッセージを捨てました", "エラー", err)
			continue
		}
		reply := s.Handle(req)
		if reply == nil {
			continue
		}
		if _, err := pc.WriteTo(reply.Marshal(), destination(req, reply)); err != nil {
			s.log.Warn("DHCP: 応答を送れません", "エラー", err)
		}
	}
}

// destination は応答の宛先を返す。アドレスを持っている（更新中の）クライアントには直接送り、
// それ以外はブロードキャストする。
func destination(req, reply *Message) *net.UDPAddr {
	if reply.Type() != Nak && req.CIAddr.Is4() && !req.CIAddr.IsUnspecified() {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(req.CIAddr, 68))
	}
	return &net.UDPAddr{IP: net.IPv4bcast, Port: 68}
}
