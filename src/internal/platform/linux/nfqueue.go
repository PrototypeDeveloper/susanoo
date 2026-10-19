//go:build linux

package linux

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

// NFQUEUE（netfilter のキュー）。nftables が渡した、外向きの新しい接続の最初のパケットを受け取り、判断を返す（C7）。
// netlink（NETLINK_NETFILTER）で、キューに結び付き、パケットを受け取り、判断（受け入れる、印を付けて戻す）を送る。
// CAP_NET_ADMIN が必要。

// nfnetlink のキューの定数（linux/netfilter/nfnetlink_queue.h）。
const (
	nfnlSubsysQueue  = 3
	nfqnlMsgPacket   = 0
	nfqnlMsgVerdict  = 1
	nfqnlMsgConfig   = 2
	nfqaCfgCmd       = 1
	nfqaCfgParams    = 2
	nfqaCfgQueueLen  = 3
	nfqaCfgMask      = 4
	nfqaCfgFlags     = 5
	nfqaPacketHdr    = 1
	nfqaVerdictHdr   = 2
	nfqaMark         = 3
	nfqaPayload      = 10
	nfqaUID          = 16
	nfqnlCfgCmdBind  = 1
	nfqnlCopyPacket  = 2
	nfqaCfgFFailOpen = 1 // 待ち行列があふれたら、判断を待たずに通す
	nfqaCfgFUIDGID   = 8 // パケットのソケットの持ち主の UID を付ける
	nfAccept         = 1
	nfRepeat         = 4
	nlmFRequestFlag  = 1
	nlmFAckFlag      = 4
	nlmsgErrorType   = 2
	nfgenmsgLen      = 4
	nfqCopyRange     = 128  // IP と TCP・UDP のヘッダーが入る大きさ
	nfqMaxLen        = 4096 // 判断を待つパケットの上限（あふれたら通す）
)

// nfqPacket はキューに入ったパケット。
type nfqPacket struct {
	id      uint32
	payload []byte
	uid     uint32
	hasUID  bool
}

// nlAttribute は netlink の属性を作る。
func nlAttribute(typ uint16, data []byte) []byte {
	b := make([]byte, (4+len(data)+3)&^3)
	binary.NativeEndian.PutUint16(b[0:2], uint16(4+len(data)))
	binary.NativeEndian.PutUint16(b[2:4], typ)
	copy(b[4:], data)
	return b
}

// nfqMessage はキュー queue への nfnetlink のメッセージを作る。
func nfqMessage(msg uint16, flags uint16, seq uint32, queue uint16, attrs ...[]byte) []byte {
	b := make([]byte, nlmsgHdrLen+nfgenmsgLen)
	binary.NativeEndian.PutUint16(b[4:6], nfnlSubsysQueue<<8|msg)
	binary.NativeEndian.PutUint16(b[6:8], flags)
	binary.NativeEndian.PutUint32(b[8:12], seq)
	binary.BigEndian.PutUint16(b[nlmsgHdrLen+2:], queue) // nfgenmsg の res_id
	for _, a := range attrs {
		b = append(b, a...)
	}
	binary.NativeEndian.PutUint32(b[0:4], uint32(len(b)))
	return b
}

// nfqBindMessages は、キューに結び付き、パケットの先頭を受け取る設定のメッセージを返す（それぞれ応答を求める）。
func nfqBindMessages(queue uint16) [][]byte {
	cmd := []byte{nfqnlCfgCmdBind, 0, 0, 0} // command、pad、pf（今のカーネルでは使わない）
	params := binary.BigEndian.AppendUint32(nil, nfqCopyRange)
	params = append(params, nfqnlCopyPacket)
	flags := uint32(nfqaCfgFFailOpen | nfqaCfgFUIDGID)
	f := nlmFRequestFlag | nlmFAckFlag
	return [][]byte{
		nfqMessage(nfqnlMsgConfig, uint16(f), 1, queue, nlAttribute(nfqaCfgCmd, cmd)),
		nfqMessage(nfqnlMsgConfig, uint16(f), 2, queue, nlAttribute(nfqaCfgParams, params)),
		nfqMessage(nfqnlMsgConfig, uint16(f), 3, queue, nlAttribute(nfqaCfgQueueLen, binary.BigEndian.AppendUint32(nil, nfqMaxLen))),
		nfqMessage(nfqnlMsgConfig, uint16(f), 4, queue,
			nlAttribute(nfqaCfgMask, binary.BigEndian.AppendUint32(nil, flags)), nlAttribute(nfqaCfgFlags, binary.BigEndian.AppendUint32(nil, flags))),
	}
}

// nfqVerdictMessage は判断のメッセージを作る。mark が 0 でなければ、パケットに印を付ける。
func nfqVerdictMessage(queue uint16, id, verdict, mark uint32) []byte {
	hdr := binary.BigEndian.AppendUint32(nil, verdict)
	hdr = binary.BigEndian.AppendUint32(hdr, id)
	attrs := [][]byte{nlAttribute(nfqaVerdictHdr, hdr)}
	if mark != 0 {
		attrs = append(attrs, nlAttribute(nfqaMark, binary.BigEndian.AppendUint32(nil, mark)))
	}
	return nfqMessage(nfqnlMsgVerdict, nlmFRequestFlag, 0, queue, attrs...)
}

// nlMessage は netlink のメッセージ。data はヘッダーの後ろ。
type nlMessage struct {
	typ  uint16
	seq  uint32
	data []byte
}

// nlMessages は netlink のメッセージの列を分ける。
func nlMessages(b []byte) ([]nlMessage, error) {
	var out []nlMessage
	for len(b) >= nlmsgHdrLen {
		l := int(binary.NativeEndian.Uint32(b[0:4]))
		if l < nlmsgHdrLen || l > len(b) {
			return out, fmt.Errorf("nfqueue: メッセージの長さ %d が不正です", l)
		}
		out = append(out, nlMessage{typ: binary.NativeEndian.Uint16(b[4:6]), seq: binary.NativeEndian.Uint32(b[8:12]), data: b[nlmsgHdrLen:l]})
		b = b[min((l+3)&^3, len(b)):]
	}
	return out, nil
}

// nlAttributes は属性を種類ごとに分ける（入れ子の印などの上位のビットは除く）。
func nlAttributes(b []byte) (map[uint16][]byte, error) {
	attrs := map[uint16][]byte{}
	for len(b) >= 4 {
		l := int(binary.NativeEndian.Uint16(b[0:2]))
		if l < 4 || l > len(b) {
			return attrs, fmt.Errorf("nfqueue: 属性の長さ %d が不正です", l)
		}
		attrs[binary.NativeEndian.Uint16(b[2:4])&0x3fff] = b[4:l]
		b = b[min((l+3)&^3, len(b)):]
	}
	return attrs, nil
}

// parseNFQPacket は、キューのパケットのメッセージの本文（nfgenmsg から）を読む。
func parseNFQPacket(data []byte) (nfqPacket, error) {
	if len(data) < nfgenmsgLen {
		return nfqPacket{}, errors.New("nfqueue: メッセージが短すぎます")
	}
	a, err := nlAttributes(data[nfgenmsgLen:])
	if err != nil {
		return nfqPacket{}, err
	}
	hdr, ok := a[nfqaPacketHdr]
	if !ok || len(hdr) < 4 {
		return nfqPacket{}, errors.New("nfqueue: パケットの見出しがありません")
	}
	// 受け取りの領域は次のパケットで使い回すので、中身は写しておく（判断は別のゴルーチンで行うため）。
	p := nfqPacket{id: binary.BigEndian.Uint32(hdr[0:4]), payload: bytes.Clone(a[nfqaPayload])}
	if u, ok := a[nfqaUID]; ok && len(u) >= 4 {
		p.uid, p.hasUID = binary.BigEndian.Uint32(u[0:4]), true
	}
	return p, nil
}

// flowKey はパケットの宛先と送り元（端末の側）。
type flowKey struct {
	proto    string // tcp か udp
	src, dst netip.AddrPort
}

// parseIPPacket は IPv4 か IPv6 のパケットの先頭から、TCP か UDP の送り元と宛先を読む。IPv6 の拡張ヘッダーと、
// IPv4 の 2 番目以降の断片は読まない（false を返す）。
func parseIPPacket(b []byte) (flowKey, bool) {
	if len(b) < 1 {
		return flowKey{}, false
	}
	var proto byte
	var src, dst netip.Addr
	var l4 []byte
	switch b[0] >> 4 {
	case 4:
		ihl := int(b[0]&0x0f) * 4
		if len(b) < 20 || ihl < 20 || len(b) < ihl+4 || binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			return flowKey{}, false
		}
		proto, src, dst, l4 = b[9], netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20])), b[ihl:]
	case 6:
		if len(b) < 44 {
			return flowKey{}, false
		}
		proto, src, dst, l4 = b[6], netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40])), b[40:]
	default:
		return flowKey{}, false
	}
	k := flowKey{
		src: netip.AddrPortFrom(src.Unmap(), binary.BigEndian.Uint16(l4[0:2])),
		dst: netip.AddrPortFrom(dst.Unmap(), binary.BigEndian.Uint16(l4[2:4])),
	}
	switch proto {
	case syscall.IPPROTO_TCP:
		k.proto = "tcp"
	case syscall.IPPROTO_UDP:
		k.proto = "udp"
	default:
		return flowKey{}, false
	}
	return k, true
}

// nfqueue はキューに結び付いた netlink のソケット。
type nfqueue struct {
	f     *os.File
	queue uint16
	seq   atomic.Uint32
}

// openNFQueue はキュー queue に結び付く。
func openNFQueue(queue uint16) (*nfqueue, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, syscall.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("nfqueue: %w", err)
	}
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<20)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("nfqueue: %w", err)
	}
	q := &nfqueue{f: os.NewFile(uintptr(fd), "nfqueue"), queue: queue}
	buf := make([]byte, 8192)
	for _, msg := range nfqBindMessages(queue) {
		if _, err := q.f.Write(msg); err != nil {
			q.f.Close()
			return nil, fmt.Errorf("nfqueue: 設定を送れません: %w", err)
		}
		if err := q.waitAck(buf, binary.NativeEndian.Uint32(msg[8:12])); err != nil {
			q.f.Close()
			return nil, err
		}
	}
	return q, nil
}

// waitAck は seq の応答を待つ。
func (q *nfqueue) waitAck(buf []byte, seq uint32) error {
	q.f.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer q.f.SetReadDeadline(time.Time{})
	for {
		n, err := q.f.Read(buf)
		if err != nil {
			return fmt.Errorf("nfqueue: 設定の応答がありません: %w", err)
		}
		msgs, err := nlMessages(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if m.typ == nlmsgErrorType && m.seq == seq && len(m.data) >= 4 {
				if code := int32(binary.NativeEndian.Uint32(m.data[0:4])); code != 0 {
					return fmt.Errorf("nfqueue: キュー %d を設定できません: %w", q.queue, syscall.Errno(-code))
				}
				return nil
			}
		}
	}
}

// read はパケットを受け取る。受け取りの待ち行列があふれたとき（ENOBUFS）は、取りこぼしたことを overflow で返す。
func (q *nfqueue) read(buf []byte) (pkts []nfqPacket, overflow bool, err error) {
	n, err := q.f.Read(buf)
	if errors.Is(err, syscall.ENOBUFS) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	msgs, err := nlMessages(buf[:n])
	for _, m := range msgs {
		if m.typ != nfnlSubsysQueue<<8|nfqnlMsgPacket {
			continue
		}
		if p, perr := parseNFQPacket(m.data); perr == nil {
			pkts = append(pkts, p)
		}
	}
	return pkts, false, err
}

// verdict は判断を送る。
func (q *nfqueue) verdict(id, verdict, mark uint32) error {
	_, err := q.f.Write(nfqVerdictMessage(q.queue, id, verdict, mark))
	return err
}

func (q *nfqueue) close() error { return q.f.Close() }
