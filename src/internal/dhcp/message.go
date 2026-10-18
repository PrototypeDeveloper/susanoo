package dhcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
)

// MessageType は DHCP のメッセージの種類（オプション 53）。
type MessageType byte

const (
	Discover MessageType = 1
	Offer    MessageType = 2
	Request  MessageType = 3
	Decline  MessageType = 4
	Ack      MessageType = 5
	Nak      MessageType = 6
	Release  MessageType = 7
	Inform   MessageType = 8
)

func (t MessageType) String() string {
	names := map[MessageType]string{
		Discover: "DISCOVER", Offer: "OFFER", Request: "REQUEST", Decline: "DECLINE",
		Ack: "ACK", Nak: "NAK", Release: "RELEASE", Inform: "INFORM",
	}
	if n, ok := names[t]; ok {
		return n
	}
	return fmt.Sprintf("種類 %d", byte(t))
}

// オプションの番号（RFC 2132）。
const (
	OptPad         = 0
	OptSubnetMask  = 1
	OptRouter      = 3
	OptDNS         = 6
	OptHostname    = 12
	OptRequestedIP = 50
	OptLeaseTime   = 51
	OptMessageType = 53
	OptServerID    = 54
	OptParamList   = 55
	OptRenewalTime = 58
	OptRebindTime  = 59
	OptClientID    = 61
	OptEnd         = 255
)

const (
	opRequest     = 1
	opReply       = 2
	htypeEthernet = 1
	fixedLen      = 236 // オプションの前までの長さ
	minReplyLen   = 300 // BOOTP の最小の長さ。古い機器のために、応答はこの長さまで埋める
)

var magicCookie = [4]byte{99, 130, 83, 99}

// Message は DHCP のメッセージ。
type Message struct {
	Op      byte
	HType   byte
	HLen    byte
	Hops    byte
	XID     uint32
	Secs    uint16
	Flags   uint16
	CIAddr  netip.Addr
	YIAddr  netip.Addr
	SIAddr  netip.Addr
	GIAddr  netip.Addr
	CHAddr  net.HardwareAddr
	Options map[byte][]byte
}

// BroadcastFlag は、クライアントが応答のブロードキャストを求めていることを表す。
const BroadcastFlag = 0x8000

// Parse は受信したメッセージを解析する。
func Parse(b []byte) (*Message, error) {
	if len(b) < fixedLen+len(magicCookie) {
		return nil, fmt.Errorf("dhcp: メッセージが短すぎます（%d バイト）", len(b))
	}
	if [4]byte(b[fixedLen:fixedLen+4]) != magicCookie {
		return nil, errors.New("dhcp: マジッククッキーが違います")
	}
	m := &Message{
		Op:      b[0],
		HType:   b[1],
		HLen:    b[2],
		Hops:    b[3],
		XID:     binary.BigEndian.Uint32(b[4:8]),
		Secs:    binary.BigEndian.Uint16(b[8:10]),
		Flags:   binary.BigEndian.Uint16(b[10:12]),
		CIAddr:  netip.AddrFrom4([4]byte(b[12:16])),
		YIAddr:  netip.AddrFrom4([4]byte(b[16:20])),
		SIAddr:  netip.AddrFrom4([4]byte(b[20:24])),
		GIAddr:  netip.AddrFrom4([4]byte(b[24:28])),
		Options: map[byte][]byte{},
	}
	if m.HLen > 16 {
		return nil, fmt.Errorf("dhcp: ハードウェアアドレスの長さ %d が不正です", m.HLen)
	}
	m.CHAddr = slices.Clone(net.HardwareAddr(b[28 : 28+int(m.HLen)]))

	opts := b[fixedLen+4:]
	for len(opts) > 0 {
		code := opts[0]
		if code == OptPad {
			opts = opts[1:]
			continue
		}
		if code == OptEnd {
			return m, nil
		}
		if len(opts) < 2 || len(opts) < 2+int(opts[1]) {
			return nil, fmt.Errorf("dhcp: オプション %d が途中で切れています", code)
		}
		n := int(opts[1])
		// 同じオプションが複数あれば、つなげて 1 つにする（RFC 3396）。
		m.Options[code] = append(m.Options[code], opts[2:2+n]...)
		opts = opts[2+n:]
	}
	return nil, errors.New("dhcp: オプションの終わりがありません")
}

// Marshal はメッセージを送信する形にする。
func (m *Message) Marshal() []byte {
	b := make([]byte, fixedLen, minReplyLen)
	b[0], b[1], b[2], b[3] = m.Op, m.HType, m.HLen, m.Hops
	binary.BigEndian.PutUint32(b[4:8], m.XID)
	binary.BigEndian.PutUint16(b[8:10], m.Secs)
	binary.BigEndian.PutUint16(b[10:12], m.Flags)
	for i, a := range []netip.Addr{m.CIAddr, m.YIAddr, m.SIAddr, m.GIAddr} {
		if a.Is4() {
			copy(b[12+4*i:16+4*i], a.AsSlice())
		}
	}
	copy(b[28:44], m.CHAddr)
	b = append(b, magicCookie[:]...)

	// メッセージの種類を先頭に置き、残りは番号の順に並べる。
	codes := make([]byte, 0, len(m.Options))
	for code := range m.Options {
		if code != OptMessageType && code != OptPad && code != OptEnd {
			codes = append(codes, code)
		}
	}
	slices.Sort(codes)
	if _, ok := m.Options[OptMessageType]; ok {
		codes = append([]byte{OptMessageType}, codes...)
	}
	for _, code := range codes {
		v := m.Options[code]
		for len(v) > 255 {
			b = append(b, code, 255)
			b = append(b, v[:255]...)
			v = v[255:]
		}
		b = append(b, code, byte(len(v)))
		b = append(b, v...)
	}
	b = append(b, OptEnd)
	for len(b) < minReplyLen {
		b = append(b, OptPad)
	}
	return b
}

// Type はメッセージの種類を返す。なければ 0。
func (m *Message) Type() MessageType {
	if v := m.Options[OptMessageType]; len(v) == 1 {
		return MessageType(v[0])
	}
	return 0
}

// AddrOption は IPv4 アドレス 1 つのオプションを返す。
func (m *Message) AddrOption(code byte) netip.Addr {
	if v := m.Options[code]; len(v) == 4 {
		return netip.AddrFrom4([4]byte(v))
	}
	return netip.Addr{}
}

// SetAddrs は IPv4 アドレスの並びのオプションを設定する。
func (m *Message) SetAddrs(code byte, addrs ...netip.Addr) {
	var v []byte
	for _, a := range addrs {
		if a.Is4() {
			v = append(v, a.AsSlice()...)
		}
	}
	if len(v) > 0 {
		m.Options[code] = v
	}
}

// SetUint32 は 32 ビットの数値のオプションを設定する。
func (m *Message) SetUint32(code byte, v uint32) {
	m.Options[code] = binary.BigEndian.AppendUint32(nil, v)
}
