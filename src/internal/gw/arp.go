package gw

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"slices"
)

// ARP の操作。
const (
	ARPRequest = 1
	ARPReply   = 2
)

const arpLen = 28 // Ethernet と IPv4 の ARP の長さ

// ARP は Ethernet と IPv4 の ARP のメッセージ。
type ARP struct {
	Op        uint16
	SenderMAC net.HardwareAddr
	SenderIP  netip.Addr
	TargetMAC net.HardwareAddr
	TargetIP  netip.Addr
}

// ParseARP は ARP のメッセージ（Ethernet のヘッダーを除く）を解析する。
func ParseARP(b []byte) (ARP, error) {
	if len(b) < arpLen {
		return ARP{}, fmt.Errorf("arp: メッセージが短すぎます（%d バイト）", len(b))
	}
	htype, ptype := binary.BigEndian.Uint16(b[0:2]), binary.BigEndian.Uint16(b[2:4])
	if htype != 1 || ptype != 0x0800 || b[4] != 6 || b[5] != 4 {
		return ARP{}, fmt.Errorf("arp: Ethernet と IPv4 の ARP ではありません")
	}
	return ARP{
		Op:        binary.BigEndian.Uint16(b[6:8]),
		SenderMAC: slices.Clone(net.HardwareAddr(b[8:14])),
		SenderIP:  netip.AddrFrom4([4]byte(b[14:18])),
		TargetMAC: slices.Clone(net.HardwareAddr(b[18:24])),
		TargetIP:  netip.AddrFrom4([4]byte(b[24:28])),
	}, nil
}

// Marshal は ARP のメッセージを送信する形にする。
func (a ARP) Marshal() []byte {
	b := make([]byte, arpLen)
	binary.BigEndian.PutUint16(b[0:2], 1)
	binary.BigEndian.PutUint16(b[2:4], 0x0800)
	b[4], b[5] = 6, 4
	binary.BigEndian.PutUint16(b[6:8], a.Op)
	copy(b[8:14], a.SenderMAC)
	if a.SenderIP.Is4() {
		copy(b[14:18], a.SenderIP.AsSlice())
	}
	copy(b[18:24], a.TargetMAC)
	if a.TargetIP.Is4() {
		copy(b[24:28], a.TargetIP.AsSlice())
	}
	return b
}
