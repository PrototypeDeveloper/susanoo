package flow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// netfilter の netlink（nfnetlink）の定数（linux/netfilter/nfnetlink*.h）。
const (
	nlmsgHdrLen  = 16
	nfgenmsgLen  = 4
	nlaTypeMask  = 0x3fff // NLA_F_NESTED と NLA_F_NET_BYTEORDER を除く
	nlmsgError   = 2
	nlmFRequest  = 0x1
	nlmFAck      = 0x4
	msgCTDelete  = 1<<8 | 2 // NFNL_SUBSYS_CTNETLINK、IPCTNL_MSG_CT_DELETE
	msgULogPkt   = 4<<8 | 0 // NFNL_SUBSYS_ULOG、NFULNL_MSG_PACKET
	msgULogCfg   = 4<<8 | 1 // NFNL_SUBSYS_ULOG、NFULNL_MSG_CONFIG
	groupCTDestr = 3        // NFNLGRP_CONNTRACK_DESTROY

	ctaTupleOrig     = 1
	ctaTupleReply    = 2
	ctaCountersOrig  = 9
	ctaCountersReply = 10
	ctaTimestamp     = 20
	ctaTupleIP       = 1
	ctaTupleProto    = 2
	ctaIPv4Src       = 1
	ctaIPv4Dst       = 2
	ctaIPv6Src       = 3
	ctaIPv6Dst       = 4
	ctaProtoNum      = 1
	ctaProtoSrcPort  = 2
	ctaProtoDstPort  = 3
	ctaCountPackets  = 1
	ctaCountBytes    = 2
	ctaTSStart       = 1
	ctaTSStop        = 2

	nfulaPayload    = 9
	nfulaCfgCmd     = 1
	nfulaCfgMode    = 2
	nfulaCfgQThresh = 5
	nfulnlCmdBind   = 1
	nfulnlCopyPkt   = 2
)

// nlMsg は netlink のメッセージ。data はヘッダーの後ろ。
type nlMsg struct {
	typ, flags uint16
	seq        uint32
	data       []byte
}

func align4(n int) int { return (n + 3) &^ 3 }

// parseMessages は受信したバイト列を netlink のメッセージに分ける。
func parseMessages(b []byte) ([]nlMsg, error) {
	var msgs []nlMsg
	for len(b) >= nlmsgHdrLen {
		l := int(binary.NativeEndian.Uint32(b[0:4]))
		if l < nlmsgHdrLen || l > len(b) {
			return msgs, fmt.Errorf("flow: netlink のメッセージの長さ %d が不正です", l)
		}
		msgs = append(msgs, nlMsg{
			typ:   binary.NativeEndian.Uint16(b[4:6]),
			flags: binary.NativeEndian.Uint16(b[6:8]),
			seq:   binary.NativeEndian.Uint32(b[8:12]),
			data:  b[nlmsgHdrLen:l],
		})
		b = b[min(align4(l), len(b)):]
	}
	return msgs, nil
}

// parseAttrs は netlink の属性を、種類ごとに分ける。
func parseAttrs(b []byte) (map[uint16][]byte, error) {
	attrs := map[uint16][]byte{}
	for len(b) >= 4 {
		l := int(binary.NativeEndian.Uint16(b[0:2]))
		if l < 4 || l > len(b) {
			return attrs, fmt.Errorf("flow: netlink の属性の長さ %d が不正です", l)
		}
		attrs[binary.NativeEndian.Uint16(b[2:4])&nlaTypeMask] = b[4:l]
		b = b[min(align4(l), len(b)):]
	}
	return attrs, nil
}

// conntrack は conntrack の 1 件の接続。
type conntrack struct {
	proto       uint8
	orig, reply tuple
	pktsOrig    uint64
	bytesOrig   uint64
	pktsReply   uint64
	bytesReply  uint64
	start, stop time.Time
}

type tuple struct{ src, dst netip.AddrPort }

// parseConntrack は conntrack のイベント（nfgenmsg から）を読む。
func parseConntrack(data []byte) (conntrack, error) {
	if len(data) < nfgenmsgLen {
		return conntrack{}, errors.New("flow: conntrack のメッセージが短すぎます")
	}
	a, err := parseAttrs(data[nfgenmsgLen:])
	if err != nil {
		return conntrack{}, err
	}
	var ct conntrack
	var proto uint8
	if ct.orig, proto, err = parseTuple(a[ctaTupleOrig]); err != nil {
		return conntrack{}, err
	}
	ct.proto = proto
	ct.reply, _, _ = parseTuple(a[ctaTupleReply])
	ct.pktsOrig, ct.bytesOrig = parseCounters(a[ctaCountersOrig])
	ct.pktsReply, ct.bytesReply = parseCounters(a[ctaCountersReply])
	if ts, err := parseAttrs(a[ctaTimestamp]); err == nil {
		ct.start = nsTime(ts[ctaTSStart])
		ct.stop = nsTime(ts[ctaTSStop])
	}
	return ct, nil
}

func parseTuple(b []byte) (tuple, uint8, error) {
	a, err := parseAttrs(b)
	if err != nil {
		return tuple{}, 0, err
	}
	ip, err := parseAttrs(a[ctaTupleIP])
	if err != nil {
		return tuple{}, 0, err
	}
	proto, err := parseAttrs(a[ctaTupleProto])
	if err != nil {
		return tuple{}, 0, err
	}
	var src, dst netip.Addr
	switch {
	case len(ip[ctaIPv4Src]) == 4 && len(ip[ctaIPv4Dst]) == 4:
		src, dst = netip.AddrFrom4([4]byte(ip[ctaIPv4Src])), netip.AddrFrom4([4]byte(ip[ctaIPv4Dst]))
	case len(ip[ctaIPv6Src]) == 16 && len(ip[ctaIPv6Dst]) == 16:
		src, dst = netip.AddrFrom16([16]byte(ip[ctaIPv6Src])), netip.AddrFrom16([16]byte(ip[ctaIPv6Dst]))
	default:
		return tuple{}, 0, errors.New("flow: conntrack のアドレスがありません")
	}
	var num uint8
	if p := proto[ctaProtoNum]; len(p) == 1 {
		num = p[0]
	}
	return tuple{
		src: netip.AddrPortFrom(src, be16(proto[ctaProtoSrcPort])),
		dst: netip.AddrPortFrom(dst, be16(proto[ctaProtoDstPort])),
	}, num, nil
}

func parseCounters(b []byte) (pkts, bytes uint64) {
	a, err := parseAttrs(b)
	if err != nil {
		return 0, 0
	}
	return be64(a[ctaCountPackets]), be64(a[ctaCountBytes])
}

func be16(b []byte) uint16 {
	if len(b) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func be64(b []byte) uint64 {
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

func nsTime(b []byte) time.Time {
	if ns := be64(b); ns != 0 && ns < 1<<62 {
		return time.Unix(0, int64(ns))
	}
	return time.Time{}
}

// parseNFLog は NFLOG のパケットのメッセージ（nfgenmsg から）から、NFLOG のグループと IP のパケットを取り出す。
func parseNFLog(data []byte) (uint16, []byte, error) {
	if len(data) < nfgenmsgLen {
		return 0, nil, errors.New("flow: NFLOG のメッセージが短すぎます")
	}
	a, err := parseAttrs(data[nfgenmsgLen:])
	if err != nil {
		return 0, nil, err
	}
	p, ok := a[nfulaPayload]
	if !ok {
		return 0, nil, errors.New("flow: NFLOG のメッセージにパケットがありません")
	}
	return binary.BigEndian.Uint16(data[2:4]), p, nil // nfgenmsg の res_id がグループ
}

// nlAttr は netlink の属性を作る。
func nlAttr(typ uint16, data []byte) []byte {
	b := make([]byte, align4(4+len(data)))
	binary.NativeEndian.PutUint16(b[0:2], uint16(4+len(data)))
	binary.NativeEndian.PutUint16(b[2:4], typ)
	copy(b[4:], data)
	return b
}

// nflogConfig は NFLOG のグループ group の設定のメッセージを作る（応答を求める）。
func nflogConfig(seq uint32, group uint16, attrs ...[]byte) []byte {
	var body []byte
	for _, a := range attrs {
		body = append(body, a...)
	}
	b := make([]byte, nlmsgHdrLen+nfgenmsgLen, nlmsgHdrLen+nfgenmsgLen+len(body))
	binary.NativeEndian.PutUint16(b[4:6], msgULogCfg)
	binary.NativeEndian.PutUint16(b[6:8], nlmFRequest|nlmFAck)
	binary.NativeEndian.PutUint32(b[8:12], seq)
	binary.BigEndian.PutUint16(b[nlmsgHdrLen+2:], group) // nfgenmsg の res_id
	b = append(b, body...)
	binary.NativeEndian.PutUint32(b[0:4], uint32(len(b)))
	return b
}

// nflogBindMessages は、NFLOG のグループに結び付き、パケットを copyRange バイトまで受け取る設定のメッセージを返す。
func nflogBindMessages(group uint16, copyRange uint32) [][]byte {
	mode := binary.BigEndian.AppendUint32(nil, copyRange)
	mode = append(mode, nfulnlCopyPkt, 0)
	return [][]byte{
		nflogConfig(1, group, nlAttr(nfulaCfgCmd, []byte{nfulnlCmdBind})),
		nflogConfig(2, group, nlAttr(nfulaCfgMode, mode)),
		nflogConfig(3, group, nlAttr(nfulaCfgQThresh, binary.BigEndian.AppendUint32(nil, 1))),
	}
}

// ackError は応答のメッセージ（NLMSG_ERROR）のエラーを返す。0 なら成功。
func ackError(m nlMsg) int32 {
	if m.typ != nlmsgError || len(m.data) < 4 {
		return 0
	}
	return int32(binary.NativeEndian.Uint32(m.data[0:4]))
}
