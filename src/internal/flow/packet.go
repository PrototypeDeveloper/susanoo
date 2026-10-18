package flow

import (
	"encoding/binary"
	"net/netip"
)

// segment は TCP のセグメント。
type segment struct {
	src, dst netip.AddrPort
	seq      uint32
	syn      bool
	payload  []byte
}

// parseTCP は IP のパケット（IPv4 か IPv6）から TCP のセグメントを取り出す。
// TCP でないもの、断片化したもの、IPv6 の拡張ヘッダーがあるものは扱わない。
// NFLOG は先頭の一部だけを渡すことがある（GSO でまとめた大きなパケットなど）ので、
// ヘッダーの示す長さより短ければ、受け取った分だけを使う。
// parseIP は IP のパケットの送信元と宛先（TCP と UDP ならポートも）と、プロトコルの番号を返す。
func parseIP(b []byte) (src, dst netip.AddrPort, proto uint8, ok bool) {
	if len(b) < 1 {
		return
	}
	var sa, da netip.Addr
	var l4 []byte
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return
		}
		ihl := int(b[0]&0x0f) * 4
		total := min(int(binary.BigEndian.Uint16(b[2:4])), len(b))
		if ihl < 20 || total < ihl {
			return
		}
		sa, da, proto = netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20])), b[9]
		if binary.BigEndian.Uint16(b[6:8])&0x1fff == 0 { // 最初の断片だけポートを読む
			l4 = b[ihl:total]
		}
	case 6:
		if len(b) < 40 {
			return
		}
		sa, da, proto = netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40])), b[6]
		l4 = b[40:]
	default:
		return
	}
	var sp, dp uint16
	if (proto == 6 || proto == 17) && len(l4) >= 4 {
		sp, dp = binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
	}
	return netip.AddrPortFrom(sa, sp), netip.AddrPortFrom(da, dp), proto, true
}

func parseTCP(b []byte) (segment, bool) {
	if len(b) < 1 {
		return segment{}, false
	}
	var src, dst netip.Addr
	var tcp []byte
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return segment{}, false
		}
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:4]))
		frag := binary.BigEndian.Uint16(b[6:8])
		total = min(total, len(b))
		if ihl < 20 || total < ihl || b[9] != 6 || frag&0x3fff != 0 {
			return segment{}, false
		}
		src, dst = netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20]))
		tcp = b[ihl:total]
	case 6:
		if len(b) < 40 || b[6] != 6 {
			return segment{}, false
		}
		plen := min(int(binary.BigEndian.Uint16(b[4:6])), len(b)-40)
		src, dst = netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40]))
		tcp = b[40 : 40+plen]
	default:
		return segment{}, false
	}
	if len(tcp) < 20 {
		return segment{}, false
	}
	off := int(tcp[12]>>4) * 4
	if off < 20 || off > len(tcp) {
		return segment{}, false
	}
	return segment{
		src:     netip.AddrPortFrom(src, binary.BigEndian.Uint16(tcp[0:2])),
		dst:     netip.AddrPortFrom(dst, binary.BigEndian.Uint16(tcp[2:4])),
		seq:     binary.BigEndian.Uint32(tcp[4:8]),
		syn:     tcp[13]&0x02 != 0,
		payload: tcp[off:],
	}, true
}
