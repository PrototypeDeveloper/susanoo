package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// レコードの種類。
const (
	TypeA     = 1
	TypeCNAME = 5
	TypeAAAA  = 28
	TypeOPT   = 41
	TypeSVCB  = 64
	TypeHTTPS = 65
)

// 応答コード。
const (
	RcodeSuccess  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeNotImp   = 4
	RcodeRefused  = 5
)

const (
	headerLen   = 12
	maxNameLen  = 255
	maxPointers = 64 // 名前の圧縮をたどる回数の上限（循環を防ぐ）

	flagQR = 0x8000
	flagTC = 0x0200
	flagRD = 0x0100
	flagRA = 0x0080
)

// Question は問い合わせ。
type Question struct {
	Name  string // 小文字、末尾の「.」なし。英小文字、数字、「-」「_」以外は \DDD でエスケープする
	Type  uint16
	Class uint16
}

// Answer は応答のうち、A、AAAA、CNAME のレコード。
type Answer struct {
	Name   string
	Type   uint16
	TTL    uint32
	IP     netip.Addr // A と AAAA
	Target string     // CNAME
}

// Message は DNS のメッセージのうち、使う項目。
type Message struct {
	ID       uint16
	Flags    uint16
	Question Question
	Answers  []Answer
	UDPSize  int // 問い合わせの EDNS（OPT）で示された UDP の大きさ。なければ 0

	questionEnd int // 問い合わせの部分の終わりの位置
}

// Response は応答のメッセージかどうかを返す。
func (m *Message) Response() bool { return m.Flags&flagQR != 0 }

// Truncated は切り詰められた応答かどうかを返す。
func (m *Message) Truncated() bool { return m.Flags&flagTC != 0 }

// Opcode は操作の種類を返す（0 が通常の問い合わせ）。
func (m *Message) Opcode() int { return int(m.Flags>>11) & 0xf }

// Rcode は応答コードを返す。
func (m *Message) Rcode() int { return int(m.Flags & 0xf) }

// Parse はメッセージを解析する。問い合わせはちょうど 1 つでなければならない。
func Parse(b []byte) (*Message, error) {
	if len(b) < headerLen {
		return nil, fmt.Errorf("dns: メッセージが短すぎます（%d バイト）", len(b))
	}
	m := &Message{ID: binary.BigEndian.Uint16(b[0:2]), Flags: binary.BigEndian.Uint16(b[2:4])}
	qd := binary.BigEndian.Uint16(b[4:6])
	counts := [3]int{int(binary.BigEndian.Uint16(b[6:8])), int(binary.BigEndian.Uint16(b[8:10])), int(binary.BigEndian.Uint16(b[10:12]))}
	if qd != 1 {
		return nil, fmt.Errorf("dns: 問い合わせの数が %d です（1 が必要）", qd)
	}
	name, off, err := readName(b, headerLen)
	if err != nil {
		return nil, err
	}
	if off+4 > len(b) {
		return nil, errors.New("dns: 問い合わせが途中で切れています")
	}
	m.Question = Question{Name: name, Type: binary.BigEndian.Uint16(b[off:]), Class: binary.BigEndian.Uint16(b[off+2:])}
	off += 4
	m.questionEnd = off

	for section, n := range counts {
		for range n {
			owner, next, err := readName(b, off)
			if err != nil {
				return nil, err
			}
			if next+10 > len(b) {
				return nil, errors.New("dns: レコードが途中で切れています")
			}
			typ := binary.BigEndian.Uint16(b[next:])
			class := binary.BigEndian.Uint16(b[next+2:])
			ttl := binary.BigEndian.Uint32(b[next+4:])
			rdlen := int(binary.BigEndian.Uint16(b[next+8:]))
			start := next + 10
			if start+rdlen > len(b) {
				return nil, errors.New("dns: レコードのデータが途中で切れています")
			}
			rdata := b[start : start+rdlen]
			switch {
			case section == 0 && typ == TypeA && rdlen == 4:
				m.Answers = append(m.Answers, Answer{Name: owner, Type: typ, TTL: ttl, IP: netip.AddrFrom4([4]byte(rdata))})
			case section == 0 && typ == TypeAAAA && rdlen == 16:
				m.Answers = append(m.Answers, Answer{Name: owner, Type: typ, TTL: ttl, IP: netip.AddrFrom16([16]byte(rdata))})
			case section == 0 && typ == TypeCNAME:
				target, _, err := readName(b, start)
				if err != nil {
					return nil, err
				}
				m.Answers = append(m.Answers, Answer{Name: owner, Type: typ, TTL: ttl, Target: target})
			case section == 2 && typ == TypeOPT && owner == "":
				m.UDPSize = int(class)
			}
			off = start + rdlen
		}
	}
	return m, nil
}

// readName は off から始まる名前を読み、名前と、名前の後ろの位置を返す。
func readName(b []byte, off int) (string, int, error) {
	var sb strings.Builder
	end, jumps, total := -1, 0, 0
	for {
		if off >= len(b) {
			return "", 0, errors.New("dns: 名前が途中で切れています")
		}
		l := int(b[off])
		switch l & 0xc0 {
		case 0x00:
			off++
			if l == 0 {
				if end < 0 {
					end = off
				}
				return sb.String(), end, nil
			}
			if off+l > len(b) {
				return "", 0, errors.New("dns: ラベルが途中で切れています")
			}
			if total += l + 1; total > maxNameLen {
				return "", 0, errors.New("dns: 名前が長すぎます")
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			for _, c := range b[off : off+l] {
				switch {
				case c >= 'A' && c <= 'Z':
					sb.WriteByte(c + 'a' - 'A')
				case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
					sb.WriteByte(c)
				default:
					fmt.Fprintf(&sb, "\\%03d", c)
				}
			}
			off += l
		case 0xc0:
			if off+1 >= len(b) {
				return "", 0, errors.New("dns: 名前の圧縮が途中で切れています")
			}
			if end < 0 {
				end = off + 2
			}
			if jumps++; jumps > maxPointers {
				return "", 0, errors.New("dns: 名前の圧縮が循環しています")
			}
			// 圧縮は、それより前に出てきた名前を指す（RFC 1035）。名前はヘッダーの後ろにしかない。
			ptr := int(binary.BigEndian.Uint16(b[off:]) & 0x3fff)
			if ptr < headerLen || ptr >= off {
				return "", 0, errors.New("dns: 名前の圧縮の指す位置が不正です")
			}
			off = ptr
		default:
			return "", 0, fmt.Errorf("dns: 対応していないラベルの種類です（0x%02x）", l)
		}
	}
}

// Reply は問い合わせ raw（解析済みの q）への、レコードを含まない応答を作る。
// rcode が RcodeSuccess なら「該当するレコードなし」、truncated なら TCP での問い合わせ直しを促す。
func Reply(raw []byte, q *Message, rcode int, truncated bool) []byte {
	out := make([]byte, headerLen, q.questionEnd)
	binary.BigEndian.PutUint16(out[0:], q.ID)
	flags := flagQR | flagRA | (q.Flags & (0x7800 | flagRD)) | uint16(rcode&0xf)
	if truncated {
		flags |= flagTC
	}
	binary.BigEndian.PutUint16(out[2:], flags)
	binary.BigEndian.PutUint16(out[4:], 1)
	return append(out, raw[headerLen:q.questionEnd]...)
}

// NewQuery は名前 name、種類 qtype の問い合わせを作る（上流の確認と試験に使う）。
func NewQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	b := make([]byte, headerLen, headerLen+len(name)+6)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], flagRD)
	binary.BigEndian.PutUint16(b[4:], 1)
	b, err := appendName(b, name)
	if err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, qtype)
	return binary.BigEndian.AppendUint16(b, 1), nil
}

func appendName(b []byte, name string) ([]byte, error) {
	if name != "" {
		for label := range strings.SplitSeq(name, ".") {
			if len(label) == 0 || len(label) > 63 {
				return nil, fmt.Errorf("dns: 名前 %q のラベルが不正です", name)
			}
			b = append(b, byte(len(label)))
			b = append(b, label...)
		}
	}
	return append(b, 0), nil
}

func setID(b []byte, id uint16) { binary.BigEndian.PutUint16(b[0:2], id) }
