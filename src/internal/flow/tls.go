package flow

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
)

const (
	recordHeaderLen = 5
	maxRecordLen    = 16384 + 2048 // TLS のレコードの上限（余裕を含む）
)

// ClientHello は TLS の ClientHello から取り出した情報。
type ClientHello struct {
	SNI     string
	ALPN    []string
	Version uint16 // 対応する最も新しい版（supported_versions があればその中から）
	JA4     string
}

// tlsRecordLen は、b が TLS のハンドシェイクのレコードで始まるなら、レコード全体の長さを返す。
// 先頭 5 バイトがそろっていなければ 0 を、TLS のハンドシェイクでなければ -1 を返す。
func tlsRecordLen(b []byte) int {
	if len(b) < recordHeaderLen {
		return 0
	}
	if b[0] != 0x16 || b[1] != 0x03 {
		return -1
	}
	n := int(binary.BigEndian.Uint16(b[3:5]))
	if n == 0 || n > maxRecordLen {
		return -1
	}
	return recordHeaderLen + n
}

// reader は境界を確かめながら読む。
type reader struct {
	b   []byte
	err bool
}

func (r *reader) bytes(n int) []byte {
	if r.err || n < 0 || n > len(r.b) {
		r.err = true
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u8() int {
	b := r.bytes(1)
	if b == nil {
		return 0
	}
	return int(b[0])
}

func (r *reader) u16() int {
	b := r.bytes(2)
	if b == nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(b))
}

func (r *reader) u24() int {
	b := r.bytes(3)
	if b == nil {
		return 0
	}
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
}

// parseClientHello は TLS のレコード（ヘッダーを含む）から ClientHello を読む。
func parseClientHello(rec []byte) (ClientHello, error) {
	n := tlsRecordLen(rec)
	if n <= 0 || n > len(rec) {
		return ClientHello{}, errors.New("flow: TLS のハンドシェイクのレコードではありません")
	}
	r := &reader{b: rec[recordHeaderLen:n]}
	if r.u8() != 1 {
		return ClientHello{}, errors.New("flow: ClientHello ではありません")
	}
	body := &reader{b: r.bytes(r.u24())}
	if r.err {
		return ClientHello{}, errors.New("flow: ClientHello が 1 つのレコードに収まっていません")
	}
	legacy := uint16(body.u16())
	body.bytes(32)                   // random
	body.bytes(body.u8())            // session_id
	suites := body.bytes(body.u16()) // cipher_suites
	body.bytes(body.u8())            // compression_methods
	if body.err || len(suites)%2 != 0 {
		return ClientHello{}, errors.New("flow: ClientHello が壊れています")
	}
	var ciphers []uint16
	for i := 0; i < len(suites); i += 2 {
		if v := binary.BigEndian.Uint16(suites[i:]); !grease(v) {
			ciphers = append(ciphers, v)
		}
	}

	ch := ClientHello{Version: legacy}
	var exts, sigs []uint16
	if len(body.b) > 0 {
		extr := &reader{b: body.bytes(body.u16())}
		for len(extr.b) > 0 && !extr.err {
			typ := uint16(extr.u16())
			data := &reader{b: extr.bytes(extr.u16())}
			if extr.err {
				break
			}
			if grease(typ) {
				continue
			}
			exts = append(exts, typ)
			switch typ {
			case 0: // server_name
				list := &reader{b: data.bytes(data.u16())}
				for len(list.b) > 0 && !list.err {
					kind := list.u8()
					name := list.bytes(list.u16())
					if kind == 0 && !list.err && ch.SNI == "" {
						ch.SNI = sanitizeHost(string(name))
					}
				}
			case 16: // application_layer_protocol_negotiation
				list := &reader{b: data.bytes(data.u16())}
				for len(list.b) > 0 && !list.err {
					if p := list.bytes(list.u8()); !list.err && len(p) > 0 {
						ch.ALPN = append(ch.ALPN, string(p))
					}
				}
			case 43: // supported_versions
				vs := data.bytes(data.u8())
				for i := 0; i+1 < len(vs); i += 2 {
					if v := binary.BigEndian.Uint16(vs[i:]); !grease(v) && v > ch.Version {
						ch.Version = v
					}
				}
			case 13: // signature_algorithms
				list := data.bytes(data.u16())
				for i := 0; i+1 < len(list); i += 2 {
					if v := binary.BigEndian.Uint16(list[i:]); !grease(v) {
						sigs = append(sigs, v)
					}
				}
			}
		}
		if extr.err {
			return ClientHello{}, errors.New("flow: ClientHello の拡張が壊れています")
		}
	}
	ch.JA4 = ja4(ch, ciphers, exts, sigs)
	return ch, nil
}

// grease は GREASE（RFC 8701）の値かどうかを返す。拡張性を保つために混ぜられる意味のない値。
func grease(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

// ja4 は JA4（TLS クライアントの指紋）を計算する。形は a_b_c。
//
//	a: t（TCP）、版、SNI の有無（d/i）、暗号の数、拡張の数、最初の ALPN の最初と最後の文字
//	b: 暗号の一覧を並べ替えたものの SHA-256 の先頭 12 文字
//	c: 拡張の一覧（SNI と ALPN を除く）を並べ替えたものと、署名の方式の一覧の SHA-256 の先頭 12 文字
//
// GREASE の値は数にも一覧にも含めない。
func ja4(ch ClientHello, ciphers, exts, sigs []uint16) string {
	version := map[uint16]string{0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}[ch.Version]
	if version == "" {
		version = "00"
	}
	sni := "i"
	if slices.Contains(exts, 0) {
		sni = "d"
	}
	alpn := "00"
	if len(ch.ALPN) > 0 {
		p := ch.ALPN[0]
		first, last := p[0], p[len(p)-1]
		if alnum(first) && alnum(last) {
			alpn = string([]byte{first, last})
		} else {
			h := hex.EncodeToString([]byte(p))
			alpn = string([]byte{h[0], h[len(h)-1]})
		}
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", version, sni, min(len(ciphers), 99), min(len(exts), 99), alpn)

	b := hash12(hexList(slices.Sorted(slices.Values(ciphers))))
	var rest []uint16
	for _, e := range exts {
		if e != 0 && e != 16 {
			rest = append(rest, e)
		}
	}
	c := "000000000000"
	if len(rest) > 0 {
		s := hexList(slices.Sorted(slices.Values(rest)))
		if len(sigs) > 0 {
			s += "_" + hexList(sigs)
		}
		c = hash12(s)
	}
	if len(ciphers) == 0 {
		b = "000000000000"
	}
	return a + "_" + b + "_" + c
}

func alnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func hexList(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func hash12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// sanitizeHost はホスト名を小文字にし、ホスト名に使わない文字を「?」に置き換える。
func sanitizeHost(s string) string {
	if len(s) > 253 {
		s = s[:253]
	}
	b := []byte(strings.ToLower(s))
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			b[i] = '?'
		}
	}
	return string(b)
}

// tlsVersionName は TLS の版の表示名を返す。
func tlsVersionName(v uint16) string {
	switch v {
	case 0x0304:
		return "TLS 1.3"
	case 0x0303:
		return "TLS 1.2"
	case 0x0302:
		return "TLS 1.1"
	case 0x0301:
		return "TLS 1.0"
	}
	return fmt.Sprintf("0x%04x", v)
}
