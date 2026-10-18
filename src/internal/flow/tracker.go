package flow

import (
	"net/netip"
	"time"
)

// Info は接続の始めの数パケットから取り出した情報。
type Info struct {
	SNI        string
	JA4        string
	TLSVersion string
	ALPN       string
	HTTPMethod string
	HTTPHost   string
}

const (
	maxStreams  = 10000            // 組み立て中の接続の上限
	maxInfos    = 50000            // 取り出した情報を接続の終わりまで覚えておく上限
	streamTTL   = 30 * time.Second // 組み立てを諦めるまでの時間
	infoTTL     = 2 * time.Hour    // 接続の終わりが届かない情報を捨てるまでの時間
	maxBuffered = maxRecordLen + recordHeaderLen
)

type flowKey struct{ src, dst netip.AddrPort }

type stream struct {
	next    uint32 // 次に来るはずの順序番号
	buf     []byte
	started time.Time
}

type infoEntry struct {
	info Info
	at   time.Time
}

// tracker は接続ごとに、TLS の ClientHello か HTTP の要求の先頭を組み立てる。
// 順序どおりに届いたセグメントだけをつなぐ（順序が乱れたら諦める）。単一のゴルーチンから使う。
type tracker struct {
	streams map[flowKey]*stream
	infos   map[flowKey]infoEntry
}

func newTracker() *tracker {
	return &tracker{streams: map[flowKey]*stream{}, infos: map[flowKey]infoEntry{}}
}

// add はセグメントを加え、情報を取り出せたら返す。
func (t *tracker) add(s segment, now time.Time) (Info, bool) {
	k := flowKey{s.src, s.dst}
	if _, done := t.infos[k]; done {
		return Info{}, false
	}
	if s.syn {
		delete(t.streams, k)
		return Info{}, false
	}
	if len(s.payload) == 0 {
		return Info{}, false
	}
	st := t.streams[k]
	if st == nil {
		if len(t.streams) >= maxStreams {
			return Info{}, false
		}
		st = &stream{next: s.seq, started: now}
		t.streams[k] = st
	}
	if s.seq != st.next {
		delete(t.streams, k) // 順序が乱れた
		return Info{}, false
	}
	st.buf = append(st.buf, s.payload...)
	st.next += uint32(len(s.payload))

	info, ok, more := extract(st.buf)
	if !ok {
		if !more || len(st.buf) >= maxBuffered {
			delete(t.streams, k)
		}
		return Info{}, false
	}
	delete(t.streams, k)
	if len(t.infos) < maxInfos {
		t.infos[k] = infoEntry{info, now}
	}
	return info, true
}

// extract は組み立て中のバイト列から情報を取り出す。足りなければ more が true。
func extract(b []byte) (info Info, ok, more bool) {
	if n := tlsRecordLen(b); n != 0 {
		if n < 0 {
			if m, host, isHTTP, need := parseHTTPRequest(b); isHTTP && !need {
				return Info{HTTPMethod: m, HTTPHost: host}, true, false
			} else if need {
				return Info{}, false, true
			}
			return Info{}, false, false
		}
		if len(b) < n {
			return Info{}, false, true
		}
		ch, err := parseClientHello(b[:n])
		if err != nil {
			return Info{}, false, false
		}
		info = Info{SNI: ch.SNI, JA4: ch.JA4, TLSVersion: tlsVersionName(ch.Version)}
		if len(ch.ALPN) > 0 {
			info.ALPN = ch.ALPN[0]
		}
		return info, true, false
	}
	return Info{}, false, true // 5 バイトに満たない
}

// take は接続の終わりに、取り出した情報を返して忘れる。
func (t *tracker) take(src, dst netip.AddrPort) (Info, bool) {
	k := flowKey{src, dst}
	e, ok := t.infos[k]
	delete(t.infos, k)
	delete(t.streams, k)
	return e.info, ok
}

// expire は古い組み立てと情報を捨てる。
func (t *tracker) expire(now time.Time) {
	for k, st := range t.streams {
		if now.Sub(st.started) > streamTTL {
			delete(t.streams, k)
		}
	}
	for k, e := range t.infos {
		if now.Sub(e.at) > infoTTL {
			delete(t.infos, k)
		}
	}
}
