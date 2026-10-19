// Package flow は GW の通信の記録（G5）を実装する。
//
//   - フローの記録：conntrack の接続の終わりのイベントから、送信元、宛先、通信量、開始と終了の時刻を記録する
//   - TLS の SNI と指紋（JA4）、平文の HTTP の Host：nftables が NFLOG で渡す、各接続の最初の数パケットから取り出す
//
// どちらも転送の経路の外で動くので、回線の速度を落とさない。記録するのは LAN から外へ転送する通信だけで、
// GW 自身の通信と、GW のリゾルバに向け直した DNS は記録しない。
package flow

import (
	"net/netip"
	"slices"
	"time"
)

// Kind は記録の種類。
type Kind int

const (
	Open    Kind = iota // TLS か HTTP の始まり（SNI か Host を取り出せたとき）
	Close               // 接続の終わり（通信量と時刻を含む）
	Blocked             // GW が落とした接続の試み（脅威情報のアドレスへの転送など。BlockGroup の NFLOG）
)

// Record は 1 件の記録。
type Record struct {
	Kind       Kind
	Time       time.Time
	Proto      uint8 // IP のプロトコルの番号（6 が TCP、17 が UDP）
	Src, Dst   netip.AddrPort
	BytesOut   uint64 // LAN から外へ
	BytesIn    uint64 // 外から LAN へ
	PacketsOut uint64
	PacketsIn  uint64
	Start, End time.Time
	Info       Info
	HasInfo    bool
}

// processor はイベントとパケットから記録を作る。単一のゴルーチンから使う。
type processor struct {
	lans     []netip.Prefix // LAN のネットワーク（IPv4 と、IPv6 を転送するなら IPv6）
	gateways []netip.Addr   // GW の LAN 側のアドレス
	emit     func(Record)
	tracker  *tracker
}

// newProcessor は、LAN のネットワーク lans と GW の LAN 側のアドレス gateways（無効なものは除く）で記録を作る。
func newProcessor(lans []netip.Prefix, gateways []netip.Addr, emit func(Record)) *processor {
	p := &processor{emit: emit, tracker: newTracker()}
	for _, l := range lans {
		if l.IsValid() {
			p.lans = append(p.lans, l)
		}
	}
	for _, g := range gateways {
		if g.IsValid() {
			p.gateways = append(p.gateways, g)
		}
	}
	return p
}

// inLAN は、アドレスが LAN のネットワークの中かを返す。
func (p *processor) inLAN(a netip.Addr) bool {
	a = a.Unmap()
	for _, l := range p.lans {
		if l.Contains(a) {
			return true
		}
	}
	return false
}

// outbound は LAN から外へ転送する通信かどうかを返す。
func (p *processor) outbound(src, dst, replySrc netip.Addr) bool {
	return p.inLAN(src) && !p.inLAN(dst) && !slices.Contains(p.gateways, replySrc.Unmap())
}

// packet は NFLOG で受け取った IP のパケットを処理する。
func (p *processor) packet(b []byte, now time.Time) {
	s, ok := parseTCP(b)
	if !ok || !p.inLAN(s.src.Addr()) || p.inLAN(s.dst.Addr()) {
		return
	}
	info, ok := p.tracker.add(s, now)
	if !ok {
		return
	}
	p.emit(Record{Kind: Open, Time: now, Proto: 6, Src: s.src, Dst: s.dst, Info: info, HasInfo: true})
}

// blocked は、GW が落として NFLOG で渡したパケットを、接続の試みの記録にする。
func (p *processor) blocked(b []byte, now time.Time) {
	src, dst, proto, ok := parseIP(b)
	if !ok || !p.inLAN(src.Addr()) || p.inLAN(dst.Addr()) {
		return
	}
	p.emit(Record{Kind: Blocked, Time: now, Proto: proto, Src: src, Dst: dst, Start: now, End: now})
}

// destroyed は conntrack の接続の終わりのイベントを処理する。
func (p *processor) destroyed(ct conntrack, now time.Time) {
	if !p.outbound(ct.orig.src.Addr(), ct.orig.dst.Addr(), ct.reply.src.Addr()) {
		return
	}
	r := Record{
		Kind: Close, Time: now, Proto: ct.proto, Src: ct.orig.src, Dst: ct.orig.dst,
		BytesOut: ct.bytesOrig, BytesIn: ct.bytesReply, PacketsOut: ct.pktsOrig, PacketsIn: ct.pktsReply,
		Start: ct.start, End: ct.stop,
	}
	if r.End.IsZero() {
		r.End = now
	}
	r.Info, r.HasInfo = p.tracker.take(ct.orig.src, ct.orig.dst)
	p.emit(r)
}
