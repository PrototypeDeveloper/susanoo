package dns

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// DefaultTimeout は上流への 1 回の問い合わせの時間切れ。
const DefaultTimeout = 2 * time.Second

// Upstream は上流の DNS サーバー。TLSName を指定すると DNS over TLS（RFC 7858）で問い合わせ、
// 接続を使い回す。指定しなければ UDP で問い合わせ、応答が切り詰められていたら TCP で問い合わせ直す。
type Upstream struct {
	Addr    netip.AddrPort
	TLSName string         // 証明書で確かめる名前
	Roots   *x509.CertPool // DoT の証明書を検証する認証局。nil ならシステムの認証局

	mu   sync.Mutex
	conn *tls.Conn
}

func (u *Upstream) String() string {
	if u.TLSName != "" {
		return fmt.Sprintf("tls://%s（%s）", u.Addr, u.TLSName)
	}
	return u.Addr.String()
}

// Exchange は問い合わせ query を送り、応答を返す。問い合わせの ID はランダムに付け替え、
// 応答の ID と問い合わせが一致するものだけを受け入れて、元の ID に戻して返す。
func (u *Upstream) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	q, err := Parse(query)
	if err != nil {
		return nil, err
	}
	var idb [2]byte
	rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	out := append([]byte(nil), query...)
	setID(out, id)

	var resp []byte
	if u.TLSName != "" {
		resp, err = u.exchangeTLS(ctx, out)
	} else {
		resp, err = u.exchangeUDP(ctx, out, id, q.Question)
		if err == nil {
			if r, perr := Parse(resp); perr == nil && r.Truncated() {
				resp, err = exchangeStream(ctx, u.dialTCP, out)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	r, err := Parse(resp)
	if err != nil {
		return nil, err
	}
	if !r.Response() || r.ID != id || r.Question != q.Question {
		return nil, errors.New("dns: 問い合わせと一致しない応答です")
	}
	setID(resp, q.ID)
	return resp, nil
}

func (u *Upstream) exchangeUDP(ctx context.Context, query []byte, id uint16, question Question) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", u.Addr.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		// ID と問い合わせが一致しない応答（偽の応答など）は読み捨てる。
		if r, err := Parse(buf[:n]); err == nil && r.Response() && r.ID == id && r.Question == question {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

func (u *Upstream) dialTCP(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", u.Addr.String())
}

// exchangeStream は TCP や TLS の接続で、長さを前に付けた形で 1 回やり取りする。
func exchangeStream(ctx context.Context, dial func(context.Context) (net.Conn, error), query []byte) ([]byte, error) {
	c, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return roundTrip(ctx, c, query)
}

func roundTrip(ctx context.Context, c net.Conn, query []byte) ([]byte, error) {
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	msg := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	if _, err := c.Write(append(msg, query...)); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// exchangeTLS は DoT の接続を使い回して問い合わせる。失敗したら接続し直して 1 回だけやり直す。
func (u *Upstream) exchangeTLS(ctx context.Context, query []byte) ([]byte, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for attempt := 0; ; attempt++ {
		if u.conn == nil {
			d := tls.Dialer{Config: &tls.Config{ServerName: u.TLSName, RootCAs: u.Roots, MinVersion: tls.VersionTLS12}}
			c, err := d.DialContext(ctx, "tcp", u.Addr.String())
			if err != nil {
				return nil, err
			}
			u.conn = c.(*tls.Conn)
		}
		resp, err := roundTrip(ctx, u.conn, query)
		if err == nil {
			u.conn.SetDeadline(time.Time{})
			return resp, nil
		}
		u.conn.Close()
		u.conn = nil
		if attempt > 0 || ctx.Err() != nil {
			return nil, err
		}
	}
}

// Close は使い回している接続を閉じる。
func (u *Upstream) Close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.conn != nil {
		u.conn.Close()
		u.conn = nil
	}
}
