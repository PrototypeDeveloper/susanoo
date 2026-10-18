// Package privsep は CLIENT の権限の分離（C10）を実装する。
//
// CLIENT は root で起動し、自分自身を非特権の利用者で起動し直して解析部とする。2 つは socketpair でつなぐ。
//
//   - 執行部（root、必要最小限の capability）：OS の監視、自己隔離、指示の署名の検証、状態の保存、端末の鍵での署名
//   - 解析部（非特権）：CONTROLLER との通信（TLS、HTTP/2、JSON）と、イベントの送信
//
// 解析部から執行部に頼めるのは、ハートビートの作成、署名付きの指示の適用、TLS 1.3 のクライアント認証の署名、
// 更新した証明書の保存の 4 つだけで、執行部はどれも自分で検証してから行う（client.Local）。ネットワークから届くデータを扱う解析部を
// 乗っ取られても、隔離の解除や監視の停止はできず、端末の鍵も持ち出せない。解析部が止まれば執行部も止まり、
// ハートビートの途絶で GW が隔離する（G10）。
//
// GW も同じ仕組みで、nft とソケットの用意を受け持つ執行部と、非特権の部分に分ける（G12、gw.go）。
//
// やり取りは「4 バイトの長さ（ビッグエンディアン）と JSON」のフレームで行い、1 フレームは maxFrame までとする。
// フレームは要求、応答、知らせのどれか（peer.go）。知らない項目や余分なデータを含むフレームは、
// 乗っ取られた恐れがあるとみなして、つながりを切る。
package privsep

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"susanoo/internal/client"
)

// maxFrame は 1 フレームの上限。脅威情報（G7）の一覧を 1 回で渡せる大きさにする。受け取る側は 1 フレームずつ読むので、
// 乗っ取られた相手が大きなフレームを送っても、使うメモリはこの大きさの数倍に収まる。
const maxFrame = 8 << 20

// noticeHello はつながりの最初に送る知らせ（相手が動くのに必要な情報）。
const noticeHello = "hello"

// Hello は CLIENT の解析部が動くのに必要な情報。解析部は設定ファイルや鍵を読まない。
type Hello struct {
	Controller        string        `json:"controller"`         // CONTROLLER のアドレスとポート
	CA                [][]byte      `json:"ca"`                 // 内部の認証局の証明書（DER）
	Chain             [][]byte      `json:"chain"`              // 端末の証明書の連なり（DER）
	HeartbeatInterval time.Duration `json:"heartbeat_interval"` // ハートビートの間隔
}

// CertPool は認証局の証明書を、検証に使う形にする。
func (h Hello) CertPool() (*x509.CertPool, error) {
	if len(h.CA) == 0 {
		return nil, errors.New("privsep: 認証局の証明書がありません")
	}
	pool := x509.NewCertPool()
	for _, der := range h.CA {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("privsep: 認証局の証明書を解析できません: %w", err)
		}
		pool.AddCert(c)
	}
	return pool, nil
}

var (
	// ErrAnalyzerStopped は、解析部とのつながりが切れたことを表す。
	ErrAnalyzerStopped = errors.New("privsep: 解析部が止まりました")
	// ErrExecutorStopped は、執行部とのつながりが切れたことを表す。
	ErrExecutorStopped = client.ErrExecutorStopped
	errFrameTooLarge   = fmt.Errorf("privsep: フレームが上限（%d バイト）を超えています", maxFrame)
)

// conn はフレームの読み書き。書き込みは複数のゴルーチンから行える。読み込みは 1 つのゴルーチンから行う。
type conn struct {
	r  *bufio.Reader
	mu sync.Mutex
	w  io.Writer
}

func newConn(rw io.ReadWriter) *conn { return &conn{r: bufio.NewReader(rw), w: rw} }

func (c *conn) send(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) > maxFrame {
		return errFrameTooLarge
	}
	frame := make([]byte, 4, 4+len(data))
	binary.BigEndian.PutUint32(frame, uint32(len(data)))
	frame = append(frame, data...)
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err = c.w.Write(frame)
	return err
}

// recv は 1 フレームを読んで v に解析する。つながりが切れていれば io.EOF を返す。
func (c *conn) recv(v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return io.EOF
		}
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrame {
		return errFrameTooLarge
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(c.r, data); err != nil {
		return fmt.Errorf("privsep: フレームが途中で切れています: %w", err)
	}
	return parseFrame(data, v)
}

// parseFrame はフレームの中身を解析する。知らない項目があれば拒否する。
func parseFrame(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("privsep: フレームを解析できません: %w", err)
	}
	if d.More() {
		return errors.New("privsep: フレームの後ろに余分なデータがあります")
	}
	return nil
}
