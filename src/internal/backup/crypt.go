package backup

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// バックアップの暗号化。パスフレーズから PBKDF2-SHA256 で鍵を作り、AES-256-GCM で 64 KiB ずつ暗号化する
// （STREAM の構成。nonce は区切りの番号で、最後の区切りには印を付けるので、並べ替え、差し替え、末尾の切り捨てが分かる）。
// ファイルごとに塩を変えるので、同じパスフレーズでも鍵は毎回変わる。
//
//	magic（"SUSANOO-BACKUP-ENC1\n"）
//	見出しの長さ（4 バイト）と見出し（JSON。kdf、反復の回数、塩、区切りの大きさ）
//	区切り（4 バイトの長さと、暗号文）の並び

const (
	encMagic       = "SUSANOO-BACKUP-ENC1\n"
	plainMagic     = "\x1f\x8b" // gzip（暗号化していないバックアップ）
	chunkSize      = 64 << 10
	kdfIterations  = 600000
	minPassphrase  = 12
	maxHeaderBytes = 4096
)

// ErrPassphrase は、パスフレーズが違うか、ファイルが壊れていることを表す。
var ErrPassphrase = errors.New("backup: 復号できません（パスフレーズが違うか、ファイルが壊れているか書き換えられています）")

type encHeader struct {
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       []byte `json:"salt"`
	Chunk      int    `json:"chunk"`
}

func deriveKey(pass []byte, salt []byte, iter int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, string(pass), salt, iter, 32)
}

// nonce は区切りの番号から nonce を作る（最後の区切りは先頭のバイトで区別する）。
func nonce(n uint64, last bool) []byte {
	b := make([]byte, 12)
	if last {
		b[0] = 1
	}
	binary.BigEndian.PutUint64(b[4:], n)
	return b
}

// encryptWriter は書かれたものを暗号化して w に書く。Close で最後の区切りを書く。
type encryptWriter struct {
	w    io.Writer
	aead cipher.AEAD
	buf  []byte
	n    uint64
	err  error
}

func newEncryptWriter(w io.Writer, pass []byte) (*encryptWriter, error) {
	if len(pass) < minPassphrase {
		return nil, fmt.Errorf("backup: パスフレーズは %d 文字以上にしてください", minPassphrase)
	}
	h := encHeader{KDF: "pbkdf2-sha256", Iterations: kdfIterations, Salt: make([]byte, 16), Chunk: chunkSize}
	rand.Read(h.Salt)
	key, err := deriveKey(pass, h.Salt, h.Iterations)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	head, _ := json.Marshal(h)
	var pre bytes.Buffer
	pre.WriteString(encMagic)
	binary.Write(&pre, binary.BigEndian, uint32(len(head)))
	pre.Write(head)
	if _, err := w.Write(pre.Bytes()); err != nil {
		return nil, err
	}
	return &encryptWriter{w: w, aead: aead}, nil
}

func (e *encryptWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n := len(p)
	e.buf = append(e.buf, p...)
	for len(e.buf) > chunkSize { // 最後の区切りは Close で書くので、ちょうどの大きさでも残す
		if e.err = e.seal(e.buf[:chunkSize], false); e.err != nil {
			return 0, e.err
		}
		e.buf = e.buf[chunkSize:]
	}
	return n, nil
}

func (e *encryptWriter) seal(chunk []byte, last bool) error {
	ct := e.aead.Seal(nil, nonce(e.n, last), chunk, nil)
	e.n++
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(ct)))
	if _, err := e.w.Write(l[:]); err != nil {
		return err
	}
	_, err := e.w.Write(ct)
	return err
}

func (e *encryptWriter) Close() error {
	if e.err != nil {
		return e.err
	}
	e.err = e.seal(e.buf, true)
	e.buf = nil
	if e.err == nil {
		e.err = errors.New("backup: 閉じた後に書き込みました")
		return nil
	}
	return e.err
}

// decryptReader は暗号化したバックアップを復号して読む。最後の区切りまで読めずに終わったら ErrPassphrase を返す。
type decryptReader struct {
	r    *bufio.Reader
	aead cipher.AEAD
	n    uint64
	buf  []byte
	done bool
}

func newDecryptReader(r *bufio.Reader, pass []byte) (*decryptReader, error) {
	var l uint32
	if err := binary.Read(r, binary.BigEndian, &l); err != nil || l > maxHeaderBytes {
		return nil, errors.New("backup: 暗号化の見出しが壊れています")
	}
	head := make([]byte, l)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, errors.New("backup: 暗号化の見出しが壊れています")
	}
	var h encHeader
	if err := json.Unmarshal(head, &h); err != nil || h.KDF != "pbkdf2-sha256" || h.Iterations < 100000 || h.Iterations > 10000000 ||
		len(h.Salt) < 16 || h.Chunk != chunkSize {
		return nil, errors.New("backup: 対応していない暗号化の見出しです")
	}
	key, err := deriveKey(pass, h.Salt, h.Iterations)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &decryptReader{r: r, aead: aead}, nil
}

func (d *decryptReader) Read(p []byte) (int, error) {
	for len(d.buf) == 0 {
		if d.done {
			return 0, io.EOF
		}
		var l uint32
		if err := binary.Read(d.r, binary.BigEndian, &l); err != nil {
			return 0, ErrPassphrase // 最後の区切りの前に終わった（切り捨てられた）
		}
		if l > chunkSize+uint32(d.aead.Overhead()) {
			return 0, ErrPassphrase
		}
		ct := make([]byte, l)
		if _, err := io.ReadFull(d.r, ct); err != nil {
			return 0, ErrPassphrase
		}
		// 最後の区切りかどうかは、両方の nonce で開けてみて決める（最後の区切りの後ろにデータがあれば壊れている）。
		pt, err := d.aead.Open(nil, nonce(d.n, false), ct, nil)
		if err != nil {
			if pt, err = d.aead.Open(nil, nonce(d.n, true), ct, nil); err != nil {
				return 0, ErrPassphrase
			}
			d.done = true
			if _, err := d.r.Peek(1); err != io.EOF {
				return 0, ErrPassphrase
			}
		}
		d.n++
		d.buf = pt
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}
