// Package audit は管理操作の監査ログを扱う（M10）。
//
// ログは 1 行に 1 件の JSON（JSON Lines）で、各記録は直前の記録のハッシュを含む。
// ハッシュは「直前のハッシュ」と「hash 以外の項目の JSON」をつないだものの SHA-256 で、
// 途中の記録の書き換え、削除、挿入は連鎖が切れることで検知できる。
// 末尾の記録をまとめて消されるとこの仕組みだけでは検知できないため、Head の値を
// 別の場所（CONTROLLER など）にも送って保管する前提とする。
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// genesis は最初の記録の prev_hash。
var genesis = strings.Repeat("0", sha256.Size*2)

// maxLine は 1 件の記録の上限。これを超える行は改ざんとみなす。
const maxLine = 1 << 20

// Entry は記録する操作。
type Entry struct {
	Actor  string // 操作した主体（証明書の持ち主、CLI の利用者など）
	Action string // 操作の種類（device.isolate など）
	Target string // 操作の対象（端末 ID など）
	Detail any    // 補足の情報。JSON にできる値
}

// Record はログの 1 件。
type Record struct {
	Seq      uint64          `json:"seq"`
	Time     time.Time       `json:"time"`
	Actor    string          `json:"actor"`
	Action   string          `json:"action"`
	Target   string          `json:"target,omitempty"`
	Detail   json.RawMessage `json:"detail,omitempty"`
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
}

// Head はログの末尾の状態。
type Head struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

// ChainError は連鎖の検証に失敗した位置と理由。
type ChainError struct {
	Line   int
	Reason string
}

func (e *ChainError) Error() string {
	return fmt.Sprintf("audit: %d 行目: %s", e.Line, e.Reason)
}

// computeHash は hash 以外の項目からハッシュを計算する。
func computeHash(r Record) (string, error) {
	r.Hash = ""
	body, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(r.PrevHash))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Verify は r から読んだログの連鎖を最初から検証し、末尾の状態を返す。
func Verify(r io.Reader) (Head, error) {
	head := Head{Hash: genesis}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)
	line := 0
	for sc.Scan() {
		line++
		var rec Record
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			return head, &ChainError{line, "JSON を解析できません: " + err.Error()}
		}
		if dec.More() {
			return head, &ChainError{line, "1 行に複数の記録があります"}
		}
		if rec.Seq != head.Seq+1 {
			return head, &ChainError{line, fmt.Sprintf("番号が %d です（%d が必要）", rec.Seq, head.Seq+1)}
		}
		if rec.PrevHash != head.Hash {
			return head, &ChainError{line, "直前の記録のハッシュと一致しません"}
		}
		want, err := computeHash(rec)
		if err != nil {
			return head, &ChainError{line, err.Error()}
		}
		if rec.Hash != want {
			return head, &ChainError{line, "記録のハッシュが一致しません（書き換えられています）"}
		}
		head = Head{Seq: rec.Seq, Hash: rec.Hash}
	}
	if err := sc.Err(); err != nil {
		return head, &ChainError{line + 1, err.Error()}
	}
	return head, nil
}

// Log は追記用に開いた監査ログ。複数のゴルーチンから同時に使える。
type Log struct {
	mu   sync.Mutex
	f    *os.File
	head Head
	now  func() time.Time
}

// Open は path のログを開く。既存のログは連鎖を検証してから末尾に追記する。
// 検証に失敗したら開かずにエラーを返す。
func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	head, err := Verify(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &Log{f: f, head: head, now: time.Now}, nil
}

// Append は操作を記録し、ディスクに書き込み終えてから返る。
func (l *Log) Append(e Entry) (Record, error) {
	if e.Actor == "" || e.Action == "" {
		return Record{}, errors.New("audit: actor と action は必須です")
	}
	var detail json.RawMessage
	if e.Detail != nil {
		raw, err := json.Marshal(e.Detail)
		if err != nil {
			return Record{}, fmt.Errorf("audit: detail を JSON にできません: %w", err)
		}
		var buf bytes.Buffer
		if err := json.Compact(&buf, raw); err != nil {
			return Record{}, err
		}
		detail = buf.Bytes()
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return Record{}, errors.New("audit: ログは閉じられています")
	}
	rec := Record{
		Seq:      l.head.Seq + 1,
		Time:     l.now().UTC(),
		Actor:    e.Actor,
		Action:   e.Action,
		Target:   e.Target,
		Detail:   detail,
		PrevHash: l.head.Hash,
	}
	hash, err := computeHash(rec)
	if err != nil {
		return Record{}, err
	}
	rec.Hash = hash
	line, err := json.Marshal(rec)
	if err != nil {
		return Record{}, err
	}
	if len(line)+1 > maxLine {
		return Record{}, fmt.Errorf("audit: 記録が大きすぎます（%d バイト）", len(line))
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return Record{}, err
	}
	if err := l.f.Sync(); err != nil {
		return Record{}, err
	}
	l.head = Head{Seq: rec.Seq, Hash: rec.Hash}
	return rec, nil
}

// Head は末尾の状態を返す。
func (l *Log) Head() Head {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.head
}

// Close はログを閉じる。
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
