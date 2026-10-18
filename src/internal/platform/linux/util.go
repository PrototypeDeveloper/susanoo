//go:build linux

package linux

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sync"
	"syscall"
	"time"
)

// maxHashSize より大きな実行ファイルはハッシュを計算しない。
const maxHashSize = 256 << 20

type hashKey struct {
	dev, ino uint64
	mtime    int64
	size     int64
}

// hasher は実行ファイルの SHA-256 を計算する。中身が変わっていなければ（デバイス、i ノード、更新時刻、大きさが同じなら）
// 前に計算した値を使う。
type hasher struct {
	mu    sync.Mutex
	cache map[hashKey]string
}

func newHasher() *hasher { return &hasher{cache: map[hashKey]string{}} }

// hashFD は開いているファイル fd の SHA-256 を返す。fd は閉じない。
func (h *hasher) hashFD(fd int) string {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil || st.Size > maxHashSize {
		return ""
	}
	key := hashKey{uint64(st.Dev), st.Ino, st.Mtim.Nano(), st.Size}
	h.mu.Lock()
	sum, ok := h.cache[key]
	h.mu.Unlock()
	if ok {
		return sum
	}
	d := sha256.New()
	buf := make([]byte, 64<<10)
	var off int64
	for {
		n, err := syscall.Pread(fd, buf, off)
		if n > 0 {
			d.Write(buf[:n])
			off += int64(n)
		}
		if err != nil {
			return ""
		}
		if n == 0 {
			break
		}
	}
	sum = hex.EncodeToString(d.Sum(nil))
	h.mu.Lock()
	if len(h.cache) >= 4096 {
		for k := range h.cache {
			delete(h.cache, k)
			break
		}
	}
	h.cache[key] = sum
	h.mu.Unlock()
	return sum
}

// limiter はイベントの数を 1 秒あたり rate、まとめて burst までに抑える（トークンバケット）。
type limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	tokens  float64
	last    time.Time
	dropped int
}

func newLimiter(rate, burst int) *limiter {
	return &limiter{rate: float64(rate), burst: float64(burst), tokens: float64(burst)}
}

// allow はイベントを通してよいかを返す。通せなかった数も数える。
func (l *limiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.last.IsZero() {
		l.tokens = min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rate)
	}
	l.last = now
	if l.tokens < 1 {
		l.dropped++
		return false
	}
	l.tokens--
	return true
}

// takeDropped は通せなかった数を返して 0 に戻す。
func (l *limiter) takeDropped() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.dropped
	l.dropped = 0
	return n
}

// overflowLog は、fanotify の待ち行列があふれてイベントを取りこぼしたことを、1 分に 1 回までログに残す。
// 取りこぼしは攻撃者が大量の操作で起こすこともできるので、黙って捨てない。
type overflowLog struct {
	mu    sync.Mutex
	last  time.Time
	count int
}

const overflowLogInterval = time.Minute

// note は取りこぼしを 1 回数え、前のログから overflowLogInterval が経っていればログに残す。
func (o *overflowLog) note(log *slog.Logger, what string, now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.count++
	if now.Sub(o.last) < overflowLogInterval {
		return
	}
	if log != nil {
		log.Warn(what+"のイベントがカーネルの待ち行列からあふれ、一部を取りこぼしました（大量の操作か、処理の遅れ）", "回数", o.count)
	}
	o.last, o.count = now, 0
}

// randomID は検知結果の ID を作る。
func randomID() string { return rand.Text() }
