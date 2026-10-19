//go:build linux

package linux

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"susanoo/internal/event"
	"susanoo/internal/platform"
)

// 資源の使用量の計測と監視の間引き（2l）、時刻の同期の状態。

const (
	maxTreeProcs       = 256 // 資源の使用量を数える子孫のプロセスの上限
	throttleRate       = 20  // 間引いている間に通す、検知結果でないイベントの 1 秒あたりの数
	throttleBurst      = 100
	throttleConnFactor = 5 // 間引いている間は、通信の一覧を取る間隔をこの倍にする
)

var _ platform.Resources = (*Platform)(nil)

// Usage は CLIENT（このプロセスと、その子孫）の資源の使用量を返す（platform.Resources）。
func (p *Platform) Usage() (platform.Usage, error) {
	u, err := processTreeUsage(p.self)
	u.Dropped = p.dropped.Load()
	return u, err
}

// SetThrottle は監視の間引きを始めるかやめる（platform.Resources）。間引いている間は、プロセス、通信、ファイルの
// イベントを合わせて 1 秒に throttleRate 個までにし、通信の一覧を取る間隔を延ばす。
func (p *Platform) SetThrottle(on bool) { p.throttled.Store(on) }

// thin は、間引いている間に e を捨てるかを返す。検知結果と、ログオンの記録（数が少なく、総当たりの検知に使う）は捨てない。
func (p *Platform) thin(e *event.Event) bool {
	if !p.throttled.Load() || e.ClassUID == event.ClassDetectionFinding || e.ClassUID == event.ClassAuthentication || p.thinner.allow(p.cfg.Now()) {
		return false
	}
	p.dropped.Add(1)
	return true
}

// processTreeUsage は pid のプロセスと、その子孫の CPU 時間と実メモリの合計を返す。
// 子孫は /proc/<pid>/task/<tid>/children でたどる（CLIENT の解析部、journalctl など）。
func processTreeUsage(root int) (platform.Usage, error) {
	var u platform.Usage
	page := int64(os.Getpagesize())
	seen := map[int]bool{}
	queue := []int{root}
	for len(queue) > 0 && len(seen) < maxTreeProcs {
		pid := queue[0]
		queue = queue[1:]
		if seen[pid] {
			continue
		}
		seen[pid] = true
		data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err != nil {
			if pid == root {
				return u, err
			}
			continue // 終わった子
		}
		ticks, rss, err := parseProcStat(data)
		if err != nil {
			if pid == root {
				return u, err
			}
			continue
		}
		u.CPU += time.Duration(ticks) * time.Second / clockTicks
		u.Memory += rss * page
		queue = append(queue, childPIDs(pid)...)
	}
	return u, nil
}

// parseProcStat は /proc/<pid>/stat から、CPU の時間（utime と stime の和。単位は clockTicks）と、実メモリのページ数を読む。
// comm は括弧で囲まれ、空白や括弧を含みうるので、最後の「)」の後ろから数える。
func parseProcStat(data []byte) (ticks uint64, rss int64, err error) {
	i := strings.LastIndexByte(string(data), ')')
	if i < 0 {
		return 0, 0, errors.New("linux: /proc/<pid>/stat の形式が違います")
	}
	// fields[0] が 3 番目の項目（state）。utime は 14 番目、stime は 15 番目、rss は 24 番目。
	fields := strings.Fields(string(data[i+1:]))
	if len(fields) < 22 {
		return 0, 0, errors.New("linux: /proc/<pid>/stat の項目が足りません")
	}
	utime, err1 := strconv.ParseUint(fields[11], 10, 64)
	stime, err2 := strconv.ParseUint(fields[12], 10, 64)
	rss, err3 := strconv.ParseInt(fields[21], 10, 64)
	if err := errors.Join(err1, err2, err3); err != nil {
		return 0, 0, fmt.Errorf("linux: /proc/<pid>/stat を解析できません: %w", err)
	}
	return utime + stime, max(rss, 0), nil
}

// childPIDs は pid の子プロセスを返す。子はそれを作ったスレッドごとに分かれて載る。
func childPIDs(pid int) []int {
	dir := "/proc/" + strconv.Itoa(pid) + "/task"
	tasks, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []int
	for _, t := range tasks {
		data, err := os.ReadFile(dir + "/" + t.Name() + "/children")
		if err != nil {
			continue
		}
		for _, s := range strings.Fields(string(data)) {
			if n, err := strconv.Atoi(s); err == nil {
				out = append(out, n)
			}
		}
	}
	return out
}

var _ platform.Clock = (*Platform)(nil)

// ClockSynchronized は時刻の同期の状態を返す（platform.Clock）。
func (p *Platform) ClockSynchronized() (bool, error) { return ClockSynchronized() }

// adjtimex(2) の値。
const (
	timeError = 5    // TIME_ERROR：時刻が同期していない
	staUnsync = 0x40 // STA_UNSYNC
)

// ClockSynchronized は、カーネルの時刻が NTP などで同期しているかを adjtimex(2) で返す（timedatectl の
// 「System clock synchronized」と同じ判断）。読むだけなので権限はいらない。
func ClockSynchronized() (bool, error) {
	var tx syscall.Timex
	state, err := syscall.Adjtimex(&tx)
	if err != nil {
		return false, fmt.Errorf("linux: adjtimex: %w", err)
	}
	return state != timeError && tx.Status&staUnsync == 0, nil
}
