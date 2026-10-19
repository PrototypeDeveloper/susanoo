//go:build linux

package linux

import (
	"os"
	"os/exec"
	"slices"
	"strconv"
	"testing"
	"time"

	"susanoo/internal/event"
)

func TestParseProcStat(t *testing.T) {
	// comm に括弧と空白を含むプロセス。utime 12、stime 30、rss 2048。
	line := "4242 (a) (b c) S 1 4242 4242 0 -1 4194560 100 0 0 0 12 30 0 0 20 0 3 0 777 123456789 2048 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"
	ticks, rss, err := parseProcStat([]byte(line))
	if err != nil || ticks != 42 || rss != 2048 {
		t.Errorf("parseProcStat = %d, %d, %v", ticks, rss, err)
	}
	for _, bad := range []string{"", "4242 no-paren S 1", "4242 (x) S 1 2 3", "4242 (x) S 1 4242 4242 0 -1 4194560 100 0 0 0 a 30 0 0 20 0 3 0 777 1 2048"} {
		if _, _, err := parseProcStat([]byte(bad)); err == nil {
			t.Errorf("parseProcStat(%q) がエラーになりません", bad)
		}
	}
}

// 資源の使用量は、このプロセスと子のプロセスの合計。
func TestProcessTreeUsage(t *testing.T) {
	self, err := processTreeUsage(os.Getpid())
	if err != nil || self.Memory <= 0 {
		t.Fatalf("processTreeUsage = %+v, %v", self, err)
	}
	if _, err := os.Stat("/proc/self/task/" + strconv.Itoa(os.Getpid()) + "/children"); err != nil {
		t.Skip("この環境の /proc には children がありません")
	}
	cmd := exec.Command("sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer cmd.Process.Kill()
	deadline := time.Now().Add(5 * time.Second)
	for !slices.Contains(childPIDs(os.Getpid()), cmd.Process.Pid) {
		if time.Now().After(deadline) {
			t.Fatalf("子のプロセス %d が見つかりません: %v", cmd.Process.Pid, childPIDs(os.Getpid()))
		}
		time.Sleep(10 * time.Millisecond)
	}
	tree, err := processTreeUsage(os.Getpid())
	if err != nil || tree.Memory <= self.Memory/2 {
		t.Errorf("子を含めた使用量 = %+v, %v（このプロセスだけでは %+v）", tree, err, self)
	}
	if _, err := processTreeUsage(1 << 30); err == nil {
		t.Error("ないプロセスでエラーになりません")
	}
}

// 間引いている間は、検知結果でないイベントを決めた数だけ通し、残りを数えて捨てる。検知結果とログオンの記録は捨てない。
func TestThin(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	p := &Platform{cfg: Config{Now: func() time.Time { return now }}, thinner: newLimiter(throttleRate, throttleBurst)}
	info := event.New(event.ClassProcessActivity, 1, event.SeverityInformational, now)
	finding := event.New(event.ClassDetectionFinding, event.FindingCreate, event.SeverityHigh, now)
	logon := event.New(event.ClassAuthentication, event.AuthLogon, event.SeverityInformational, now)
	for range 1000 {
		if p.thin(info) {
			t.Fatal("間引いていないのに捨てました")
		}
	}
	p.SetThrottle(true)
	passed := 0
	for range 1000 {
		if !p.thin(info) {
			passed++
		}
		if p.thin(finding) || p.thin(logon) {
			t.Fatal("検知結果かログオンの記録を捨てました")
		}
	}
	if passed != throttleBurst || p.dropped.Load() != uint64(1000-throttleBurst) {
		t.Errorf("通した数 %d、捨てた数 %d", passed, p.dropped.Load())
	}
	now = now.Add(time.Second)
	if p.thin(info) {
		t.Error("1 秒たっても通しません")
	}
	p.SetThrottle(false)
	if p.thin(info) {
		t.Error("間引きをやめても捨てました")
	}
}

func TestClockSynchronized(t *testing.T) {
	if _, err := ClockSynchronized(); err != nil {
		t.Fatal(err)
	}
}
