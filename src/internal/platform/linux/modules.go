//go:build linux

package linux

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"susanoo/internal/event"
)

// カーネルモジュールの監視（C4）。/proc/modules を定期的に読み、起動した後に新しく読み込まれたモジュールを検知結果にする。
// 誰が読み込んだかは分からない（モジュールの読み込みはプロセスの操作として記録されないため）。
// モジュールの自動読み込みの設定の変更は、永続化の場所（/etc/modules-load.d など）の監視で捕らえる。

const (
	modulesPath         = "/proc/modules"
	defaultModulePoll   = 10 * time.Second
	maxModulesPerReport = 20
)

type moduleMonitor struct {
	path     string
	interval time.Duration
	known    map[string]bool
}

func newModuleMonitor(interval time.Duration) (*moduleMonitor, error) {
	if interval <= 0 {
		interval = defaultModulePoll
	}
	m := &moduleMonitor{path: modulesPath, interval: interval}
	data, err := os.ReadFile(m.path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", m.path, err)
	}
	m.known = map[string]bool{}
	for _, name := range parseModules(data) {
		m.known[name] = true
	}
	return m, nil
}

func (m *moduleMonitor) close() error { return nil }

func (m *moduleMonitor) run(ctx context.Context, emit func(*event.Event)) error {
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
		data, err := os.ReadFile(m.path)
		if err != nil {
			continue
		}
		for _, e := range m.check(parseModules(data), time.Now()) {
			emit(e)
		}
	}
}

// check は今のモジュールの一覧 names から、知らないモジュールを検知結果にする。
func (m *moduleMonitor) check(names []string, now time.Time) []*event.Event {
	var fresh []string
	for _, n := range names {
		if !m.known[n] {
			m.known[n] = true
			fresh = append(fresh, n)
		}
	}
	if len(fresh) == 0 {
		return nil
	}
	if len(fresh) > maxModulesPerReport {
		fresh = append(fresh[:maxModulesPerReport], "…")
	}
	msg := fmt.Sprintf("カーネルモジュールが読み込まれました: %s", strings.Join(fresh, "、"))
	e := event.New(event.ClassDetectionFinding, event.FindingCreate, event.SeverityMedium, now)
	e.Message = msg
	e.FindingInfo = &event.FindingInfo{UID: randomID(), Title: "カーネルモジュールの読み込み", Desc: msg, Types: []string{event.FindingTypeKernelModule}}
	e.Unmapped = map[string]any{"kernel_module": map[string]any{"names": fresh}}
	return []*event.Event{e}
}

// parseModules は /proc/modules の各行の先頭（モジュールの名前）を返す。
func parseModules(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) > 0 {
			out = append(out, f[0])
		}
	}
	return out
}
