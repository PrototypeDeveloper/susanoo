package main

import (
	"bytes"
	"strings"
	"testing"

	"susanoo/internal/api"
)

func TestResourceLimits(t *testing.T) {
	cpu, mem, err := resourceLimits(nil)
	if err != nil || cpu != defaultCPUPercent || mem != defaultMemoryMB<<20 {
		t.Errorf("既定値 = %v %v %v", cpu, mem, err)
	}
	cpu, mem, err = resourceLimits(&resourceConfig{CPUPercent: 25})
	if err != nil || cpu != 25 || mem != defaultMemoryMB<<20 {
		t.Errorf("CPU だけ書いたとき = %v %v %v", cpu, mem, err)
	}
	for _, bad := range []resourceConfig{{CPUPercent: -1}, {CPUPercent: maxCPUPercent + 1}, {MemoryMB: 4}, {MemoryMB: maxMemoryMB + 1}} {
		if _, _, err := resourceLimits(&bad); err == nil {
			t.Errorf("%+v を受け付けました", bad)
		}
	}
	if goMemoryLimit(512<<20) != 256<<20 || goMemoryLimit(16<<20) != minGoMemoryLimit {
		t.Errorf("Go のメモリの回収の目安 = %d %d", goMemoryLimit(512<<20), goMemoryLimit(16<<20))
	}
}

// ctl devices の状態の欄に、時刻のずれと監視の間引きを載せる。
func TestPrintDeviceStates(t *testing.T) {
	var buf bytes.Buffer
	printDevices(&buf,
		api.Device{ID: "pc-001", Group: "default", ClockSkewed: true, ClockOffset: 300, Resources: &api.ResourceUsage{Throttled: true}},
		api.Device{ID: "pc-002", Group: "default", ClockOffset: -0.5, Away: true},
	)
	out := buf.String()
	for _, want := range []string{"時刻のずれ +300.0 秒（進んでいる）、監視を間引き中", "不在"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q がありません:\n%s", want, out)
		}
	}
	if strings.Contains(out, "-0.5") {
		t.Errorf("上限を超えていない時刻のずれを載せました:\n%s", out)
	}
	if got := resourceUsage(&api.ResourceUsage{CPUPercent: 3.25, MemoryBytes: 41 << 20, Dropped: 7}); got != "CPU 3.2%、メモリ 41 MiB、間引いたイベント 7" {
		t.Errorf("resourceUsage = %q", got)
	}
}
