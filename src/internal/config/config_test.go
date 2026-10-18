package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

type sample struct {
	Name     string   `json:"name"`
	Interval Duration `json:"interval"`
}

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad(t *testing.T) {
	var s sample
	if err := Load(write(t, `{"name": "a", "interval": "1m30s"}`), &s); err != nil {
		t.Fatal(err)
	}
	if s.Name != "a" || time.Duration(s.Interval) != 90*time.Second {
		t.Errorf("内容が違う: %+v", s)
	}
}

func TestLoadRejects(t *testing.T) {
	for _, content := range []string{
		`{"nmae": "a"}`,
		`{"interval": 5}`,
		`{"interval": "5x"}`,
		`{"interval": "-1s"}`,
		`{} {}`,
	} {
		var s sample
		if err := Load(write(t, content), &s); err == nil {
			t.Errorf("%s を受け付けた", content)
		}
	}
}

func TestResolve(t *testing.T) {
	if got := Resolve("/etc/susanoo/client.json", "ca.crt"); got != "/etc/susanoo/ca.crt" {
		t.Errorf("相対パス: %s", got)
	}
	if got := Resolve("/etc/susanoo/client.json", "/var/lib/x"); got != "/var/lib/x" {
		t.Errorf("絶対パス: %s", got)
	}
	if got := Resolve("/etc/susanoo/client.json", ""); got != "" {
		t.Errorf("空: %s", got)
	}
}

func TestDurationOr(t *testing.T) {
	if Duration(0).Or(time.Second) != time.Second {
		t.Error("0 のとき既定値を返さない")
	}
	if Duration(time.Minute).Or(time.Second) != time.Minute {
		t.Error("指定した値を返さない")
	}
}
