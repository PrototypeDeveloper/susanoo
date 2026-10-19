package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"susanoo/internal/config"
)

// systemd のユニットと利用者の定義（deploy/systemd）が、設定の例と食い違わない（2n）。
func TestDeployFiles(t *testing.T) {
	deploy := filepath.Join("..", "..", "..", "deploy", "systemd")
	examples := filepath.Join("..", "..", "..", "config")
	read := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(deploy, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	var gw gwConfig
	if err := config.Load(filepath.Join(examples, "gw.example.json"), &gw); err != nil {
		t.Fatal(err)
	}
	var client clientConfig
	if err := config.Load(filepath.Join(examples, "client.example.json"), &client); err != nil {
		t.Fatal(err)
	}
	for _, u := range []struct{ file, mode string }{{"susanoo-gw.service", "gw"}, {"susanoo-client.service", "client"}} {
		unit := read(u.file)
		m := regexp.MustCompile(`(?m)^ExecStart=/usr/local/bin/susanoo (\S+) -config (/etc/susanoo/\S+\.json)$`).FindStringSubmatch(unit)
		if m == nil || m[1] != u.mode {
			t.Errorf("%s の ExecStart が susanoo %s -config ... ではありません", u.file, u.mode)
		}
		// 起動し直しを求める終了コード（75）でも、異常終了でも起動し直す。
		if !strings.Contains(unit, "\nRestart=always\n") || !strings.Contains(unit, "\nKillMode=mixed\n") {
			t.Errorf("%s に Restart=always と KillMode=mixed がありません", u.file)
		}
	}
	// GW が書き込む場所は、ユニットで書けるようにしてある。
	gwUnit := read("susanoo-gw.service")
	for _, dir := range []string{gw.PKIDir, gw.StateDir} {
		ok := false
		for _, rw := range []string{"/etc/susanoo", "/var/lib/susanoo"} {
			if strings.HasPrefix(dir, rw+"/") && strings.Contains(gwUnit, "-"+rw) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("GW の %s がユニットの ReadWritePaths にありません", dir)
		}
	}
	// 利用者の定義は、GW の設定の例の controller_user と lan_user と同じ名前。
	users := map[string]bool{}
	for _, line := range strings.Split(read("susanoo.conf"), "\n") {
		if f := strings.Fields(line); len(f) > 1 && f[0] == "u" {
			users[f[1]] = true
		}
	}
	if !users[gw.ControllerUser] || !users[gw.LANUser] || len(users) != 2 {
		t.Errorf("利用者の定義 = %v（%s と %s のはず）", users, gw.ControllerUser, gw.LANUser)
	}
	// CLIENT のユニットの資源の上限は、設定の例の resources より大きい。
	cpu, mem, err := resourceLimits(client.Resources)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read("susanoo-client.service"), "CPUQuota=25%") || cpu >= 25 || mem >= 384<<20 {
		t.Errorf("CLIENT の資源の上限（設定 CPU %v%%、メモリ %d）がユニットより大きいです", cpu, mem>>20)
	}
}
