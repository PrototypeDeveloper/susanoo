//go:build lab

package lab

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func init() {
	extraHelpers["console"] = consoleEdit
}

// consoleEdit は「合言葉の URL|置き換える前の文字|置き換えた後の文字」で、Web コンソールに入り、設定の JSON の文字を置き換えて、
// 確かめてから保存する（ブラウザーの代わり）。合言葉のない URL で入れないことも確かめる。
func consoleEdit(arg string) int {
	parts := strings.Split(arg, "|")
	if len(parts) != 3 {
		return 2
	}
	u, err := url.Parse(parts[0])
	if err != nil {
		return 2
	}
	base := u.Scheme + "://" + u.Host
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	if resp, err := c.Get(base + "/api/config"); err != nil || resp.StatusCode != http.StatusForbidden {
		fmt.Println("合言葉なしで入れました:", err)
		return 1
	}
	resp, err := c.Get(parts[0])
	if err != nil || resp.StatusCode != http.StatusOK {
		fmt.Println("合言葉の URL で入れません:", err)
		return 1
	}
	resp.Body.Close()
	resp, err = c.Get(base + "/api/config")
	if err != nil {
		fmt.Println(err)
		return 1
	}
	var cfg struct{ Text, Hash string }
	json.NewDecoder(resp.Body).Decode(&cfg)
	resp.Body.Close()
	if !strings.Contains(cfg.Text, parts[1]) {
		fmt.Println("置き換える文字がありません:", cfg.Text)
		return 1
	}
	text := strings.Replace(cfg.Text, parts[1], parts[2], 1)
	post := func(path string, body any) map[string]any {
		data, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", base)
		resp, err := c.Do(req)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		json.Unmarshal(raw, &out)
		return out
	}
	if out := post("/api/check", map[string]string{"text": text}); out["ok"] != true || out["changed"] != true {
		fmt.Println("確かめられません:", out)
		return 1
	}
	out := post("/api/save", map[string]string{"text": text, "hash": cfg.Hash})
	if out["ok"] != true {
		fmt.Println("保存できません:", out)
		return 1
	}
	fmt.Println("保存しました:", out["backup"])
	return 0
}

// TestConsole は、設定を編集する Web コンソール（2p）を確かめる：ループバックだけで待ち受け、合言葉の URL で入ったときだけ、
// 設定を確かめて控えを残して保存できること。
func TestConsole(t *testing.T) {
	if *susanooBin == "" {
		t.Fatal("-susanoo で susanoo の実行ファイルを指定してください")
	}
	pc1 := &machine{ns: "sus-c1", id: "pc-001", port: "p-c1"}
	machines := []*machine{pc1}
	l := &lab{t: t, dir: t.TempDir()}
	buildTopology(t, machines)
	l.setup(machines)
	gwConfig := filepath.Join(l.dir, "gw.json")
	start(t, "GW", nsGW, nil, *susanooBin, "gw", "-config", gwConfig)
	waitFor(t, "GW の起動", 10*time.Second, func() bool { return l.devices() != nil })
	l.dhcp(pc1)

	t.Log("段階1: Web コンソールはループバックのアドレスだけで待ち受け、LAN からは接続できない")
	if out, err := inNS(nsGW, *susanooBin, "console", "-config", gwConfig, "-listen", gwLAN+":18485").CombinedOutput(); err == nil || !strings.Contains(string(out), "ループバック") {
		t.Errorf("LAN のアドレスで起動しました（%v）:\n%s", err, out)
	}
	console := start(t, "Web コンソール", nsGW, nil, *susanooBin, "console", "-config", gwConfig, "-listen", "127.0.0.1:18484", "-service", "none")
	var link string
	waitFor(t, "Web コンソールの起動", 10*time.Second, func() bool {
		link = regexp.MustCompile(`http://127\.0\.0\.1:18484/\?token=[A-Z0-9]+`).FindString(console.log.String())
		return link != ""
	})
	if dialFrom(t, pc1.ns, gwLAN+":18484") {
		t.Error("LAN から Web コンソールに接続できました")
	}

	t.Log("段階2: 合言葉の URL で入ると、設定を確かめてから、前の設定を控えに残して保存できる（合言葉なしでは入れない）")
	before, err := os.ReadFile(gwConfig)
	if err != nil {
		t.Fatal(err)
	}
	if ok, out := runHelper(t, nsGW, "console:"+link+`|"heartbeat_timeout": "4s"|"heartbeat_timeout": "5s"`); !ok {
		t.Fatalf("Web コンソールで保存できません: %s", out)
	}
	after, _ := os.ReadFile(gwConfig)
	if !strings.Contains(string(after), `"heartbeat_timeout": "5s"`) {
		t.Errorf("保存した設定:\n%s", after)
	}
	backups, _ := filepath.Glob(gwConfig + ".*.bak")
	if len(backups) != 1 {
		t.Fatalf("控え = %v", backups)
	}
	if data, _ := os.ReadFile(backups[0]); !bytes.Equal(data, before) {
		t.Error("控えが前の設定と違います")
	}
	if !strings.Contains(console.log.String(), "Web コンソールで設定ファイルを保存しました") {
		t.Errorf("Web コンソールのログ:\n%s", console.log.String())
	}
}
