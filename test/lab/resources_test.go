//go:build lab

package lab

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func init() {
	extraHelpers["skewhb"] = skewHeartbeats
}

// skewHeartbeats は「CONTROLLER のアドレス|端末の鍵のディレクトリ|端末 ID|ずらす秒数」で、端末の鍵で署名した、時刻を
// ずらしたハートビートを 1 秒ごとに送り続ける（時刻のずれた端末の代わり。名前空間では時計そのものをずらせないため）。
// 署名の形（用途と中身の前に "susanoo-sign-v1" を付けて ed25519 で署名する）は src/internal/sign と同じ。
func skewHeartbeats(arg string) int {
	parts := strings.Split(arg, "|")
	if len(parts) != 4 {
		return 2
	}
	addr, dir, id := parts[0], parts[1], parts[2]
	offset, err := strconv.Atoi(parts[3])
	if err != nil {
		return 2
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key"))
	if err != nil {
		fmt.Println(err)
		return 1
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		fmt.Println(err)
		return 1
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	priv := cert.PrivateKey.(ed25519.PrivateKey)
	sum := sha256.Sum256(priv.Public().(ed25519.PublicKey))
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert}, ServerName: "controller.susanoo.internal",
	}}}
	boot := fmt.Sprintf("skew-%d", time.Now().UnixNano())
	for n := 1; ; n++ {
		payload, _ := json.Marshal(map[string]any{
			"device_id": id, "boot_id": boot, "counter": n, "time": time.Now().Add(time.Duration(offset) * time.Second).UTC(), "hostname": id,
			"applied": 0, "capabilities": map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH, "features": []string{}},
		})
		msg := append([]byte("susanoo-sign-v1\x00heartbeat\x00"), payload...)
		env, _ := json.Marshal(map[string]any{"purpose": "heartbeat", "key_id": hex.EncodeToString(sum[:8]), "payload": payload, "signature": ed25519.Sign(priv, msg)})
		resp, err := client.Post("https://"+addr+"/v1/heartbeat", "application/json", bytes.NewReader(env))
		if err != nil {
			fmt.Println(err)
		} else {
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				fmt.Println(resp.Status, string(body))
			}
			resp.Body.Close()
		}
		time.Sleep(time.Second)
	}
}

// TestResources は、CLIENT の資源の上限（非機能の性能）と、端末の時刻のずれの検知（共通基盤の時刻）を確かめる。
func TestResources(t *testing.T) {
	if *susanooBin == "" {
		t.Fatal("-susanoo で susanoo の実行ファイルを指定してください")
	}
	pc1 := &machine{ns: "sus-c1", id: "pc-001", agent: true, port: "p-c1"}
	pc2 := &machine{ns: "sus-c2", id: "pc-002", agent: true, port: "p-c2"} // CLIENT の代わりに、時刻をずらしたハートビートを送る
	machines := []*machine{pc1, pc2}
	l := &lab{t: t, dir: t.TempDir()}
	buildTopology(t, machines)
	l.setup(machines)
	// pc-001 の CLIENT は、メモリの上限を最も小さくして、すぐに上限を超えさせる。
	cfgPath := filepath.Join(l.dir, pc1.id+".json")
	var cfg map[string]any
	data, err := os.ReadFile(cfgPath)
	if err != nil || json.Unmarshal(data, &cfg) != nil {
		t.Fatalf("CLIENT の設定を読めません: %v", err)
	}
	cfg["resources"] = map[string]any{"memory_mb": 8}
	writeJSON(t, cfgPath, cfg)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start(t, "GW", nsGW, nil, *susanooBin, "gw", "-config", filepath.Join(l.dir, "gw.json"))
	waitFor(t, "GW の起動", 10*time.Second, func() bool { return l.devices() != nil })
	for _, m := range machines {
		l.dhcp(m)
	}
	start(t, "CLIENT "+pc1.id, pc1.ns, nil, *susanooBin, "client", "-config", cfgPath)
	start(t, "時刻のずれた端末 "+pc2.id, pc2.ns, []string{helperEnv + "=skewhb:" + controllerAddr + "|" + filepath.Join(l.dir, pc2.id) + "|" + pc2.id + "|600"}, self)

	t.Log("段階1: CLIENT は資源の使用量を報告し、上限を超えたら監視を間引いて検知結果を送る（隔離はしない）")
	waitFor(t, "資源の上限による監視の間引き", 30*time.Second, func() bool {
		r := l.devices()[pc1.id].Resources
		return r != nil && r.Throttled
	})
	d := l.devices()[pc1.id]
	if r := d.Resources; r.MemoryBytes <= 8<<20 || r.CPUPercent < 0 {
		t.Errorf("報告した資源の使用量 = %+v", *r)
	}
	waitFor(t, "資源の上限の検知結果", 10*time.Second, func() bool {
		return eventLine(l.events(), `"resource_limit"`, `"uid":"`+pc1.id+`"`, `"memory_limit":8388608`)
	})
	if d.Isolation != "" {
		t.Errorf("資源の上限で隔離しました: %s", d.Isolation)
	}
	out, err := inNS(nsGW, *susanooBin, "ctl", "status", "-dir", l.ctrlDir, "-server", controllerAddr).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "資源の上限を超えて監視を間引いている端末:\n  "+pc1.id) {
		t.Errorf("ctl status（%v）:\n%s", err, out)
	}
	out, err = inNS(nsGW, *susanooBin, "ctl", "devices", "-dir", l.ctrlDir, "-server", controllerAddr).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "監視を間引き中") {
		t.Errorf("ctl devices（%v）:\n%s", err, out)
	}

	t.Log("段階2: 時刻が CONTROLLER と大きくずれている端末を検知する（隔離はしない）。時刻の合っている端末は検知しない")
	waitFor(t, "時刻のずれの検知", 20*time.Second, func() bool { return l.devices()[pc2.id].ClockSkewed })
	if off := l.devices()[pc2.id].ClockOffset; off < 590 || off > 610 {
		t.Errorf("時刻のずれ = %v 秒（600 秒のはず）", off)
	}
	waitFor(t, "時刻のずれの検知結果", 10*time.Second, func() bool {
		return eventLine(l.events(), `"clock_skew"`, `"uid":"`+pc2.id+`"`)
	})
	d1, d2 := l.devices()[pc1.id], l.devices()[pc2.id]
	if d1.ClockSkewed || math.Abs(d1.ClockOffset) > 5 {
		t.Errorf("時刻の合っている端末の時刻のずれ = %v %v", d1.ClockSkewed, d1.ClockOffset)
	}
	if d1.ClockSynced == nil {
		t.Error("CLIENT が時刻の同期の状態を報告していません")
	}
	if d2.Isolation != "" {
		t.Errorf("時刻のずれで隔離しました: %s", d2.Isolation)
	}
	var st struct {
		ClockSynced *bool    `json:"clock_synced"`
		ClockSkewed []device `json:"clock_skewed"`
	}
	if !l.ctlJSON(&st, "status") || st.ClockSynced == nil || len(st.ClockSkewed) != 1 || st.ClockSkewed[0].ID != pc2.id {
		t.Errorf("ctl status -json の時刻 = %v %+v", st.ClockSynced, st.ClockSkewed)
	}
}
