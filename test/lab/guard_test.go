//go:build lab

package lab

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func init() {
	extraHelpers["uarp"] = unicastARP
}

// unicastARP は「インターフェース|名乗るアドレス|相手のアドレス|相手の MAC アドレス」で、相手だけに宛てた ARP の応答を
// 3 秒の間 0.2 秒ごとに送る（端末だけに宛てたゲートウェイのなりすましの再現。スイッチは GW に転送しない）。
func unicastARP(arg string) int {
	parts := strings.Split(arg, "|")
	if len(parts) != 4 {
		return 2
	}
	ifi, err := net.InterfaceByName(parts[0])
	if err != nil {
		fmt.Println(err)
		return 1
	}
	claim, target := net.ParseIP(parts[1]).To4(), net.ParseIP(parts[2]).To4()
	hw, err := net.ParseMAC(parts[3])
	if claim == nil || target == nil || err != nil {
		return 2
	}
	pkt := make([]byte, 28)
	binary.BigEndian.PutUint16(pkt[0:], 1)      // Ethernet
	binary.BigEndian.PutUint16(pkt[2:], 0x0800) // IPv4
	pkt[4], pkt[5] = 6, 4
	binary.BigEndian.PutUint16(pkt[6:], 2) // 応答
	copy(pkt[8:14], ifi.HardwareAddr)
	copy(pkt[14:18], claim)
	copy(pkt[18:24], hw)
	copy(pkt[24:28], target)
	proto := htons(syscall.ETH_P_ARP)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(proto))
	if err != nil {
		fmt.Println(err)
		return 1
	}
	defer syscall.Close(fd)
	to := &syscall.SockaddrLinklayer{Protocol: proto, Ifindex: ifi.Index, Halen: 6}
	copy(to.Addr[:], hw)
	for range 15 {
		if err := syscall.Sendto(fd, pkt, 0, to); err != nil {
			fmt.Println(err)
			return 1
		}
		time.Sleep(200 * time.Millisecond)
	}
	return 0
}

// TestEndpointGuard は、1f-3 で v1 に残した端末の監視（2m-1）を確かめる：指示を適用しない端末の検知、端末だけに宛てた
// ARP のなりすましの検知と GW のエントリの固定、守る場所の外の大量の変更の検知、隔離中の更新サーバーの変更の反映。
func TestEndpointGuard(t *testing.T) {
	if *susanooBin == "" {
		t.Fatal("-susanoo で susanoo の実行ファイルを指定してください")
	}
	pc1 := &machine{ns: "sus-c1", id: "pc-001", agent: true, port: "p-c1"}
	pc2 := &machine{ns: "sus-c2", id: "pc-002", agent: true, port: "p-c2"}  // CLIENT の代わりに、指示を適用しないハートビートを送る
	pc3 := &machine{ns: "sus-c3", id: "pc-003", agent: false, port: "p-c3"} // なりすます機器
	machines := []*machine{pc1, pc2, pc3}
	l := &lab{t: t, dir: t.TempDir()}
	buildTopology(t, machines)
	l.setup(machines)
	// pc-001 の CLIENT は、試験用のディレクトリのファイルシステムで、守る場所の外の大量の変更を監視する。
	data := filepath.Join(l.dir, "data")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(l.dir, pc1.id+".json")
	var cfg map[string]any
	raw, err := os.ReadFile(cfgPath)
	if err != nil || json.Unmarshal(raw, &cfg) != nil {
		t.Fatalf("CLIENT の設定を読めません: %v", err)
	}
	files := cfg["files"].(map[string]any)
	files["wide"], files["wide_files"], files["mass_window"] = []string{data}, 100, "20s"
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
	agent := start(t, "CLIENT "+pc1.id, pc1.ns, nil, *susanooBin, "client", "-config", cfgPath)
	start(t, "指示を適用しない端末 "+pc2.id, pc2.ns, []string{helperEnv + "=skewhb:" + controllerAddr + "|" + filepath.Join(l.dir, pc2.id) + "|" + pc2.id + "|0"}, self)
	waitFor(t, "端末の接続", 15*time.Second, func() bool {
		d := l.devices()
		return d[pc1.id].Software != "" && !d[pc2.id].LastSeen.IsZero()
	})
	gwMAC := strings.TrimSpace(sh(t, "ip", "netns", "exec", nsGW, "cat", "/sys/class/net/lan0/address"))
	ctl := func(args ...string) string {
		t.Helper()
		out, err := inNS(nsGW, append(append([]string{*susanooBin, "ctl"}, args...), "-dir", l.ctrlDir, "-server", controllerAddr)...).CombinedOutput()
		if err != nil {
			t.Fatalf("ctl %s: %v\n%s", args[0], err, out)
		}
		return string(out)
	}

	t.Log("段階1: ハートビートを送り続けるのに指示を適用しない端末（乗っ取られた解析部の代わり）を検知する。指示を適用する端末は検知しない")
	ctl("isolate", pc2.id)
	waitFor(t, "指示の未適用の検知", 20*time.Second, func() bool { return l.devices()[pc2.id].Lagging })
	waitFor(t, "指示の未適用の検知結果", 10*time.Second, func() bool {
		return eventLine(l.events(), `"command_not_applied"`, `"uid":"`+pc2.id+`"`)
	})
	if l.devices()[pc1.id].Lagging {
		t.Error("指示を適用している端末を検知しました")
	}
	if out := ctl("status"); !strings.Contains(out, "指示を適用していない端末") || !strings.Contains(out, "  "+pc2.id+"\n") {
		t.Errorf("ctl status:\n%s", out)
	}

	t.Log("段階2: 端末だけに宛てた ARP のなりすまし（GW には届かない）を CLIENT が見つけ、GW のエントリを固定して知らせる。CONTROLLER はなりすました機器を隔離する")
	waitFor(t, "端末の ARP の表の GW のエントリ", 10*time.Second, func() bool {
		return strings.Contains(sh(t, "ip", "-n", pc1.ns, "neigh", "show", gwLAN), gwMAC)
	})
	if ok, out := runHelper(t, pc3.ns, "uarp:eth0|"+gwLAN+"|"+pc1.ip+"|"+pc1.mac); !ok {
		t.Fatalf("なりすましの ARP を送れません: %s", out)
	}
	waitFor(t, "なりすました機器の隔離", 15*time.Second, func() bool { return l.hosts()[pc3.mac].Isolation != "" })
	if h := l.hosts()[pc3.mac]; h.Reason != "ゲートウェイのなりすまし" {
		t.Errorf("なりすました機器の隔離の理由 = %q", h.Reason)
	}
	if neigh := sh(t, "ip", "-n", pc1.ns, "neigh", "show", gwLAN); !strings.Contains(neigh, gwMAC) || !strings.Contains(neigh, "PERMANENT") {
		t.Errorf("端末の ARP の表の GW のエントリを固定していません: %s", neigh)
	}
	ev := l.events()
	if !eventLine(ev, `"arp_poisoning"`, `"uid":"`+pc1.id+`"`, `"observed_mac":"`+pc3.mac+`"`) {
		t.Error("端末の ARP の表のなりすましの検知結果がありません")
	}
	if !eventLine(ev, `"gateway_spoofing"`, `"reported_by":"`+pc1.id+`"`) {
		t.Error("端末が知らせたゲートウェイのなりすましの検知結果がありません")
	}
	if d := l.devices()[pc1.id]; d.Isolation != "" {
		t.Errorf("知らせた端末を隔離しました: %s", d.Isolation)
	}

	t.Log("段階3: 守る場所の外で 1 つのプロセスが大量の既存のファイルを書き換えたら検知結果にする（試験運用なので隔離しない）。作ったばかりのファイルは数えない")
	for i := range 150 {
		if err := os.WriteFile(filepath.Join(data, fmt.Sprintf("f%03d", i)), []byte("data\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sh(t, "ip", "netns", "exec", pc1.ns, "sh", "-c", `for i in $(seq 1 150); do echo x > "$1/new$i"; done`, "sh", data)
	time.Sleep(3 * time.Second)
	if eventLine(l.events(), `"wide_mass_change"`) {
		t.Fatal("作ったばかりのファイルへの書き込みを数えました")
	}
	sh(t, "ip", "netns", "exec", pc1.ns, "sh", "-c", `for f in "$1"/f*; do echo y > "$f"; done`, "sh", data)
	waitFor(t, "守る場所の外の大量の変更の検知結果", 15*time.Second, func() bool {
		return eventLine(l.events(), `"wide_mass_change"`, `"uid":"`+pc1.id+`"`)
	})
	if d := l.devices()[pc1.id]; d.Isolation != "" {
		t.Errorf("試験運用のルールで隔離しました: %s", d.Isolation)
	}

	t.Log("段階4: 隔離中に更新サーバーを変えると、CLIENT の自己隔離にも反映する")
	push := func(version int, cidr string) {
		t.Helper()
		path := filepath.Join(l.dir, fmt.Sprintf("policy-v%d.json", version))
		writeJSON(t, path, map[string]any{
			"version": version, "name": "更新サーバーの変更", "issued_at": time.Now().UTC(), "response": "enforce", "on_failure": "fail_open",
			"groups": []map[string]any{{"name": "default", "egress": map[string]any{"default": "allow"}, "isolation": "management",
				"updates": []map[string]any{{"cidr": cidr}}}},
		})
		ctl("policy", "push", path)
	}
	clientTable := func() string {
		out, _ := inNS(pc1.ns, "nft", "list", "table", "inet", "susanoo_client").Output()
		return string(out)
	}
	push(2, "203.0.113.64/26")
	ctl("isolate", pc1.id, "-level", "management_and_updates")
	waitFor(t, "更新サーバーを許す自己隔離", 15*time.Second, func() bool { return strings.Contains(clientTable(), "203.0.113.64/26") })
	push(3, "198.51.100.0/24")
	waitFor(t, "変えた更新サーバーの自己隔離への反映", 15*time.Second, func() bool {
		tbl := clientTable()
		return strings.Contains(tbl, "198.51.100.0/24") && !strings.Contains(tbl, "203.0.113.64/26")
	})

	t.Log("段階5: CLIENT を止めると、固定した ARP の表のエントリを消す")
	agent.stop(syscall.SIGTERM)
	if neigh := sh(t, "ip", "-n", pc1.ns, "neigh", "show", gwLAN); strings.Contains(neigh, "PERMANENT") {
		t.Errorf("止めた後も固定したままです: %s", neigh)
	}
}
