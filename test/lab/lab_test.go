//go:build lab

// Package lab は、ネットワーク名前空間の検証環境で susanoo を動かす結合試験。
//
// root 権限が必要で、「make lab-test」で使い捨てのネットワーク名前空間とマウント名前空間の中から起動する。
// ホストのネットワークに触れないよう、ホストの名前空間で起動されたら何もせずに終了する。
// 検証環境は veth だけでつなぎ、実際のNICとはつながず、外への経路も持たない。
//
//	sus-inet（疑似インターネット 203.0.113.2。LAN への経路はなく、GW の NAT がないと応答できない）
//	   │
//	sus-gw（GW と CONTROLLER。ルーター方式、DHCP サーバー。WAN 203.0.113.1、LAN 10.77.0.1）
//	   │
//	sus-sw（スイッチ）
//	   ├─ sus-c1（端末 pc-001。DHCP でアドレスを得る）
//	   ├─ sus-c2（端末 pc-002）
//	   ├─ sus-c3（端末 pc-003。LAN から離れて戻る）
//	   └─ sus-c4（CLIENT のない機器 pc-004。ゲートウェイを名乗る）
package lab

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var susanooBin = flag.String("susanoo", "", "susanoo の実行ファイル（絶対パス）")

// helperEnv が設定されていると、試験の実行ファイルは補助のプログラムとして動く。
const helperEnv = "SUSANOO_LAB_HELPER"

const (
	nsInet = "sus-inet"
	nsGW   = "sus-gw"
	nsSW   = "sus-sw"

	gwLAN          = "10.77.0.1"
	controllerAddr = "10.77.0.1:8443"
	serverAddr     = "203.0.113.2:8080"

	// GW の CONTROLLER と LAN 側の処理を動かす UID。ホストの /etc/passwd を変えないよう、利用者を作らずに
	// 番号で指定する（65000〜65533 は予約されていて、ふつうは使われない）。
	gwControllerUID = "65001"
	gwLANUID        = "65002"
	// GW と CLIENT の執行部に残す capability（/proc/<pid>/status の CapEff の形）。
	gwExecutorCaps     = "0000000000001000" // CAP_NET_ADMIN
	clientExecutorCaps = "0000000000281004" // CAP_DAC_READ_SEARCH、CAP_NET_ADMIN、CAP_SYS_PTRACE、CAP_SYS_ADMIN
)

// この試験は src/internal のパッケージを使わず、susanoo の実行ファイルだけを外から操作する。
// ctl の JSON の出力のうち、確かめる項目だけをここで定める。

type device struct {
	ID         string    `json:"id"`
	MACs       []string  `json:"macs"`
	Isolation  string    `json:"isolation"`
	Applied    string    `json:"applied"`
	Reason     string    `json:"reason"`
	Away       bool      `json:"away"`
	Features   []string  `json:"features"`
	LastSeen   time.Time `json:"last_seen"`
	CertExpiry time.Time `json:"cert_expiry"`
	Revoked    time.Time `json:"revoked"`
	AppControl string    `json:"app_control"`
	Software   string    `json:"software"`
	Resources  *struct {
		CPUPercent  float64 `json:"cpu_percent"`
		MemoryBytes int64   `json:"memory_bytes"`
		Throttled   bool    `json:"throttled"`
	} `json:"resources"`
	ClockOffset float64 `json:"clock_offset"`
	ClockSkewed bool    `json:"clock_skewed"`
	ClockSynced *bool   `json:"clock_synced"`
}

type host struct {
	MAC       string   `json:"mac"`
	IP        string   `json:"ip"`
	Hostname  string   `json:"hostname"`
	DeviceID  string   `json:"device_id"`
	Isolation string   `json:"isolation"`
	Reason    string   `json:"reason"`
	Risk      int      `json:"risk"`
	IPv6      []string `json:"ipv6"`
}

type auditRecord struct {
	Action string `json:"action"`
	Target string `json:"target"`
}

// machine は検証環境の端末。
type machine struct {
	ns    string // 名前空間
	id    string // 端末 ID（ホスト名としても使う）
	agent bool   // CLIENT を動かすか
	port  string // スイッチ側の veth の名前
	mac   string
	ip    string
}

func TestMain(m *testing.M) {
	if spec := os.Getenv(helperEnv); spec != "" {
		os.Exit(helper(spec))
	}
	flag.Parse()
	if err := guard(); err != nil {
		fmt.Fprintln(os.Stderr, "lab:", err)
		os.Exit(2)
	}
	if err := privateRun(); err != nil {
		fmt.Fprintln(os.Stderr, "lab:", err)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

// guard は、ホストの名前空間で起動されていないことを確かめる。
func guard() error {
	if os.Geteuid() != 0 {
		return errors.New("root 権限で実行してください（make lab-test）")
	}
	for _, ns := range []struct{ name, label string }{{"net", "ネットワーク"}, {"mnt", "マウント"}} {
		self, err := os.Readlink("/proc/self/ns/" + ns.name)
		if err != nil {
			return err
		}
		host, err := os.Readlink("/proc/1/ns/" + ns.name)
		if err != nil {
			return err
		}
		if self == host {
			return fmt.Errorf("ホストの%s名前空間で起動されました。ホストに触れないよう、何もせずに終了します（make lab-test で実行してください）", ns.label)
		}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, i := range ifaces {
		if i.Name != "lo" {
			return fmt.Errorf("ループバック以外のインターフェース %s が見えます。空のネットワーク名前空間で実行してください", i.Name)
		}
	}
	return nil
}

// privateRun は /run に一時的なファイルシステムを重ね、ip netns の登録がホストに残らないようにする。
func privateRun() error {
	if err := syscall.Mount("tmpfs", "/run", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=0755"); err != nil {
		return fmt.Errorf("/run に tmpfs を重ねられません: %w", err)
	}
	return os.MkdirAll("/run/netns", 0o755)
}

// helper は名前空間の中で動く補助のプログラム。
//
//	serve:アドレス                 試験用のサーバー
//	dial:アドレス                  接続できれば 0 で終了する
//	garp:インターフェース:アドレス  そのアドレスを名乗る ARP を送る（なりすましの再現）
func helper(spec string) int {
	kind, arg, _ := strings.Cut(spec, ":")
	switch kind {
	case "serve":
		ln, err := net.Listen("tcp", arg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		for {
			c, err := ln.Accept()
			if err != nil {
				return 1
			}
			c.Write([]byte("ok\n"))
			c.Close()
		}
	case "dial":
		c, err := net.DialTimeout("tcp", arg, 2*time.Second)
		if err != nil {
			return 1
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 3)
		if n, _ := c.Read(buf); string(buf[:n]) != "ok\n" {
			return 1
		}
		return 0
	case "garp":
		iface, ip, _ := strings.Cut(arg, ":")
		if err := sendGratuitousARP(iface, net.ParseIP(ip).To4()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if h, ok := extraHelpers[kind]; ok {
		return h(arg)
	}
	return 2
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// sendGratuitousARP は、ip を名乗る ARP の応答をブロードキャストする。
func sendGratuitousARP(iface string, ip net.IP) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	if ip == nil {
		return errors.New("アドレスが不正です")
	}
	pkt := make([]byte, 28)
	binary.BigEndian.PutUint16(pkt[0:], 1)      // Ethernet
	binary.BigEndian.PutUint16(pkt[2:], 0x0800) // IPv4
	pkt[4], pkt[5] = 6, 4
	binary.BigEndian.PutUint16(pkt[6:], 2) // 応答
	copy(pkt[8:14], ifi.HardwareAddr)
	copy(pkt[14:18], ip)
	copy(pkt[18:24], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(pkt[24:28], ip)
	proto := htons(syscall.ETH_P_ARP)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(proto))
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	to := &syscall.SockaddrLinklayer{Protocol: proto, Ifindex: ifi.Index, Halen: 6, Addr: [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}
	for range 3 {
		if err := syscall.Sendto(fd, pkt, 0, to); err != nil {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

// sendARPRequests は、送信元 from として、targets のアドレスを探す ARP の要求をブロードキャストする。
func sendARPRequests(iface string, from net.IP, targets []net.IP) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	proto := htons(syscall.ETH_P_ARP)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(proto))
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	to := &syscall.SockaddrLinklayer{Protocol: proto, Ifindex: ifi.Index, Halen: 6, Addr: [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}
	for _, target := range targets {
		pkt := make([]byte, 28)
		binary.BigEndian.PutUint16(pkt[0:], 1)      // Ethernet
		binary.BigEndian.PutUint16(pkt[2:], 0x0800) // IPv4
		pkt[4], pkt[5] = 6, 4
		binary.BigEndian.PutUint16(pkt[6:], 1) // 要求
		copy(pkt[8:14], ifi.HardwareAddr)
		copy(pkt[14:18], from)
		copy(pkt[24:28], target)
		if err := syscall.Sendto(fd, pkt, 0, to); err != nil {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil
}

func sh(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func ip(t *testing.T, args ...string) string { t.Helper(); return sh(t, "ip", args...) }

func inNS(ns string, args ...string) *exec.Cmd {
	return exec.Command("ip", append([]string{"netns", "exec", ns}, args...)...)
}

// udhcpcScript は busybox udhcpc が得たアドレスを設定するだけのスクリプト。
// DNS の設定（/etc/resolv.conf）は書き換えない。
const udhcpcScript = `#!/bin/sh
case "$1" in
  bound|renew)
    ip addr flush dev "$interface"
    ip addr add "$ip/${mask:-24}" dev "$interface"
    [ -n "$router" ] && ip route replace default via "$router" dev "$interface"
    ;;
esac
exit 0
`

// buildTopology は検証環境のネットワークを作る。veth はすべて名前空間の中に作る。
// 疑似インターネットには LAN への経路を設定しない（GW の NAT が必要）。
func buildTopology(t *testing.T, machines []*machine, extraInet ...string) {
	t.Helper()
	buildTopologyWith(t, machines, false, extraInet...)
}

// buildTopology6 は buildTopology と同じだが、IPv6 を止めない（リンクローカルのアドレスを使う試験のため）。
// 重複の確認を省いてアドレスをすぐに使えるようにし、スイッチはマルチキャストをすべてのポートに流す。
func buildTopology6(t *testing.T, machines []*machine) {
	t.Helper()
	buildTopologyWith(t, machines, true)
}

func buildTopologyWith(t *testing.T, machines []*machine, ipv6 bool, extraInet ...string) {
	t.Helper()
	all := []string{nsInet, nsGW, nsSW}
	for _, m := range machines {
		all = append(all, m.ns)
	}
	for _, ns := range all {
		ip(t, "netns", "add", ns)
		ip(t, "-n", ns, "link", "set", "lo", "up")
		// IPv6 を使う試験でも、スイッチでは止める（スイッチのポートが LAN の機器として見えないように）。
		if ipv6 && ns != nsSW {
			sh(t, "ip", "netns", "exec", ns, "sysctl", "-qw", "net.ipv6.conf.all.accept_dad=0", "net.ipv6.conf.default.accept_dad=0")
		} else {
			sh(t, "ip", "netns", "exec", ns, "sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1")
		}
	}
	t.Cleanup(func() {
		for _, ns := range all {
			exec.Command("ip", "netns", "del", ns).Run()
		}
	})
	ip(t, "-n", nsGW, "link", "add", "wan0", "type", "veth", "peer", "name", "eth0", "netns", nsInet)
	ip(t, "-n", nsGW, "link", "add", "lan0", "type", "veth", "peer", "name", "p-gw", "netns", nsSW)
	ip(t, "-n", nsSW, "link", "add", "br0", "type", "bridge")
	if ipv6 {
		ip(t, "-n", nsSW, "link", "set", "br0", "type", "bridge", "mcast_snooping", "0")
	}
	ports := []string{"p-gw"}
	for _, m := range machines {
		ip(t, "-n", m.ns, "link", "add", "eth0", "type", "veth", "peer", "name", m.port, "netns", nsSW)
		ip(t, "-n", m.ns, "link", "set", "eth0", "up")
		ports = append(ports, m.port)
	}
	for _, p := range ports {
		ip(t, "-n", nsSW, "link", "set", p, "master", "br0")
		ip(t, "-n", nsSW, "link", "set", p, "up")
	}
	ip(t, "-n", nsSW, "link", "set", "br0", "up")
	for _, a := range []struct{ ns, dev, addr string }{
		{nsInet, "eth0", "203.0.113.2/24"},
		{nsGW, "wan0", "203.0.113.1/24"},
		{nsGW, "lan0", gwLAN + "/24"},
	} {
		ip(t, "-n", a.ns, "addr", "add", a.addr, "dev", a.dev)
		ip(t, "-n", a.ns, "link", "set", a.dev, "up")
	}
	for _, a := range extraInet {
		ip(t, "-n", nsInet, "addr", "add", a, "dev", "eth0")
	}
	for _, m := range machines {
		m.mac = regexp.MustCompile(`link/ether ([0-9a-f:]{17})`).FindStringSubmatch(ip(t, "-n", m.ns, "-o", "link", "show", "dev", "eth0"))[1]
	}
}

// dhcp は端末で busybox udhcpc を動かし、GW の DHCP サーバーからアドレスを得る。
func (l *lab) dhcp(m *machine) {
	t := l.t
	t.Helper()
	out, err := inNS(m.ns, "busybox", "udhcpc", "-i", "eth0", "-f", "-q", "-n", "-t", "5", "-T", "1",
		"-s", l.script, "-x", "hostname:"+m.id).CombinedOutput()
	if err != nil {
		t.Fatalf("%s が DHCP でアドレスを得られません: %v\n%s", m.id, err, out)
	}
	m.ip = l.addrOf(m.ns)
	if m.ip == "" {
		t.Fatalf("%s にアドレスが設定されていません\n%s", m.id, out)
	}
}

func (l *lab) addrOf(ns string) string {
	out := ip(l.t, "-n", ns, "-4", "-o", "addr", "show", "dev", "eth0")
	if m := regexp.MustCompile(`inet ([0-9.]+)/`).FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type proc struct {
	name string
	cmd  *exec.Cmd
	log  *syncBuffer
	done chan struct{}
}

// start は名前空間 ns の中でプログラムを起動する。試験の終わりに止め、失敗していればログを表示する。
func start(t *testing.T, name, ns string, env []string, args ...string) *proc {
	t.Helper()
	p := &proc{name: name, cmd: inNS(ns, args...), log: &syncBuffer{}, done: make(chan struct{})}
	p.cmd.Env = append(os.Environ(), env...)
	p.cmd.Stdout, p.cmd.Stderr = p.log, p.log
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.cmd.Wait(); close(p.done) }()
	t.Cleanup(func() {
		p.stop(syscall.SIGTERM)
		if t.Failed() {
			t.Logf("---- %s のログ ----\n%s", p.name, p.log.String())
		}
	})
	return p
}

func (p *proc) stop(sig syscall.Signal) {
	select {
	case <-p.done:
		return
	default:
	}
	p.cmd.Process.Signal(sig)
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		p.cmd.Process.Kill()
		<-p.done
	}
}

// reachable は名前空間 ns から試験用のサーバーに接続できるかを返す。
func reachable(t *testing.T, ns string) bool {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := inNS(ns, self)
	cmd.Env = append(os.Environ(), helperEnv+"=dial:"+serverAddr)
	return cmd.Run() == nil
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s を待ちきれません", what)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

type lab struct {
	t        *testing.T
	dir      string
	ctrlDir  string
	adminDir string // 管理者の証明書のディレクトリ（空なら ctrlDir。二段構えではルートのディレクトリ）
	script   string
}

// admin は ctl の -dir に渡す、管理者の証明書のディレクトリを返す。
func (l *lab) admin() string {
	if l.adminDir != "" {
		return l.adminDir
	}
	return l.ctrlDir
}

func (l *lab) susanoo(args ...string) string {
	l.t.Helper()
	return sh(l.t, *susanooBin, args...)
}

// ctlJSON は GW の名前空間から ctl を実行し、JSON の出力を v に読む。
func (l *lab) ctlJSON(v any, args ...string) bool {
	args = append(append([]string{*susanooBin, "ctl"}, args...), "-dir", l.admin(), "-server", controllerAddr, "-json")
	out, err := inNS(nsGW, args...).Output()
	return err == nil && json.Unmarshal(out, v) == nil
}

func (l *lab) devices() map[string]device {
	var list []device
	if !l.ctlJSON(&list, "devices") {
		return nil
	}
	m := map[string]device{}
	for _, d := range list {
		m[d.ID] = d
	}
	return m
}

func (l *lab) hosts() map[string]host {
	var list []host
	if !l.ctlJSON(&list, "hosts") {
		return nil
	}
	m := map[string]host{}
	for _, h := range list {
		m[h.MAC] = h
	}
	return m
}

// init は CONTROLLER の鍵と、DHCP のスクリプトを用意する。
func (l *lab) init() {
	for _, uid := range []string{gwControllerUID, gwLANUID} {
		if _, err := user.LookupId(uid); err == nil {
			l.t.Fatalf("UID %s はこのホストで使われています。試験の gwControllerUID と gwLANUID を変えてください", uid)
		}
	}
	// GW の非特権のプロセスが状態のディレクトリまで辿れるよう、試験の作業ディレクトリ（root の 0700）を
	// 辿れるだけにする（中身の一覧は見せない）。実際の環境の /var/lib は 0755 なので要らない。
	for _, d := range []string{filepath.Dir(l.dir), l.dir} {
		if err := os.Chmod(d, 0o711); err != nil {
			l.t.Fatal(err)
		}
	}
	l.ctrlDir = filepath.Join(l.dir, "controller")
	l.script = filepath.Join(l.dir, "udhcpc.sh")
	if err := os.WriteFile(l.script, []byte(udhcpcScript), 0o755); err != nil {
		l.t.Fatal(err)
	}
	l.susanoo("ctl", "init", "-dir", l.ctrlDir)
}

// writeGW はポリシーの groups と、GW の設定（基本の設定に extra を足したもの）を書く。
func (l *lab) writeGW(groups []map[string]any, extra map[string]any) {
	writeJSON(l.t, filepath.Join(l.dir, "policy.json"), map[string]any{
		"version": 1, "name": "検証環境", "issued_at": time.Now().UTC(), "response": "enforce", "on_failure": "fail_open", "groups": groups,
	})
	gw := map[string]any{
		"listen": controllerAddr, "pki_dir": "controller", "state_dir": "gw-state", "policy": "policy.json", "heartbeat_timeout": "4s",
		"controller_user": gwControllerUID, "lan_user": gwLANUID,
		"router": map[string]any{"lan": "lan0", "wan": "wan0", "admin_ports": []int{}},
		"dhcp":   map[string]any{"range": "10.77.0.100-10.77.0.199", "lease_time": "10m"},
	}
	for k, v := range extra {
		gw[k] = v
	}
	writeJSON(l.t, filepath.Join(l.dir, "gw.json"), gw)
}

func (l *lab) setup(machines []*machine) {
	t := l.t
	l.init()
	l.writeGW([]map[string]any{{"name": "default", "egress": map[string]any{"default": "allow"}, "isolation": "management"}}, nil)
	for _, m := range machines {
		if !m.agent {
			continue
		}
		keyDir := filepath.Join(l.dir, m.id)
		l.susanoo("client", "keygen", "-dir", keyDir)
		l.susanoo("ctl", "issue", "-dir", l.ctrlDir, "-id", m.id, "-pub", filepath.Join(keyDir, "client.pub"), "-out", keyDir)
		// ファイルとカーネルモジュールの監視は TestClient で確かめる。ここでは使わない（既定の場所は実際の /etc とホームのため）。
		writeJSON(t, filepath.Join(l.dir, m.id+".json"), map[string]any{
			"controller": controllerAddr, "pki_dir": m.id, "state_dir": m.id + "-state", "heartbeat_interval": "1s",
			"honeytokens": []map[string]string{{"path": l.token(m.id), "kind": "aws"}},
			"files": map[string]any{"watch": []string{}, "persistence": []string{}, "privilege": []string{},
				"sensitive": []map[string]any{}, "protect": []string{}},
			"kernel_modules": false, "logons": map[string]any{"enabled": false},
		})
	}
}

func (l *lab) token(id string) string { return filepath.Join(l.dir, id+"-home", ".aws", "credentials") }

// auditActions は ctl audit で監査ログの連鎖を確かめ、記録された操作を返す。
func (l *lab) auditActions() []string {
	out := l.susanoo("ctl", "audit", "-file", filepath.Join(l.dir, "gw-state", "controller", "audit.log"), "-json")
	var records []auditRecord
	if err := json.Unmarshal([]byte(out), &records); err != nil {
		l.t.Fatalf("ctl audit の出力を解析できません: %v\n%s", err, out)
	}
	var actions []string
	for _, r := range records {
		actions = append(actions, r.Action+":"+r.Target)
	}
	return actions
}

func (l *lab) nftSet(name string) string {
	return sh(l.t, "ip", "netns", "exec", nsGW, "nft", "list", "set", "inet", "susanoo_gw", name)
}

// TestGateway はフェーズ1のゲート「検証環境で、検知から隔離までが自動で動く」を、
// ルーター方式の GW、DHCP、LAN の機器の台帳とあわせて確かめる。
func TestGateway(t *testing.T) {
	if *susanooBin == "" {
		t.Fatal("-susanoo で susanoo の実行ファイルを指定してください")
	}
	pc1 := &machine{ns: "sus-c1", id: "pc-001", agent: true, port: "p-c1"}
	pc2 := &machine{ns: "sus-c2", id: "pc-002", agent: true, port: "p-c2"}
	pc3 := &machine{ns: "sus-c3", id: "pc-003", agent: true, port: "p-c3"}
	pc4 := &machine{ns: "sus-c4", id: "pc-004", agent: false, port: "p-c4"}
	machines := []*machine{pc1, pc2, pc3, pc4}

	l := &lab{t: t, dir: t.TempDir()}
	buildTopology(t, machines)
	l.setup(machines)

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start(t, "試験用サーバー", nsInet, []string{helperEnv + "=serve:" + serverAddr}, self)
	gwProc := start(t, "GW", nsGW, nil, *susanooBin, "gw", "-config", filepath.Join(l.dir, "gw.json"))
	waitFor(t, "GW の起動", 10*time.Second, func() bool { return l.devices() != nil })
	t.Log("段階0: GW は権限を分けて動く。執行部は CAP_NET_ADMIN だけを持ち、CONTROLLER と LAN 側の処理は別々の UID で capability を持たない")
	checkPrivsep(t, gwProc.cmd.Process.Pid, gwExecutorCaps, map[string]string{"gw\x00controller": gwControllerUID, "gw\x00lan": gwLANUID})

	agents := map[string]*proc{}
	for _, m := range machines {
		l.dhcp(m)
		if m.agent {
			agents[m.id] = start(t, "CLIENT "+m.id, m.ns, nil, *susanooBin, "client", "-config", filepath.Join(l.dir, m.id+".json"))
		}
	}
	waitFor(t, "端末の登録と機器との結び付き", 15*time.Second, func() bool {
		d := l.devices()
		for _, m := range machines {
			if m.agent && (!slices.Contains(d[m.id].MACs, m.mac) || !slices.Contains(d[m.id].Features, "honeytoken")) {
				return false
			}
		}
		return true
	})

	t.Log("段階1: DHCP でアドレスを得て、GW の NAT 経由で外部に接続できる。CLIENT のない機器は未登録として台帳に載る")
	hosts := l.hosts()
	for _, m := range machines {
		h, ok := hosts[m.mac]
		if !ok || h.IP != m.ip || h.Hostname != m.id {
			t.Errorf("%s の台帳 = %+v（アドレス %s）", m.id, h, m.ip)
		}
		if want := map[bool]string{true: m.id, false: ""}[m.agent]; h.DeviceID != want {
			t.Errorf("%s の端末との結び付き = %q, 期待値 %q", m.id, h.DeviceID, want)
		}
		if !strings.HasPrefix(m.ip, "10.77.0.1") {
			t.Errorf("%s のアドレス %s が DHCP の範囲の外", m.id, m.ip)
		}
		if !reachable(t, m.ns) {
			t.Errorf("%s が外部に接続できません", m.id)
		}
	}
	if t.Failed() {
		t.FailNow()
	}

	t.Log("段階2: pc-001 のおとりを読むと隔離され、端末側のルールを消してアドレスを変えても、MAC アドレスで止まる")
	if _, err := os.ReadFile(l.token(pc1.id)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "pc-001 の隔離と自己隔離の適用", 10*time.Second, func() bool {
		d := l.devices()[pc1.id]
		return d.Isolation == "management" && d.Applied == "management"
	})
	if set := l.nftSet("isolate_management_mac"); !strings.Contains(set, pc1.mac) {
		t.Errorf("GW の遮断の集合に pc-001 の MAC アドレスがありません\n%s", set)
	}
	if reachable(t, pc1.ns) {
		t.Error("隔離した pc-001 が外部に接続できます")
	}
	sh(t, "ip", "netns", "exec", pc1.ns, "nft", "delete", "table", "inet", "susanoo_client")
	ip(t, "-n", pc1.ns, "addr", "flush", "dev", "eth0")
	ip(t, "-n", pc1.ns, "addr", "add", "10.77.0.250/24", "dev", "eth0")
	ip(t, "-n", pc1.ns, "route", "replace", "default", "via", gwLAN)
	if reachable(t, pc1.ns) {
		t.Error("端末側のルールを消してアドレスを変えると、隔離した pc-001 が外部に接続できます")
	}
	if !reachable(t, pc2.ns) {
		t.Error("隔離していない pc-002 が外部に接続できません")
	}

	t.Log("段階3: LAN にいる pc-002 のエージェントを強制終了すると、ハートビートの途絶で隔離される")
	agents[pc2.id].stop(syscall.SIGKILL)
	waitFor(t, "pc-002 の隔離", 15*time.Second, func() bool {
		d := l.devices()[pc2.id]
		return d.Isolation == "management" && d.Reason == "ハートビートの途絶"
	})
	if reachable(t, pc2.ns) {
		t.Error("ハートビートが途絶えた pc-002 が外部に接続できます")
	}

	t.Log("段階4: pc-003 が LAN から離れると不在になり隔離されず、戻ると元どおり使える")
	ip(t, "-n", pc3.ns, "link", "set", "eth0", "down")
	waitFor(t, "pc-003 の不在", 15*time.Second, func() bool { return l.devices()[pc3.id].Away })
	if d := l.devices()[pc3.id]; d.Isolation != "" {
		t.Errorf("LAN から離れた pc-003 を隔離しました: %+v", d)
	}
	ip(t, "-n", pc3.ns, "link", "set", "eth0", "up")
	ip(t, "-n", pc3.ns, "route", "replace", "default", "via", gwLAN)
	waitFor(t, "pc-003 の復帰", 30*time.Second, func() bool {
		d := l.devices()[pc3.id]
		return !d.Away && d.Isolation == ""
	})
	time.Sleep(5 * time.Second) // ハートビートの途絶の判定時間（4 秒）を超えても隔離されないこと
	if d := l.devices()[pc3.id]; d.Isolation != "" || d.Away {
		t.Errorf("戻った pc-003 = %+v", d)
	}
	if !reachable(t, pc3.ns) {
		t.Error("戻った pc-003 が外部に接続できません")
	}

	t.Log("段階5: 管理者が pc-001 の隔離を解除すると外部に接続できる。ここまでの隔離と解除が監査ログに記録されている")
	sh(t, "ip", "netns", "exec", nsGW, *susanooBin, "ctl", "release", pc1.id, "-dir", l.ctrlDir, "-server", controllerAddr)
	waitFor(t, "pc-001 の解除の適用", 15*time.Second, func() bool {
		d := l.devices()[pc1.id]
		return d.Isolation == "" && d.Applied == ""
	})
	waitFor(t, "pc-001 の外部への接続", 10*time.Second, func() bool { return reachable(t, pc1.ns) })
	actions := l.auditActions()
	for _, want := range []string{"device.isolate:" + pc1.id, "device.isolate:" + pc2.id, "device.release:" + pc1.id} {
		if !slices.Contains(actions, want) {
			t.Errorf("監査ログに %s がありません: %v", want, actions)
		}
	}
	if slices.Contains(actions, "device.isolate:"+pc3.id) {
		t.Errorf("不在だった pc-003 の隔離が記録されています: %v", actions)
	}

	// ゲートウェイを名乗る ARP はブロードキャストされ、ほかの端末の ARP の情報も書き換える（攻撃の影響）。
	// そのため、ほかの端末についての確認はここまでに済ませる。
	t.Log("段階6: CLIENT のない pc-004 がゲートウェイのアドレスを名乗ると、MAC アドレスで遮断される")
	garp := inNS(pc4.ns, self)
	garp.Env = append(os.Environ(), helperEnv+"=garp:eth0:"+gwLAN)
	if out, err := garp.CombinedOutput(); err != nil {
		t.Fatalf("なりすましの ARP を送れません: %v\n%s", err, out)
	}
	waitFor(t, "pc-004 の隔離", 10*time.Second, func() bool {
		h := l.hosts()[pc4.mac]
		return h.Isolation == "management" && h.Reason == "ゲートウェイのなりすまし"
	})
	if set := l.nftSet("isolate_management_mac"); !strings.Contains(set, pc4.mac) {
		t.Errorf("GW の遮断の集合に pc-004 の MAC アドレスがありません\n%s", set)
	}
	if reachable(t, pc4.ns) {
		t.Error("なりすました pc-004 が外部に接続できます")
	}

	t.Log("段階7: 監査ログの連鎖が正しく、機器の隔離が記録されている")
	if actions := l.auditActions(); !slices.Contains(actions, "host.isolate:"+pc4.mac) {
		t.Errorf("監査ログに host.isolate:%s がありません: %v", pc4.mac, actions)
	}

	t.Log("段階8: 管理者が pc-003 の証明書を失効させると、全遮断で隔離され、その証明書では CONTROLLER と通信できない")
	sh(t, "ip", "netns", "exec", nsGW, *susanooBin, "ctl", "revoke", pc3.id, "-dir", l.ctrlDir, "-server", controllerAddr)
	revokedAt := time.Now()
	waitFor(t, "失効による隔離", 10*time.Second, func() bool {
		d := l.devices()[pc3.id]
		return d.Isolation == "full" && d.Reason == "証明書の失効" && !d.Revoked.IsZero()
	})
	if set := l.nftSet("isolate_full_mac"); !strings.Contains(set, pc3.mac) {
		t.Errorf("GW の遮断の集合に pc-003 の MAC アドレスがありません\n%s", set)
	}
	time.Sleep(3 * time.Second) // ハートビートの間隔（1 秒）の 3 倍待っても、最終接続が進まない
	if d := l.devices()[pc3.id]; d.LastSeen.After(revokedAt.Add(time.Second)) {
		t.Errorf("失効させた後もハートビートを受け付けています（最終接続 %v、失効 %v）", d.LastSeen, revokedAt)
	}
	if actions := l.auditActions(); !slices.Contains(actions, "device.revoke:"+pc3.id) {
		t.Errorf("監査ログに device.revoke:%s がありません: %v", pc3.id, actions)
	}

	t.Log("段階9: 全体の状態に端末と機器の台数と最近の検知が載り、保存したイベントを端末と種類で検索できる")
	var st struct {
		Devices struct {
			Total, Isolated, Revoked int
		} `json:"devices"`
		Hosts struct {
			Unregistered, Isolated int
		} `json:"hosts"`
		RecentFindings []json.RawMessage `json:"recent_findings"`
	}
	if !l.ctlJSON(&st, "status") {
		t.Fatal("ctl status に失敗しました")
	}
	// pc-002（途絶）と pc-003（失効）が隔離中。pc-001 も、段階 6 のなりすましで GW 宛ての通信を横取りされて
	// ハートビートが途絶え、隔離されることがある。pc-004 は CLIENT のない機器で、なりすましで隔離した。
	d := l.devices()
	if st.Devices.Total != 3 || st.Devices.Isolated < 2 || d[pc2.id].Isolation == "" || d[pc3.id].Isolation == "" || st.Devices.Revoked != 1 ||
		st.Hosts.Unregistered < 1 || st.Hosts.Isolated != 1 || len(st.RecentFindings) == 0 {
		t.Errorf("全体の状態: 端末 %+v、機器 %+v、最近の検知 %d 件", st.Devices, st.Hosts, len(st.RecentFindings))
	}
	out := sh(t, "ip", "netns", "exec", nsGW, *susanooBin, "ctl", "events", "-device", pc1.id, "-class", "finding", "-json", "-dir", l.ctrlDir, "-server", controllerAddr)
	if !strings.Contains(out, `"honeytoken"`) || strings.Contains(out, `"uid":"`+pc2.id+`"`) {
		t.Errorf("pc-001 の検知の検索結果（先頭）= %.500s", out)
	}
}

// checkPrivsep は、権限を分けたプロセスを /proc で確かめる。pid は起動したプロセス（ip netns exec がそのまま
// susanoo になる）。執行部は capability が wantCaps だけで no_new_privs が立つ。執行部の子の非特権のプロセスは、
// コマンドラインに children のキーを含むものが、それぞれ値の UID で動き、capability と補助グループを持たない。
func checkPrivsep(t *testing.T, pid int, wantCaps string, children map[string]string) {
	t.Helper()
	executor := pid
	if procStatus(pid)["Name"] != "susanoo" {
		executor = childNamed(pid, "susanoo", "")
	}
	st := procStatus(executor)
	if st["CapEff"] != wantCaps || st["CapPrm"] != wantCaps || st["CapBnd"] != wantCaps || st["NoNewPrivs"] != "1" {
		t.Errorf("執行部の権限: CapEff=%s CapPrm=%s CapBnd=%s NoNewPrivs=%s（%s のはず）", st["CapEff"], st["CapPrm"], st["CapBnd"], st["NoNewPrivs"], wantCaps)
	}
	for cmdline, wantUID := range children {
		child := childNamed(executor, "susanoo", cmdline)
		if child == 0 {
			t.Errorf("コマンドラインに %q を含む非特権のプロセスが見つかりません", cmdline)
			continue
		}
		st := procStatus(child)
		if uids := strings.Fields(st["Uid"]); len(uids) != 4 || slices.ContainsFunc(uids, func(u string) bool { return u != wantUID }) {
			t.Errorf("%q の利用者: Uid=%s（%s のはず）", cmdline, st["Uid"], wantUID)
		}
		if st["CapEff"] != "0000000000000000" || st["CapPrm"] != "0000000000000000" || st["NoNewPrivs"] != "1" || st["Groups"] != "" {
			t.Errorf("%q の権限: CapEff=%s CapPrm=%s NoNewPrivs=%s Groups=%q", cmdline, st["CapEff"], st["CapPrm"], st["NoNewPrivs"], st["Groups"])
		}
	}
}

// procStatus は /proc/<pid>/status の項目を返す。
func procStatus(pid int) map[string]string {
	m := map[string]string{}
	data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

// childNamed は、親が ppid で名前が name で、コマンドラインに cmdline を含むプロセスを返す。なければ 0 を返す。
func childNamed(ppid int, name, cmdline string) int {
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if st := procStatus(pid); st["PPid"] != strconv.Itoa(ppid) || st["Name"] != name {
			continue
		}
		if data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); strings.Contains(string(data), cmdline) {
			return pid
		}
	}
	return 0
}
