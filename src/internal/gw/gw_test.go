package gw

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"susanoo/internal/nft"
	"susanoo/internal/policy"
)

type recorder struct {
	scripts []string
	fail    string // この文字列を含むスクリプトを失敗させる
}

func (r *recorder) Run(_ context.Context, script string) error {
	r.scripts = append(r.scripts, script)
	if r.fail != "" && strings.Contains(script, r.fail) {
		return errors.New("nft: No such file or directory")
	}
	return nil
}

func TestSync(t *testing.T) {
	r := &recorder{}
	e := &Enforcer{NFT: r, ManagementPort: 8443, Updates: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	err := e.Sync(context.Background(),
		map[netip.Addr]policy.IsolationLevel{netip.MustParseAddr("10.77.0.11"): policy.IsolateManagement},
		map[string]policy.IsolationLevel{"02:00:00:00:00:0b": policy.IsolateManagement})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"elements = { 10.77.0.11 }", "elements = { 02:00:00:00:00:0b }", "192.0.2.0/24"} {
		if !strings.Contains(r.scripts[0], want) {
			t.Errorf("%q が含まれない\n%s", want, r.scripts[0])
		}
	}

	// 2 回目からは集合だけを入れ替える（DNS で得た更新サーバーのアドレスを保つ）。空にすると要素がなくなる。
	if err := e.Sync(context.Background(), nil, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.scripts[1], "10.77.0.11") || strings.Contains(r.scripts[1], "02:00:00:00:00:0b") || strings.Contains(r.scripts[1], "delete table") {
		t.Errorf("集合の入れ替えになっていない\n%s", r.scripts[1])
	}
	// 集合の入れ替えに失敗したら、テーブルを作り直す。
	r.fail = "flush set"
	if err := e.Sync(context.Background(), nil, nil); err != nil {
		t.Fatal(err)
	}
	if last := r.scripts[len(r.scripts)-1]; !strings.Contains(last, "delete table inet susanoo_gw") {
		t.Errorf("テーブルを作り直していない\n%s", last)
	}
	if err := (&Enforcer{NFT: r}).Sync(context.Background(), nil, nil); err == nil {
		t.Error("管理通信のポートなしで適用できた")
	}
}

func TestRouterApply(t *testing.T) {
	r := &recorder{}
	forward := filepath.Join(t.TempDir(), "ip_forward")
	if err := os.WriteFile(forward, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	acceptRA := filepath.Join(t.TempDir(), "accept_ra")
	os.WriteFile(acceptRA, []byte("1\n"), 0o644)
	router := &Router{Rules: nft.Router{LAN: "lan0", WAN: "wan0", ManagementPort: 8443}, NFT: r, forwardPath: forward, acceptRAPath: acceptRA}
	if err := router.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(acceptRA); string(got) != "0\n" {
		t.Errorf("LAN のルーター広告の受け付け = %q", got)
	}
	if len(r.scripts) != 1 || !strings.Contains(r.scripts[0], `oifname "wan0" masquerade`) {
		t.Errorf("スクリプト = %v", r.scripts)
	}
	if got, _ := os.ReadFile(forward); string(got) != "1\n" {
		t.Errorf("転送の設定 = %q", got)
	}
	// IPv6 を転送するときは、WAN 側を RA に従わせたまま（2）、IPv6 の転送を有効にする。
	dir := t.TempDir()
	for _, d := range []string{"lan0", "wan0", "all"} {
		os.MkdirAll(filepath.Join(dir, d), 0o755)
		os.WriteFile(filepath.Join(dir, d, "accept_ra"), []byte("1\n"), 0o644)
		os.WriteFile(filepath.Join(dir, d, "forwarding"), []byte("0\n"), 0o644)
	}
	v6 := &Router{Rules: nft.Router{LAN: "lan0", WAN: "wan0", ManagementPort: 8443, IPv6: true}, NFT: r, forwardPath: forward, sysctlDir: dir}
	if err := v6.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	for file, want := range map[string]string{"lan0/accept_ra": "0\n", "wan0/accept_ra": "2\n", "all/forwarding": "1\n", "lan0/forwarding": "0\n"} {
		if got, _ := os.ReadFile(filepath.Join(dir, file)); string(got) != want {
			t.Errorf("%s = %q", file, got)
		}
	}
	if s := r.scripts[len(r.scripts)-1]; strings.Contains(s, "nfproto ipv6 drop") {
		t.Errorf("IPv6 を転送するのに遮断している:\n%s", s)
	}
	bad := &Router{Rules: nft.Router{LAN: "x", WAN: "x", ManagementPort: 8443}, NFT: r, forwardPath: forward, acceptRAPath: acceptRA}
	if err := bad.Apply(context.Background()); err == nil {
		t.Error("不正なルールを適用できた")
	}
}

func TestARP(t *testing.T) {
	a := ARP{
		Op:        ARPReply,
		SenderMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1},
		SenderIP:  netip.MustParseAddr("10.77.0.11"),
		TargetMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2},
		TargetIP:  netip.MustParseAddr("10.77.0.1"),
	}
	b := a.Marshal()
	if len(b) != 28 {
		t.Fatalf("長さ = %d", len(b))
	}
	got, err := ParseARP(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Op != a.Op || !bytes.Equal(got.SenderMAC, a.SenderMAC) || got.SenderIP != a.SenderIP || !bytes.Equal(got.TargetMAC, a.TargetMAC) || got.TargetIP != a.TargetIP {
		t.Errorf("読み直した ARP = %+v", got)
	}

	if _, err := ParseARP(b[:27]); err == nil {
		t.Error("短いメッセージを受け付けた")
	}
	other := append([]byte{}, b...)
	other[3] = 0xdd // プロトコルの種類を IPv4 以外にする
	if _, err := ParseARP(other); err == nil {
		t.Error("IPv4 以外の ARP を受け付けた")
	}
}

func FuzzParseARP(f *testing.F) {
	f.Add(ARP{Op: ARPRequest, SenderMAC: make(net.HardwareAddr, 6), TargetMAC: make(net.HardwareAddr, 6)}.Marshal())
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := ParseARP(b)
		if err != nil {
			return
		}
		// 解析できた ARP は、書き出すと元の先頭 28 バイトと同じになる。
		if !bytes.Equal(a.Marshal(), b[:28]) {
			t.Fatalf("書き出した ARP が元と違う: %x", b[:28])
		}
	})
}
