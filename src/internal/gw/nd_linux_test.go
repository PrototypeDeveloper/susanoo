//go:build linux

package gw

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"testing"
)

// runBPF は ndFilter に使う classic BPF の命令（ld b/h abs、jeq/jge/jgt k、ret k）だけを解釈する。
// skfProtocol の読み込みは、パケットの種類 proto を返す。
func runBPF(t *testing.T, prog []syscall.SockFilter, pkt []byte, proto ...uint32) uint32 {
	t.Helper()
	var a uint32
	for pc := 0; pc < len(prog); pc++ {
		ins := prog[pc]
		if ins.Code == syscall.BPF_LD|syscall.BPF_H|syscall.BPF_ABS && ins.K == skfProtocol {
			a = proto[0]
			continue
		}
		switch ins.Code {
		case syscall.BPF_LD | syscall.BPF_B | syscall.BPF_ABS:
			if int(ins.K) >= len(pkt) {
				return 0
			}
			a = uint32(pkt[ins.K])
		case syscall.BPF_LD | syscall.BPF_H | syscall.BPF_ABS:
			if int(ins.K)+2 > len(pkt) {
				return 0
			}
			a = uint32(binary.BigEndian.Uint16(pkt[ins.K:]))
		case syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, syscall.BPF_JMP | syscall.BPF_JGE | syscall.BPF_K, syscall.BPF_JMP | syscall.BPF_JGT | syscall.BPF_K:
			var ok bool
			switch ins.Code & 0xf0 {
			case syscall.BPF_JEQ:
				ok = a == ins.K
			case syscall.BPF_JGE:
				ok = a >= ins.K
			case syscall.BPF_JGT:
				ok = a > ins.K
			}
			if ok {
				pc += int(ins.Jt)
			} else {
				pc += int(ins.Jf)
			}
		case syscall.BPF_RET | syscall.BPF_K:
			return ins.K
		default:
			t.Fatalf("知らない命令 %#x", ins.Code)
		}
	}
	t.Fatal("ret に届かない")
	return 0
}

// カーネルの絞り込みは、近隣探索（133〜136）と DHCPv6 のクライアントのポートへの UDP だけを通す。
func TestNDFilter(t *testing.T) {
	echo := icmpv6(llGW, AllNodes, []byte{128, 0, 0, 0, 0, 1, 0, 1}) // ping
	ra := WithdrawRA(llRogue, macX, nil, nil)
	toServer := SolicitDHCPv6(llGW, macX, 1)
	toClient := advertise(llRogue, llGW, 1, llRogue, netip.MustParseAddr("2001:db8::1"))
	for name, tc := range map[string]struct {
		pkt  []byte
		pass bool
	}{
		"RS":              {RouterSolicit(llGW, macX), true},
		"RA":              {ra, true},
		"NA":              {neighborAdvert(llRogue, llGW, macX, 0x20, 255), true},
		"ping":            {echo, false},
		"DHCPv6 のサーバーへ":   {toServer, false},
		"DHCPv6 のクライアントへ": {toClient, true},
		"短いパケット":          {[]byte{0x60, 0, 0}, false},
	} {
		if got := runBPF(t, ndFilter, tc.pkt) != 0; got != tc.pass {
			t.Errorf("%s を通すか = %v", name, got)
		}
		// ブリッジのポートでは、IPv6 のときだけ同じ判定をする。
		if got := runBPF(t, ndPortFilter(), tc.pkt, syscall.ETH_P_IPV6) != 0; got != tc.pass {
			t.Errorf("ブリッジのポートで %s を通すか = %v", name, got)
		}
		if runBPF(t, ndPortFilter(), tc.pkt, syscall.ETH_P_IP) != 0 {
			t.Errorf("ブリッジのポートで IPv4 の %s を通した", name)
		}
	}
	arp := ARP{Op: ARPRequest, SenderMAC: macX, SenderIP: netip.MustParseAddr("10.77.0.5"), TargetMAC: make([]byte, 6), TargetIP: netip.MustParseAddr("10.77.0.1")}.Marshal()
	if runBPF(t, arpPortFilter, arp, syscall.ETH_P_ARP) == 0 || runBPF(t, arpPortFilter, echo, syscall.ETH_P_IPV6) != 0 || runBPF(t, arpPortFilter, arp, syscall.ETH_P_IP) != 0 {
		t.Error("ブリッジのポートの ARP の絞り込みが違う")
	}
}

func TestParseRoute(t *testing.T) {
	data := []byte("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"wan0\t00000000\t0100710A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
		"br0\t0000710A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" +
		"br0\t00000000\tFE00710A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n")
	if a, err := parseRoute(data, "br0"); err != nil || a.String() != "10.113.0.254" {
		t.Errorf("br0 の既定の経路 = %v %v", a, err)
	}
	if _, err := parseRoute(data, "lan0"); err == nil {
		t.Error("経路のない装置で次の転送先を返した")
	}
}
