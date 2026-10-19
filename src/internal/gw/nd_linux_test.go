//go:build linux

package gw

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"testing"
)

// runBPF は ndFilter に使う classic BPF の命令（ld b/h abs、jeq/jge/jgt k、ret k）だけを解釈する。
func runBPF(t *testing.T, prog []syscall.SockFilter, pkt []byte) uint32 {
	t.Helper()
	var a uint32
	for pc := 0; pc < len(prog); pc++ {
		ins := prog[pc]
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
	}
}
