package behavior

import (
	"net/netip"
	"testing"
	"time"
)

// FuzzDetector は、さまざまな観測を与えても、止まったり落ちたりしないことを確かめる。
func FuzzDetector(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8}, "c2.example.test")
	f.Add([]byte{}, "")
	f.Fuzz(func(t *testing.T, data []byte, name string) {
		d := New(Config{OffHours: OffHours{Groups: []string{"default"}, Days: []string{}}, InternalScan: InternalScan{Targets: 5}}, all)
		at := t0
		for i, b := range data {
			at = at.Add(time.Duration(b) * time.Second)
			s := pc
			if b&1 == 1 {
				s = Subject{Key: "k" + string(rune(b%5)), Group: "default"}
			}
			f := Flow{Open: b&2 == 2, Time: at, Start: at.Add(-time.Duration(b) * time.Millisecond), Proto: b % 20,
				Src: netip.AddrPortFrom(src.Addr(), uint16(i)), Dst: netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, b}), uint16(b)),
				BytesOut: uint64(b) << 16, BytesIn: uint64(b), Hostname: name}
			d.Flow(s, f, at)
			d.DNS(s, name, at)
			d.ARPRequest(s, netip.AddrFrom4([4]byte{10, 0, 0, b}), at)
		}
		if snap := d.Snapshot(true); snap != nil {
			if err := New(Config{}, all).Restore(snap); err != nil {
				t.Fatalf("保存した宛先を読み直せない: %v", err)
			}
		}
		BaseDomain(name)
	})
}
