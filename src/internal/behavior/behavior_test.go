package behavior

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"susanoo/internal/config"
)

var (
	t0  = time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC) // 月曜日
	pc  = Subject{Key: "device:pc-001", Name: "pc-001", Group: "default"}
	src = netip.MustParseAddrPort("10.77.0.101:40000")
	dst = netip.MustParseAddrPort("203.0.113.9:443")
)

func all(string) bool { return true }

func closed(start time.Time, out uint64) Flow {
	return Flow{Time: start.Add(time.Second), Start: start, End: start.Add(time.Second), Proto: 6, Src: src, Dst: dst, BytesOut: out, BytesIn: 100}
}

func kinds(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Kind)
	}
	return out
}

func TestConfigValidate(t *testing.T) {
	var zero Config
	if err := zero.Validate(); err != nil {
		t.Fatalf("既定値 = %v", err)
	}
	for name, tc := range map[string]struct {
		cfg  Config
		want string
	}{
		"少なすぎる回数":   {Config{Beacon: Beacon{MinCount: 2}}, "min_count"},
		"逆の間隔":      {Config{Beacon: Beacon{MinInterval: config.Duration(time.Hour), MaxInterval: config.Duration(time.Minute)}}, "min_interval"},
		"大きすぎるばらつき": {Config{Beacon: Beacon{MaxJitter: 2}}, "max_jitter"},
		"ポート 0":     {Config{Beacon: Beacon{ExcludePorts: []uint16{0}}}, "exclude_ports"},
		"小さすぎる量":    {Config{LargeUpload: LargeUpload{Bytes: 10}}, "large_upload.bytes"},
		"短すぎる区間":    {Config{LargeUpload: LargeUpload{Window: config.Duration(time.Second)}}, "large_upload.window"},
		"少なすぎるアドレス": {Config{InternalScan: InternalScan{Targets: 2}}, "internal_scan.targets"},
		"少なすぎる宛先":   {Config{NewDestinations: NewDestinations{Count: 1}}, "new_destinations.count"},
		"長すぎる学習":    {Config{NewDestinations: NewDestinations{Baseline: config.Duration(100 * 24 * time.Hour)}}, "baseline"},
		"知らない曜日":    {Config{OffHours: OffHours{Days: []string{"monday"}}}, "days"},
		"不正な時刻":     {Config{OffHours: OffHours{Start: "8時"}}, "start"},
		"同じ始まりと終わり": {Config{OffHours: OffHours{Start: "09:00", End: "09:00"}}, "同じ"},
		"知らない時間帯":   {Config{OffHours: OffHours{Timezone: "Mars/Olympus"}}, "timezone"},
		"不正なグループ":   {Config{OffHours: OffHours{Groups: []string{"a~canary"}}}, "groups"},
	} {
		if err := tc.cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: エラー = %v（%q を含むこと）", name, err, tc.want)
		}
	}
}

func TestBusinessHours(t *testing.T) {
	s, err := (&Config{OffHours: OffHours{Timezone: "Asia/Tokyo"}}).settings()
	if err != nil {
		t.Fatal(err)
	}
	jst := time.FixedZone("JST", 9*3600)
	for at, want := range map[time.Time]bool{
		time.Date(2026, 10, 19, 9, 0, 0, 0, jst):  true,  // 月曜 9 時
		time.Date(2026, 10, 19, 7, 59, 0, 0, jst): false, // 始まりの前
		time.Date(2026, 10, 19, 20, 0, 0, 0, jst): false, // 終わり
		time.Date(2026, 10, 18, 12, 0, 0, 0, jst): false, // 日曜
	} {
		if got := s.business(at); got != want {
			t.Errorf("%v = %v", at, got)
		}
	}
	// 日をまたぐ業務時間は、始まりの日で業務日かを判断する。
	s, _ = (&Config{OffHours: OffHours{Start: "22:00", End: "06:00", Days: []string{"fri"}, Timezone: "Asia/Tokyo"}}).settings()
	for at, want := range map[time.Time]bool{
		time.Date(2026, 10, 23, 23, 0, 0, 0, jst): true,  // 金曜 23 時
		time.Date(2026, 10, 24, 5, 0, 0, 0, jst):  true,  // 土曜 5 時（金曜の夜の続き）
		time.Date(2026, 10, 24, 23, 0, 0, 0, jst): false, // 土曜 23 時
		time.Date(2026, 10, 23, 12, 0, 0, 0, jst): false,
	} {
		if got := s.business(at); got != want {
			t.Errorf("日をまたぐ %v = %v", at, got)
		}
	}
	// 業務日を空にすると、毎日が時間外。
	s, _ = (&Config{OffHours: OffHours{Days: []string{}}}).settings()
	if s.business(t0) {
		t.Error("業務日が空でも業務時間がある")
	}
}

func TestBeacon(t *testing.T) {
	d := New(Config{}, all)
	// SNI は接続の始まりの記録から引き継ぐ。
	var got []Finding
	for i := range 8 {
		start := t0.Add(time.Duration(i) * time.Minute).Add(time.Duration(i%3) * time.Second) // 少し揺らぐ
		d.Flow(pc, Flow{Open: true, Time: start, Src: src, Dst: dst, Hostname: "c2.example.test"}, start)
		got = append(got, d.Flow(pc, closed(start, 500), start.Add(time.Second))...)
	}
	if len(got) != 1 || got[0].Kind != KindBeacon || got[0].Dst.Hostname != "c2.example.test" || !strings.Contains(got[0].Message, "約 1m") {
		t.Fatalf("1 分ごとの接続 = %+v", got)
	}
	// 知らせた後は、cooldown の間は知らせない。
	for i := 8; i < 20; i++ {
		start := t0.Add(time.Duration(i) * time.Minute)
		d.Flow(pc, Flow{Open: true, Time: start, Src: src, Dst: dst, Hostname: "c2.example.test"}, start)
		if fs := d.Flow(pc, closed(start, 500), start); len(fs) != 0 {
			t.Fatalf("cooldown の間に知らせた: %v", kinds(fs))
		}
	}

	// 間隔がばらばらなら知らせない。順番が入れ替わって届いても並べ直す。
	d = New(Config{}, all)
	at := t0
	for _, gap := range []int{12, 300, 45, 600, 20, 150, 33, 480, 90, 15, 240, 60, 400, 25, 180, 70} {
		at = at.Add(time.Duration(gap) * time.Second)
		if fs := d.Flow(pc, closed(at, 1), at); len(fs) != 0 {
			t.Errorf("ばらばらな間隔で知らせた: %+v", fs[0])
		}
	}
	d = New(Config{}, all)
	var n int
	for _, i := range []int{1, 0, 3, 2, 5, 4, 7, 6} {
		start := t0.Add(time.Duration(i) * 30 * time.Second)
		n += len(d.Flow(pc, closed(start, 1), t0.Add(5*time.Minute)))
	}
	if n != 1 {
		t.Errorf("入れ替わって届いた周期的な接続の知らせ = %d", n)
	}

	// 前に不規則な接続があっても、最近の接続が周期的なら知らせる。
	d = New(Config{}, all)
	n = 0
	for _, m := range []int{0, 7, 9, 30, 31} {
		n += len(d.Flow(pc, closed(t0.Add(time.Duration(m)*time.Minute), 1), t0))
	}
	for i := range 8 {
		n += len(d.Flow(pc, closed(t0.Add(time.Hour+time.Duration(i)*20*time.Second), 1), t0.Add(2*time.Hour)))
	}
	if n != 1 {
		t.Errorf("不規則な接続の後の周期的な接続の知らせ = %d", n)
	}

	// NTP と、除いたポートと、短すぎる間隔は対象にしない。
	d = New(Config{Beacon: Beacon{ExcludePorts: []uint16{443}}}, all)
	for i := range 10 {
		start := t0.Add(time.Duration(i) * time.Minute)
		ntp := closed(start, 1)
		ntp.Proto, ntp.Dst = 17, netip.MustParseAddrPort("203.0.113.9:123")
		if fs := append(d.Flow(pc, ntp, start), d.Flow(pc, closed(start, 1), start)...); len(fs) != 0 {
			t.Errorf("NTP か除いたポートで知らせた: %v", kinds(fs))
		}
	}
	d = New(Config{}, all)
	for i := range 10 {
		start := t0.Add(time.Duration(i) * time.Second)
		if fs := d.Flow(pc, closed(start, 1), start); len(fs) != 0 {
			t.Errorf("1 秒ごと（min_interval より短い）で知らせた")
		}
	}
	// 止めた種類は数えない。
	d = New(Config{}, func(k string) bool { return k != KindBeacon })
	for i := range 10 {
		start := t0.Add(time.Duration(i) * time.Minute)
		if fs := d.Flow(pc, closed(start, 1), start); len(fs) != 0 {
			t.Errorf("止めた周期的な通信の検知で知らせた")
		}
	}
	if d.Enabled(KindBeacon) || !d.Enabled(KindLargeUpload) || d.Enabled(KindOffHours) {
		t.Error("使っている種類が違う")
	}
}

func TestLargeUpload(t *testing.T) {
	d := New(Config{LargeUpload: LargeUpload{Bytes: 10 << 20, Window: config.Duration(10 * time.Minute)}}, func(k string) bool { return k == KindLargeUpload })
	// 区間の外に出た量は数えない。
	if fs := d.Flow(pc, closed(t0, 6<<20), t0); len(fs) != 0 {
		t.Fatal("上限の前に知らせた")
	}
	at := t0.Add(15 * time.Minute)
	if fs := d.Flow(pc, closed(at, 6<<20), at); len(fs) != 0 {
		t.Fatal("区間の外の量を数えた")
	}
	at = at.Add(3 * time.Minute)
	fs := d.Flow(pc, closed(at, 5<<20), at)
	if len(fs) != 1 || fs[0].Kind != KindLargeUpload || fs[0].Traffic.BytesOut != 11<<20 || !strings.Contains(fs[0].Message, "11.0 MiB") {
		t.Fatalf("上限を超えた送信 = %+v", fs)
	}
	at = at.Add(time.Minute)
	if fs := d.Flow(pc, closed(at, 20<<20), at); len(fs) != 0 {
		t.Error("区間の間にもう一度知らせた")
	}
	// ほかの機器は別に数える。
	other := Subject{Key: "host:02:00:00:00:00:02", Name: "02:00:00:00:00:02"}
	if fs := d.Flow(other, closed(at, 1<<20), at); len(fs) != 0 {
		t.Error("ほかの機器の量と合わせた")
	}
}

func TestInternalScan(t *testing.T) {
	d := New(Config{InternalScan: InternalScan{Targets: 10, Window: config.Duration(time.Minute)}}, all)
	// 同じアドレスを何度探しても 1 つと数える。
	for range 20 {
		if fs := d.ARPRequest(pc, netip.MustParseAddr("10.77.0.1"), t0); len(fs) != 0 {
			t.Fatal("同じアドレスで知らせた")
		}
	}
	// ゆっくり探すと区間の外のものは数えない。
	for i := range 12 {
		at := t0.Add(time.Duration(i) * 10 * time.Second)
		if fs := d.ARPRequest(pc, netip.AddrFrom4([4]byte{10, 77, 0, byte(10 + i)}), at); len(fs) != 0 {
			t.Fatalf("1 分に 6 個で知らせた（%d 個目）", i)
		}
	}
	d = New(Config{InternalScan: InternalScan{Targets: 10, Window: config.Duration(time.Minute)}}, all)
	var got []Finding
	for i := range 12 {
		got = append(got, d.ARPRequest(pc, netip.AddrFrom4([4]byte{10, 77, 0, byte(100 + i)}), t0.Add(time.Duration(i)*time.Second))...)
	}
	if len(got) != 1 || got[0].Kind != KindInternalScan || got[0].Details["targets"] != 10 || !strings.Contains(got[0].Message, "10.77.0.100") {
		t.Fatalf("短い間に 12 個のアドレス = %+v", got)
	}
}

func TestNewDestinations(t *testing.T) {
	cfg := Config{NewDestinations: NewDestinations{Count: 5, Window: config.Duration(10 * time.Minute), Baseline: config.Duration(time.Hour)}}
	d := New(cfg, all)
	// 学習の期間に使った宛先は覚えるだけ。
	for i := range 20 {
		if fs := d.DNS(pc, fmt.Sprintf("www.known%d.example", i), t0); len(fs) != 0 {
			t.Fatal("学習の期間に知らせた")
		}
	}
	after := t0.Add(2 * time.Hour)
	// 覚えた宛先（ほかのホスト名でも同じ単位）は新しい宛先に数えない。
	for i := range 20 {
		if fs := d.DNS(pc, fmt.Sprintf("api.known%d.example.", i), after); len(fs) != 0 {
			t.Fatal("覚えた宛先で知らせた")
		}
	}
	var got []Finding
	for i := range 6 {
		got = append(got, d.DNS(pc, fmt.Sprintf("x%d.dga%d.co.jp", i, i), after.Add(time.Duration(i)*time.Second))...)
	}
	if len(got) != 1 || got[0].Kind != KindNewDestinations || got[0].Details["count"] != 5 || !strings.Contains(got[0].Message, "dga0.co.jp") {
		t.Fatalf("新しい宛先 = %+v", got)
	}

	// 覚えた宛先は保存して読み直せる。
	data := d.Snapshot(false)
	if data == nil || d.Snapshot(false) != nil {
		t.Fatal("変更があるときだけ保存する")
	}
	d2 := New(cfg, all)
	if err := d2.Restore(data); err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		if fs := d2.DNS(pc, fmt.Sprintf("known%d.example", i), after.Add(time.Hour)); len(fs) != 0 {
			t.Fatal("読み直した後に覚えた宛先で知らせた")
		}
	}
	var st map[string]map[string]any
	if json.Unmarshal(data, &st) != nil || st["device:pc-001"]["first"] == nil {
		t.Errorf("保存した形 = %s", data)
	}
}

func TestOffHours(t *testing.T) {
	cfg := Config{OffHours: OffHours{Groups: []string{"office"}, Timezone: "UTC", MinBytes: 1 << 20}}
	d := New(cfg, all)
	office := Subject{Key: "device:pc-009", Name: "pc-009", Group: "office"}
	night := time.Date(2026, 10, 19, 23, 0, 0, 0, time.UTC)
	// 業務時間の内と、対象でないグループは数えない。
	if fs := append(d.Flow(office, closed(t0, 5<<20), t0), d.Flow(pc, closed(night, 5<<20), night)...); len(fs) != 0 {
		t.Fatalf("業務時間か対象外のグループで知らせた: %v", kinds(fs))
	}
	if fs := d.Flow(office, closed(night, 600<<10), night); len(fs) != 0 {
		t.Fatal("量が少ないのに知らせた")
	}
	fs := d.Flow(office, closed(night.Add(time.Minute), 600<<10), night.Add(time.Minute))
	if len(fs) != 1 || fs[0].Kind != KindOffHours || !strings.Contains(fs[0].Message, "10-19 23:01") {
		t.Fatalf("時間外の通信 = %+v", fs)
	}
	// グループがなければ検知しない。
	if New(Config{}, all).Enabled(KindOffHours) {
		t.Error("グループがないのに時間外の通信を検知する")
	}
}

func TestBaseDomain(t *testing.T) {
	for in, want := range map[string]string{
		"www.example.com":        "example.com",
		"Example.COM.":           "example.com",
		"a.b.example.co.jp":      "example.co.jp",
		"example.co.jp":          "example.co.jp",
		"co.jp":                  "co.jp",
		"x.example.jp":           "example.jp",
		"api.service.com.au":     "service.com.au",
		"deep.sub.example.org":   "example.org",
		"localhost":              "",
		"203.0.113.9":            "",
		"":                       "",
		"a..example.com":         "",
		"bad name.example.com":   "",
		strings.Repeat("a", 300): "",
	} {
		if got := BaseDomain(in); got != want {
			t.Errorf("BaseDomain(%q) = %q, 期待値 %q", in, got, want)
		}
	}
}

// 覚える量には上限がある。
func TestLimits(t *testing.T) {
	d := New(Config{}, all)
	for i := range maxBeacons + 100 {
		f := closed(t0, 1)
		f.Dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}), uint16(1+i%60000))
		d.Flow(pc, f, t0)
	}
	if len(d.beacons) > maxBeacons {
		t.Errorf("周期的な通信の組 = %d", len(d.beacons))
	}
	for i := range maxKnown + 50 {
		d.DNS(pc, fmt.Sprintf("n%d.example", i), t0)
	}
	if n := len(d.dests[pc.Key].Known); n > maxKnown {
		t.Errorf("覚えた宛先 = %d", n)
	}
	for i := range maxConns + 10 {
		f := Flow{Open: true, Src: netip.AddrPortFrom(src.Addr(), uint16(i)), Dst: netip.AddrPortFrom(dst.Addr(), uint16(i>>16)), Hostname: "x.test"}
		d.Flow(pc, f, t0)
	}
	if len(d.conns) > maxConns {
		t.Errorf("終わっていない接続 = %d", len(d.conns))
	}
}
