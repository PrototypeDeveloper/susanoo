package behavior

import (
	"cmp"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"susanoo/internal/event"
)

// 検知の種類（検知結果の種類と同じ）。
const (
	KindBeacon          = event.FindingTypeBeacon
	KindLargeUpload     = event.FindingTypeLargeUpload
	KindInternalScan    = event.FindingTypeInternalScan
	KindNewDestinations = event.FindingTypeNewDestinations
	KindOffHours        = event.FindingTypeOffHours
)

// Kinds はすべての検知の種類。
var Kinds = []string{KindBeacon, KindLargeUpload, KindInternalScan, KindNewDestinations, KindOffHours}

// 覚えておく量の上限（乗っ取られた機器が大量の宛先や MAC アドレスを使っても、メモリを使い切らないように）。
const (
	maxConns     = 65536 // SNI か Host が分かった、終わっていない接続
	maxBeacons   = 20000 // 周期的な通信を確かめる、機器と宛先の組
	maxSubjects  = 4096  // 機器ごとの状態
	maxKnown     = 1024  // 機器ごとに覚える宛先
	maxScanAddrs = 1024  // 機器ごとに覚える、ARP で探したアドレス
	connTTL      = time.Hour
	sampleNames  = 10 // 検知結果に載せる例の数
)

// Subject は観測の対象の機器。
type Subject struct {
	Key   string // 状態を数える単位（device:端末 ID、host:MAC アドレスなど）
	Name  string // 表示に使う名前（端末 ID、MAC アドレス、アドレス）
	Group string
}

// Flow は外へ転送した通信の記録。
type Flow struct {
	Open       bool // TLS か HTTP の始まり（Hostname がある）。false なら接続の終わり
	Time       time.Time
	Start, End time.Time
	Proto      uint8
	Src, Dst   netip.AddrPort
	BytesOut   uint64
	BytesIn    uint64
	Hostname   string // SNI か HTTP の Host
}

// Finding は検知した振る舞い。
type Finding struct {
	Kind     string
	Subject  Subject
	Title    string
	Message  string
	Severity event.Severity
	Dst      *event.Endpoint
	Traffic  *event.Traffic
	Details  map[string]any
}

// Detector は振る舞いを検知する。複数のゴルーチンから使える。
type Detector struct {
	mu      sync.Mutex
	s       settings
	enabled map[string]bool

	conns   map[connKey]connInfo
	beacons map[string]*beaconState
	uploads map[string]*uploadState
	scans   map[string]*scanState
	dests   map[string]*destState
	offs    map[string]*offState
	dirty   bool // 覚えた宛先に、保存していない変更がある
}

type connKey struct{ src, dst netip.AddrPort }

type connInfo struct {
	name string
	at   time.Time
}

// New は、設定 cfg（検証済みのもの）で、enabled が真の種類だけを検知する Detector を作る。
func New(cfg Config, enabled func(kind string) bool) *Detector {
	d := &Detector{conns: map[connKey]connInfo{}, beacons: map[string]*beaconState{}, uploads: map[string]*uploadState{},
		scans: map[string]*scanState{}, dests: map[string]*destState{}, offs: map[string]*offState{}}
	d.Configure(cfg, enabled)
	return d
}

// Configure は設定を切り替える。止めた種類の状態は捨てる（覚えた宛先は残す）。
func (d *Detector) Configure(cfg Config, enabled func(kind string) bool) {
	s, err := cfg.settings()
	if err != nil {
		s, _ = (&Config{}).settings()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.s = s
	d.enabled = map[string]bool{}
	for _, k := range Kinds {
		d.enabled[k] = enabled == nil || enabled(k)
	}
	if len(s.offGroups) == 0 {
		d.enabled[KindOffHours] = false
	}
	if !d.enabled[KindBeacon] {
		clear(d.beacons)
	}
	if !d.enabled[KindLargeUpload] {
		clear(d.uploads)
	}
	if !d.enabled[KindInternalScan] {
		clear(d.scans)
	}
	if !d.enabled[KindOffHours] {
		clear(d.offs)
	}
}

// Enabled は種類 kind を検知しているかを返す。
func (d *Detector) Enabled(kind string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.enabled[kind]
}

// Flow は通信の記録を受け取り、検知した振る舞いを返す。now は今の時刻（知らせを繰り返さない判断に使う）。
func (d *Detector) Flow(sub Subject, f Flow, now time.Time) []Finding {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []Finding
	if f.Open {
		if f.Hostname != "" {
			if len(d.conns) >= maxConns {
				d.pruneConnsLocked(now)
			}
			d.conns[connKey{f.Src, f.Dst}] = connInfo{name: f.Hostname, at: now}
			out = appendFinding(out, d.destLocked(sub, f.Hostname, now))
		}
		return out
	}
	key := connKey{f.Src, f.Dst}
	if c, ok := d.conns[key]; ok {
		f.Hostname = c.name
		delete(d.conns, key)
	}
	out = appendFinding(out, d.beaconLocked(sub, f, now))
	out = appendFinding(out, d.uploadLocked(sub, f, now))
	out = appendFinding(out, d.offHoursLocked(sub, f, now))
	return out
}

// DNS は DNS の問い合わせの名前を受け取り、検知した振る舞いを返す。
func (d *Detector) DNS(sub Subject, name string, now time.Time) []Finding {
	d.mu.Lock()
	defer d.mu.Unlock()
	return appendFinding(nil, d.destLocked(sub, name, now))
}

// ARPRequest は、機器 sub が LAN のアドレス target を ARP で探したことを受け取り、検知した振る舞いを返す。
func (d *Detector) ARPRequest(sub Subject, target netip.Addr, now time.Time) []Finding {
	d.mu.Lock()
	defer d.mu.Unlock()
	return appendFinding(nil, d.scanLocked(sub, target, now))
}

func appendFinding(out []Finding, f *Finding) []Finding {
	if f != nil {
		out = append(out, *f)
	}
	return out
}

func (d *Detector) pruneConnsLocked(now time.Time) {
	for k, c := range d.conns {
		if now.Sub(c.at) > connTTL {
			delete(d.conns, k)
		}
	}
	for k := range d.conns {
		if len(d.conns) < maxConns {
			break
		}
		delete(d.conns, k)
	}
}

// --- 周期的な通信 ---

type beaconState struct {
	times    []time.Time // 接続の始まり（古い順。最大 maxBeaconHistory）
	seen     time.Time
	reported time.Time
}

var protoNames = map[uint8]string{1: "icmp", 6: "tcp", 17: "udp", 58: "ipv6-icmp"}

func (d *Detector) beaconLocked(sub Subject, f Flow, now time.Time) *Finding {
	s := &d.s
	port := f.Dst.Port()
	if !d.enabled[KindBeacon] || (f.Proto == 17 && port == 123) || slices.Contains(s.beaconExclude, port) {
		return nil
	}
	start := f.Start
	if start.IsZero() {
		start = f.Time
	}
	dst := cmp.Or(f.Hostname, f.Dst.Addr().String())
	proto := cmp.Or(protoNames[f.Proto], strconv.Itoa(int(f.Proto)))
	key := sub.Key + "\x00" + proto + "\x00" + dst + "\x00" + strconv.Itoa(int(port))
	b := d.beacons[key]
	if b == nil {
		if len(d.beacons) >= maxBeacons {
			d.pruneBeaconsLocked(now)
		}
		b = &beaconState{}
		d.beacons[key] = b
	}
	b.seen = now
	i, _ := slices.BinarySearchFunc(b.times, start, time.Time.Compare)
	b.times = slices.Insert(b.times, i, start)
	if len(b.times) > maxBeaconHistory {
		b.times = b.times[len(b.times)-maxBeaconHistory:]
	}
	if len(b.times) < s.beaconMinCount || (!b.reported.IsZero() && now.Sub(b.reported) < s.beaconCooldown) {
		return nil
	}
	// 判断には最近の min_count 回だけを使う（前の不規則な接続に、新しく始まった周期的な接続が埋もれないように）。
	recent := b.times[len(b.times)-s.beaconMinCount:]
	mean, jitter := intervals(recent)
	if mean < s.beaconMin || mean > s.beaconMax || jitter > s.beaconJitter {
		return nil
	}
	b.reported = now
	count := len(recent)
	b.times = b.times[:0]
	ep := &event.Endpoint{IP: f.Dst.Addr().String(), Port: int(port), Hostname: f.Hostname}
	return &Finding{
		Kind: KindBeacon, Subject: sub, Title: "周期的な通信（ビーコン）", Severity: event.SeverityMedium, Dst: ep,
		Message: fmt.Sprintf("機器 %s が %s（%s）へ、約 %s ごとに %d 回接続しています（間隔のばらつき %.0f%%）",
			sub.Name, net.JoinHostPort(dst, strconv.Itoa(int(port))), proto, roundDuration(mean), count, jitter*100),
		Details: map[string]any{"interval_ms": mean.Milliseconds(), "jitter": math.Round(jitter*1000) / 1000, "count": count, "protocol": proto},
	}
}

// intervals は、古い順の時刻の間隔の平均と、ばらつき（標準偏差÷平均）を返す。
func intervals(times []time.Time) (time.Duration, float64) {
	n := len(times) - 1
	if n < 1 {
		return 0, math.Inf(1)
	}
	var sum float64
	for i := 1; i <= n; i++ {
		sum += float64(times[i].Sub(times[i-1]))
	}
	mean := sum / float64(n)
	if mean <= 0 {
		return 0, math.Inf(1)
	}
	var sq float64
	for i := 1; i <= n; i++ {
		x := float64(times[i].Sub(times[i-1])) - mean
		sq += x * x
	}
	return time.Duration(mean), math.Sqrt(sq/float64(n)) / mean
}

func (d *Detector) pruneBeaconsLocked(now time.Time) {
	for k, b := range d.beacons {
		if now.Sub(b.seen) > 2*d.s.beaconMax {
			delete(d.beacons, k)
		}
	}
	for k := range d.beacons {
		if len(d.beacons) < maxBeacons {
			break
		}
		delete(d.beacons, k)
	}
}

// --- 大量の送信 ---

// uploadBuckets は、送信量を数える区間の数。window をこの数に分けて数える。
const uploadBuckets = 12

type uploadBucket struct {
	index int64 // 区間の番号（時刻÷区間の長さ）
	bytes uint64
	max   uint64 // 区間の中で最も多く送った接続の量
	dst   string
}

type uploadState struct {
	buckets  [uploadBuckets]uploadBucket
	reported time.Time
}

func (d *Detector) uploadLocked(sub Subject, f Flow, now time.Time) *Finding {
	s := &d.s
	if !d.enabled[KindLargeUpload] || f.BytesOut == 0 {
		return nil
	}
	u := d.uploads[sub.Key]
	if u == nil {
		if len(d.uploads) >= maxSubjects {
			clear(d.uploads)
		}
		u = &uploadState{}
		d.uploads[sub.Key] = u
	}
	at := cmp.Or(f.End, f.Time)
	width := int64(s.uploadWindow / uploadBuckets)
	idx := at.UnixNano() / width
	b := &u.buckets[idx%uploadBuckets]
	if b.index != idx {
		*b = uploadBucket{index: idx}
	}
	b.bytes += f.BytesOut
	dst := net.JoinHostPort(cmp.Or(f.Hostname, f.Dst.Addr().String()), strconv.Itoa(int(f.Dst.Port())))
	if f.BytesOut > b.max {
		b.max, b.dst = f.BytesOut, dst
	}
	var total, top uint64
	topDst := ""
	for _, x := range u.buckets {
		if x.index > idx-uploadBuckets && x.index <= idx {
			total += x.bytes
			if x.max > top {
				top, topDst = x.max, x.dst
			}
		}
	}
	if total < s.uploadBytes || (!u.reported.IsZero() && now.Sub(u.reported) < s.uploadWindow) {
		return nil
	}
	u.reported = now
	u.buckets = [uploadBuckets]uploadBucket{}
	return &Finding{
		Kind: KindLargeUpload, Subject: sub, Title: "大量の送信", Severity: event.SeverityHigh,
		Dst: &event.Endpoint{IP: f.Dst.Addr().String(), Port: int(f.Dst.Port()), Hostname: f.Hostname}, Traffic: &event.Traffic{BytesOut: int64(total)},
		Message: fmt.Sprintf("機器 %s が %s の間に %s を外部へ送りました（最も多い接続は %s へ %s）",
			sub.Name, roundDuration(s.uploadWindow), formatBytes(total), topDst, formatBytes(top)),
		Details: map[string]any{"bytes_out": total, "window_s": int64(s.uploadWindow.Seconds()), "top_destination": topDst, "top_bytes": top},
	}
}

// --- LAN 内のスキャン ---

type scanState struct {
	targets  map[netip.Addr]time.Time
	reported time.Time
}

func (d *Detector) scanLocked(sub Subject, target netip.Addr, now time.Time) *Finding {
	s := &d.s
	if !d.enabled[KindInternalScan] {
		return nil
	}
	st := d.scans[sub.Key]
	if st == nil {
		if len(d.scans) >= maxSubjects {
			clear(d.scans)
		}
		st = &scanState{targets: map[netip.Addr]time.Time{}}
		d.scans[sub.Key] = st
	}
	st.targets[target] = now
	if len(st.targets) >= s.scanTargets || len(st.targets) >= maxScanAddrs {
		for a, t := range st.targets {
			if now.Sub(t) > s.scanWindow || now.Before(t) {
				delete(st.targets, a)
			}
		}
	}
	if len(st.targets) < s.scanTargets || (!st.reported.IsZero() && now.Sub(st.reported) < s.scanWindow) {
		return nil
	}
	addrs := make([]netip.Addr, 0, len(st.targets))
	for a := range st.targets {
		addrs = append(addrs, a)
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	n := len(addrs)
	var sample []string
	for _, a := range addrs[:min(n, sampleNames)] {
		sample = append(sample, a.String())
	}
	st.reported = now
	clear(st.targets)
	return &Finding{
		Kind: KindInternalScan, Subject: sub, Title: "LAN 内のスキャン", Severity: event.SeverityHigh,
		Message: fmt.Sprintf("機器 %s が %s の間に、LAN の %d 個のアドレスを ARP で探しました（例: %s）",
			sub.Name, roundDuration(s.scanWindow), n, strings.Join(sample, "、")),
		Details: map[string]any{"targets": n, "window_s": int64(s.scanWindow.Seconds()), "sample": sample},
	}
}

// --- 新しい宛先の急増 ---

type destState struct {
	First    time.Time            `json:"first"` // 機器を初めて見た時刻（学習の期間の始まり）
	Known    map[string]time.Time `json:"known"` // 覚えた宛先 → 最後に使った時刻
	news     []time.Time
	recent   []string
	reported time.Time
}

func (d *Detector) destLocked(sub Subject, name string, now time.Time) *Finding {
	s := &d.s
	if !d.enabled[KindNewDestinations] || sub.Key == "" {
		return nil
	}
	base := BaseDomain(name)
	if base == "" {
		return nil
	}
	st := d.dests[sub.Key]
	if st == nil {
		if len(d.dests) >= maxSubjects {
			d.pruneDestsLocked()
		}
		st = &destState{First: now, Known: map[string]time.Time{}}
		d.dests[sub.Key] = st
	}
	if last, ok := st.Known[base]; ok {
		if now.Sub(last) > time.Hour {
			st.Known[base] = now
			d.dirty = true
		}
		return nil
	}
	if len(st.Known) >= maxKnown {
		var oldest string
		var at time.Time
		for k, t := range st.Known {
			if oldest == "" || t.Before(at) {
				oldest, at = k, t
			}
		}
		delete(st.Known, oldest)
	}
	st.Known[base] = now
	d.dirty = true
	if now.Sub(st.First) < s.newBaseline {
		return nil
	}
	st.news = append(st.news, now)
	st.recent = append(st.recent, base)
	if len(st.recent) > sampleNames {
		st.recent = st.recent[len(st.recent)-sampleNames:]
	}
	i := 0
	for i < len(st.news) && now.Sub(st.news[i]) > s.newWindow {
		i++
	}
	st.news = st.news[i:]
	if len(st.news) < s.newCount || (!st.reported.IsZero() && now.Sub(st.reported) < s.newWindow) {
		if len(st.news) > s.newCount {
			st.news = st.news[len(st.news)-s.newCount:]
		}
		return nil
	}
	n := len(st.news)
	sample := slices.Clone(st.recent)
	st.reported, st.news, st.recent = now, nil, nil
	return &Finding{
		Kind: KindNewDestinations, Subject: sub, Title: "新しい宛先の急増", Severity: event.SeverityMedium,
		Message: fmt.Sprintf("機器 %s が %s の間に、これまで使わなかった %d 個の宛先に問い合わせました（例: %s）",
			sub.Name, roundDuration(s.newWindow), n, strings.Join(sample, "、")),
		Details: map[string]any{"count": n, "window_s": int64(s.newWindow.Seconds()), "sample": sample},
	}
}

// pruneDestsLocked は、最も長く使っていない機器の宛先を捨てる。
func (d *Detector) pruneDestsLocked() {
	type entry struct {
		key  string
		last time.Time
	}
	var all []entry
	for k, st := range d.dests {
		var last time.Time
		for _, t := range st.Known {
			if t.After(last) {
				last = t
			}
		}
		all = append(all, entry{k, last})
	}
	slices.SortFunc(all, func(a, b entry) int { return a.last.Compare(b.last) })
	for _, e := range all[:len(all)/4+1] {
		delete(d.dests, e.key)
	}
	d.dirty = true
}

// --- 時間外の通信 ---

type offState struct {
	since    time.Time // 数え始めた時刻
	bytes    uint64
	reported time.Time
}

func (d *Detector) offHoursLocked(sub Subject, f Flow, now time.Time) *Finding {
	s := &d.s
	if !d.enabled[KindOffHours] || !slices.Contains(s.offGroups, sub.Group) {
		return nil
	}
	at := cmp.Or(f.End, f.Time)
	if s.business(at) {
		return nil
	}
	o := d.offs[sub.Key]
	if o == nil {
		if len(d.offs) >= maxSubjects {
			clear(d.offs)
		}
		o = &offState{since: at}
		d.offs[sub.Key] = o
	}
	if at.Sub(o.since) > 12*time.Hour {
		o.since, o.bytes = at, 0
	}
	o.bytes += f.BytesOut + f.BytesIn
	if o.bytes < max(s.offMinBytes, 1) || (!o.reported.IsZero() && now.Sub(o.reported) < s.offCooldown) {
		return nil
	}
	total := o.bytes
	o.reported, o.since, o.bytes = now, at, 0
	lt := at.In(s.offLoc)
	return &Finding{
		Kind: KindOffHours, Subject: sub, Title: "時間外の通信", Severity: event.SeverityLow,
		Dst:     &event.Endpoint{IP: f.Dst.Addr().String(), Port: int(f.Dst.Port()), Hostname: f.Hostname},
		Traffic: &event.Traffic{BytesOut: int64(f.BytesOut), BytesIn: int64(f.BytesIn)},
		Message: fmt.Sprintf("機器 %s が業務時間の外（%s）に %s を通信しました", sub.Name, lt.Format("01-02 15:04 MST"), formatBytes(total)),
		Details: map[string]any{"bytes": total, "local_time": lt.Format(time.RFC3339)},
	}
}

// --- 覚えた宛先の保存 ---

// Snapshot は覚えた宛先（新しい宛先の急増の学習）を JSON で返す。保存していない変更がなければ nil を返す。
func (d *Detector) Snapshot(force bool) []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.dirty && !force {
		return nil
	}
	data, err := json.Marshal(d.dests)
	if err != nil {
		return nil
	}
	d.dirty = false
	return data
}

// Restore は Snapshot で保存した宛先を読み込む。
func (d *Detector) Restore(data []byte) error {
	var dests map[string]*destState
	if err := json.Unmarshal(data, &dests); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, st := range dests {
		if st == nil || k == "" {
			continue
		}
		if st.Known == nil {
			st.Known = map[string]time.Time{}
		}
		d.dests[k] = st
	}
	return nil
}

// --- 表示 ---

func roundDuration(d time.Duration) string {
	switch {
	case d >= time.Hour:
		return d.Round(time.Minute).String()
	case d >= time.Minute:
		return d.Round(time.Second).String()
	case d >= time.Second:
		return d.Round(100 * time.Millisecond).String()
	}
	return d.Round(time.Millisecond).String()
}

func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d バイト", n)
	}
	v, i := float64(n), -1
	for v >= unit && i < 3 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.1f %s", v, []string{"KiB", "MiB", "GiB", "TiB"}[i])
}
