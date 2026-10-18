// Package behavior は GW の振る舞いの検知（G6）を実装する。
//
// CONTROLLER に集まる GW の観測（外へ転送した通信の記録、DNS の問い合わせ、LAN の ARP の要求）から、次の振る舞いを検知する。
//
//   - 周期的な通信（beacon）：同じ機器から同じ宛先への接続の始まりが、ほぼ一定の間隔で続く（C2 のビーコンの疑い）
//   - 大量の送信（large_upload）：一定の時間に外へ送った量が多い（データの持ち出しの疑い）
//   - LAN 内のスキャン（internal_scan）：短い間に、LAN の多くのアドレスを ARP で探す（偵察と横展開の疑い）
//   - 新しい宛先の急増（new_destinations）：平常時（学習の期間）に使わなかった宛先（ドメイン）への問い合わせが急に増える
//   - 時間外の通信（off_hours）：決めたグループの機器が、業務時間の外に通信する
//
// 検知した振る舞いは検知結果として CONTROLLER に返し、検知ルール（rules）で点を付けて危険度に加える。
// 誤検知が出やすいため、既定のルールは試験運用（monitor）とし、例外で平常の通信を除いてから加点にする。
package behavior

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	_ "time/tzdata" // 時間帯の名前（Asia/Tokyo など）を、OS の時間帯の情報によらず解決するため

	"susanoo/internal/config"
)

// Config は振る舞いの検知の設定（検知ルールの behavior）。0 の項目は既定値を使う。
// 検知を止めるときは、その検知結果のルール（beacon など）の mode を off にする。
type Config struct {
	Beacon          Beacon          `json:"beacon,omitzero"`
	LargeUpload     LargeUpload     `json:"large_upload,omitzero"`
	InternalScan    InternalScan    `json:"internal_scan,omitzero"`
	NewDestinations NewDestinations `json:"new_destinations,omitzero"`
	OffHours        OffHours        `json:"off_hours,omitzero"`
}

// Beacon は周期的な通信の検知の設定。宛先は、SNI か HTTP の Host が分かればその名前、なければアドレスとし、
// ポートとプロトコルごとに数える。NTP（UDP 123）は時刻合わせで必ず周期的になるため対象にしない。
type Beacon struct {
	MinCount     int             `json:"min_count,omitempty"`     // 判断に使う接続の数の下限。既定 8（3〜16）
	MinInterval  config.Duration `json:"min_interval,omitempty"`  // 間隔の平均の下限。既定 10s
	MaxInterval  config.Duration `json:"max_interval,omitempty"`  // 間隔の平均の上限。既定 2h
	MaxJitter    float64         `json:"max_jitter,omitempty"`    // 間隔のばらつき（標準偏差÷平均）の上限。既定 0.15
	ExcludePorts []uint16        `json:"exclude_ports,omitempty"` // 対象にしない宛先のポート
	Cooldown     config.Duration `json:"cooldown,omitempty"`      // 同じ宛先を再び知らせるまでの時間。既定 6h
}

// LargeUpload は大量の送信の検知の設定。通信量は接続の終わりの記録で数える（長く続く接続は終わったときに数える）。
type LargeUpload struct {
	Bytes  int64           `json:"bytes,omitempty"`  // window の間に外へ送った量の上限。既定 512 MiB
	Window config.Duration `json:"window,omitempty"` // 既定 1h
}

// InternalScan は LAN 内のスキャンの検知の設定。
type InternalScan struct {
	Targets int             `json:"targets,omitempty"` // window の間に ARP で探したアドレスの数の上限。既定 30
	Window  config.Duration `json:"window,omitempty"`  // 既定 1m
}

// NewDestinations は新しい宛先の急増の検知の設定。宛先は、問い合わせた名前と SNI を登録できる単位
// （example.co.jp など）にまとめて数える。機器を初めて見てから baseline の間は、宛先を覚えるだけにする（学習の期間）。
type NewDestinations struct {
	Count    int             `json:"count,omitempty"`    // window の間の新しい宛先の数の上限。既定 50
	Window   config.Duration `json:"window,omitempty"`   // 既定 1h
	Baseline config.Duration `json:"baseline,omitempty"` // 学習の期間。既定 72h
}

// OffHours は時間外の通信の検知の設定。groups を書いたときだけ検知する。
type OffHours struct {
	Groups   []string        `json:"groups,omitempty"`    // 対象のグループ
	Days     []string        `json:"days"`                // 業務日（mon〜sun）。省略すると mon〜fri。空にすると毎日を時間外とする
	Start    string          `json:"start,omitempty"`     // 業務の始まり（15:04 の形）。既定 08:00
	End      string          `json:"end,omitempty"`       // 業務の終わり。既定 20:00。start より前なら日をまたぐ
	Timezone string          `json:"timezone,omitempty"`  // 時間帯（Asia/Tokyo など）。既定は GW の時間帯
	MinBytes int64           `json:"min_bytes,omitempty"` // 時間外に通信した量がこれを超えたら知らせる。既定 10 MiB
	Cooldown config.Duration `json:"cooldown,omitempty"`  // 同じ機器を再び知らせるまでの時間。既定 8h
}

// 既定値。
const (
	DefaultBeaconMinCount    = 8
	DefaultBeaconMinInterval = 10 * time.Second
	DefaultBeaconMaxInterval = 2 * time.Hour
	DefaultBeaconMaxJitter   = 0.15
	DefaultBeaconCooldown    = 6 * time.Hour
	DefaultUploadBytes       = 512 << 20
	DefaultUploadWindow      = time.Hour
	DefaultScanTargets       = 30
	DefaultScanWindow        = time.Minute
	DefaultNewDestCount      = 50
	DefaultNewDestWindow     = time.Hour
	DefaultNewDestBaseline   = 72 * time.Hour
	DefaultOffHoursStart     = "08:00"
	DefaultOffHoursEnd       = "20:00"
	DefaultOffHoursMinBytes  = 10 << 20
	DefaultOffHoursCooldown  = 8 * time.Hour
	maxBeaconHistory         = 16
)

var defaultDays = []string{"mon", "tue", "wed", "thu", "fri"}

var dayNames = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

// settings は既定値を埋めて解釈した設定。
type settings struct {
	beaconMinCount         int
	beaconMin, beaconMax   time.Duration
	beaconJitter           float64
	beaconExclude          []uint16
	beaconCooldown         time.Duration
	uploadBytes            uint64
	uploadWindow           time.Duration
	scanTargets            int
	scanWindow             time.Duration
	newCount               int
	newWindow, newBaseline time.Duration
	offGroups              []string
	offDays                [7]bool
	offStart, offEnd       int // 0 時からの分
	offLoc                 *time.Location
	offMinBytes            uint64
	offCooldown            time.Duration
}

// Validate は設定を確かめる。問題をまとめて返す。
func (c *Config) Validate() error {
	_, err := c.settings()
	return err
}

func (c *Config) settings() (settings, error) {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf("behavior: "+format, args...)) }
	b := c.Beacon
	s := settings{
		beaconMinCount: or(b.MinCount, DefaultBeaconMinCount),
		beaconMin:      b.MinInterval.Or(DefaultBeaconMinInterval),
		beaconMax:      b.MaxInterval.Or(DefaultBeaconMaxInterval),
		beaconJitter:   b.MaxJitter,
		beaconExclude:  b.ExcludePorts,
		beaconCooldown: b.Cooldown.Or(DefaultBeaconCooldown),
		uploadBytes:    uint64(or(c.LargeUpload.Bytes, DefaultUploadBytes)),
		uploadWindow:   c.LargeUpload.Window.Or(DefaultUploadWindow),
		scanTargets:    or(c.InternalScan.Targets, DefaultScanTargets),
		scanWindow:     c.InternalScan.Window.Or(DefaultScanWindow),
		newCount:       or(c.NewDestinations.Count, DefaultNewDestCount),
		newWindow:      c.NewDestinations.Window.Or(DefaultNewDestWindow),
		newBaseline:    c.NewDestinations.Baseline.Or(DefaultNewDestBaseline),
		offGroups:      c.OffHours.Groups,
		offMinBytes:    uint64(or(c.OffHours.MinBytes, DefaultOffHoursMinBytes)),
		offCooldown:    c.OffHours.Cooldown.Or(DefaultOffHoursCooldown),
		offLoc:         time.Local,
	}
	if s.beaconJitter == 0 {
		s.beaconJitter = DefaultBeaconMaxJitter
	}
	if s.beaconMinCount < 3 || s.beaconMinCount > maxBeaconHistory {
		add("beacon.min_count は 3 から %d にしてください", maxBeaconHistory)
	}
	if s.beaconMin < 100*time.Millisecond || s.beaconMax > 24*time.Hour || s.beaconMin >= s.beaconMax {
		add("beacon.min_interval と max_interval は 100ms から 24h の間で、min_interval を小さくしてください")
	}
	if s.beaconJitter <= 0 || s.beaconJitter > 1 {
		add("beacon.max_jitter は 0 より大きく 1 以下にしてください")
	}
	if slices.Contains(s.beaconExclude, 0) {
		add("beacon.exclude_ports にポート 0 は書けません")
	}
	if s.beaconCooldown > 7*24*time.Hour {
		add("beacon.cooldown は 7 日以下にしてください")
	}
	if c.LargeUpload.Bytes < 0 || (c.LargeUpload.Bytes > 0 && c.LargeUpload.Bytes < 1024) {
		add("large_upload.bytes は 1024 以上にしてください")
	}
	if s.uploadWindow < time.Minute || s.uploadWindow > 24*time.Hour {
		add("large_upload.window は 1 分から 24 時間にしてください")
	}
	if s.scanTargets < 5 || s.scanTargets > 1024 {
		add("internal_scan.targets は 5 から 1024 にしてください")
	}
	if s.scanWindow < time.Second || s.scanWindow > time.Hour {
		add("internal_scan.window は 1 秒から 1 時間にしてください")
	}
	if s.newCount < 3 || s.newCount > 10000 {
		add("new_destinations.count は 3 から 10000 にしてください")
	}
	if s.newWindow < time.Minute || s.newWindow > 24*time.Hour {
		add("new_destinations.window は 1 分から 24 時間にしてください")
	}
	if s.newBaseline > 90*24*time.Hour {
		add("new_destinations.baseline は 90 日以下にしてください")
	}
	o := c.OffHours
	for _, g := range o.Groups {
		if g == "" || strings.Contains(g, "~") {
			add("off_hours.groups のグループ名 %q が不正です", g)
		}
	}
	days := o.Days
	if days == nil {
		days = defaultDays
	}
	for _, d := range days {
		wd, ok := dayNames[d]
		if !ok {
			add("off_hours.days の %q は mon、tue、wed、thu、fri、sat、sun のどれかにしてください", d)
			continue
		}
		s.offDays[wd] = true
	}
	var err error
	if s.offStart, err = parseClock(cmpOr(o.Start, DefaultOffHoursStart)); err != nil {
		add("off_hours.start: %v", err)
	}
	if s.offEnd, err = parseClock(cmpOr(o.End, DefaultOffHoursEnd)); err != nil {
		add("off_hours.end: %v", err)
	}
	if err == nil && s.offStart == s.offEnd {
		add("off_hours.start と end を同じにはできません")
	}
	if o.Timezone != "" {
		if s.offLoc, err = time.LoadLocation(o.Timezone); err != nil {
			add("off_hours.timezone %q が分かりません", o.Timezone)
		}
	}
	if o.MinBytes < 0 {
		add("off_hours.min_bytes は 0 以上にしてください")
	}
	if s.offCooldown > 7*24*time.Hour {
		add("off_hours.cooldown は 7 日以下にしてください")
	}
	return s, errors.Join(errs...)
}

func parseClock(s string) (int, error) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, fmt.Errorf("%q は 08:00 のような時刻で書いてください", s)
	}
	return t.Hour()*60 + t.Minute(), nil
}

func or[T int | int64](v, def T) T {
	if v == 0 {
		return def
	}
	return v
}

func cmpOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// business は、時刻 t が業務時間の内かを返す。
func (s *settings) business(t time.Time) bool {
	lt := t.In(s.offLoc)
	minute := lt.Hour()*60 + lt.Minute()
	if s.offStart < s.offEnd {
		return s.offDays[lt.Weekday()] && minute >= s.offStart && minute < s.offEnd
	}
	// 日をまたぐ業務時間（22:00〜06:00 など）は、始まりの日で業務日かを判断する。
	if minute >= s.offStart {
		return s.offDays[lt.Weekday()]
	}
	if minute < s.offEnd {
		return s.offDays[(lt.Weekday()+6)%7]
	}
	return false
}
