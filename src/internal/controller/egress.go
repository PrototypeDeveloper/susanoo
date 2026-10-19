package controller

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/egress"
	"susanoo/internal/event"
	"susanoo/internal/fsutil"
	"susanoo/internal/policy"
)

// Egress は外部通信の制御（G2）。端末のグループと隔離の状態を受け取る。
type Egress interface {
	SetMembership(ctx context.Context, m egress.Membership) error
}

// maxLearned は、学習モードで通した名前と遮断した名前の記録の上限。
const maxLearned = 20000

// 監査ログに記録するグループの変更。
const (
	ActionDeviceGroup = "device.group"
	ActionHostGroup   = "host.group"
)

type learnedKey struct {
	group, domain string
	blocked       bool
	addr, proto   string // 直接指定したアドレスへの通信（domain は空。2m-2）
	port          int
}

// learnedLog は、学習モードで通した名前と遮断した名前の記録。DNS の問い合わせごとに更新するので、
// 台帳とは別のロックで守る。
type learnedLog struct {
	mu      sync.Mutex
	entries map[learnedKey]*api.Learned
	dirty   bool
	full    bool // 上限に達したことを記録済み
}

func (c *Controller) learnedPath() string { return filepath.Join(c.cfg.Dir, "learned.json") }

func loadLearned(path string) (map[learnedKey]*api.Learned, error) {
	entries := map[learnedKey]*api.Learned{}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return entries, nil
	}
	if err != nil {
		return nil, err
	}
	var list []*api.Learned
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("controller: 学習の記録 %s を解析できません: %w", path, err)
	}
	for _, l := range list {
		entries[learnedKey{group: l.Group, domain: l.Domain, blocked: l.Blocked, addr: l.Address, proto: l.Protocol, port: l.Port}] = l
	}
	return entries, nil
}

// RecordLearned は、学習モードで通した名前（blocked が false）と遮断した名前（true）を記録する。
func (c *Controller) RecordLearned(group, domain string, blocked bool) {
	now := c.now()
	l := &c.learned
	l.mu.Lock()
	defer l.mu.Unlock()
	key := learnedKey{group: group, domain: domain, blocked: blocked}
	e := l.entries[key]
	if e == nil {
		if len(l.entries) >= maxLearned {
			if !l.full {
				l.full = true
				c.log.Warn("学習の記録が上限に達しました。新しい名前は記録しません", "上限", maxLearned)
			}
			return
		}
		e = &api.Learned{Group: group, Domain: domain, Blocked: blocked, First: now}
		l.entries[key] = e
	}
	e.Count++
	e.Last = now
	l.dirty = true
}

// learnedList は記録を、グループ、遮断の有無、回数の多い順に並べて返す。
func (c *Controller) learnedList() []api.Learned {
	c.learned.mu.Lock()
	out := make([]api.Learned, 0, len(c.learned.entries))
	for _, e := range c.learned.entries {
		out = append(out, *e)
	}
	c.learned.mu.Unlock()
	slices.SortFunc(out, func(a, b api.Learned) int {
		if c := strings.Compare(a.Group, b.Group); c != 0 {
			return c
		}
		if a.Blocked != b.Blocked {
			if a.Blocked {
				return 1
			}
			return -1
		}
		return cmp.Or(b.Count-a.Count, strings.Compare(learnedLabel(a), learnedLabel(b)))
	})
	return out
}

func (c *Controller) saveLearned(force bool) {
	l := &c.learned
	l.mu.Lock()
	if !l.dirty && !force {
		l.mu.Unlock()
		return
	}
	l.dirty = false
	l.mu.Unlock()
	data, err := json.MarshalIndent(c.learnedList(), "", "  ")
	if err == nil {
		err = fsutil.WriteFileAtomic(c.learnedPath(), append(data, '\n'), 0o600)
	}
	if err != nil {
		c.log.Error("学習の記録を保存できません", "エラー", err)
	}
}

// DNSRecord は GW のリゾルバが受けた 1 件の問い合わせ。
type DNSRecord struct {
	Time    time.Time
	Client  netip.Addr
	Name    string
	Type    uint16
	Rcode   int
	Answers []string
	Action  string // forward、block、nodata、refuse
	Reason  string
	Group   string
}

var dnsTypes = map[uint16]string{1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS"}

// RecordDNS は DNS の問い合わせを OCSF の DNS Activity として保存する（G3 の問い合わせの記録）。
func (c *Controller) RecordDNS(r DNSRecord) {
	sub, t, s := c.behaviorTarget(subject{ip: r.Client})
	deviceID := t.device

	sev := event.SeverityInformational
	if r.Action == "block" || r.Action == "refuse" {
		sev = event.SeverityLow
	}
	e := event.New(event.ClassDNSActivity, event.DNSActivityResponse, sev, r.Time)
	typ, ok := dnsTypes[r.Type]
	if !ok {
		typ = fmt.Sprintf("TYPE%d", r.Type)
	}
	e.Query = &event.DNSQuery{Hostname: r.Name, Type: typ, Class: "IN"}
	for _, a := range r.Answers {
		e.Answers = append(e.Answers, event.DNSAnswer{Rdata: a})
	}
	rcode := r.Rcode
	e.RcodeID = &rcode
	if r.Client.IsValid() {
		e.SrcEndpoint = &event.Endpoint{IP: r.Client.String(), UID: deviceID}
		e.Device = &event.Device{UID: deviceID, IP: r.Client.String()}
	}
	e.Unmapped = map[string]any{"dns": map[string]any{"action": r.Action, "reason": r.Reason, "group": r.Group}}
	c.observe(e, s)
	c.checkOutsideLAN("dns", r.Client)
	if r.Action == "forward" && r.Rcode == 0 && r.Group != "" {
		c.rememberAnswers(r.Group, r.Answers, c.now())
	}
	if r.Client.IsValid() {
		c.reportBehavior(c.detector.DNS(sub, r.Name, c.now()), t, s)
		c.intelDNS(r, t, s)
	}
}

// deviceByAddrLocked は、アドレス ip を使っている端末の ID を返す。なければ空。
func (c *Controller) deviceByAddrLocked(ip netip.Addr) string {
	for _, d := range c.devices {
		if d.Addr == ip {
			return d.ID
		}
	}
	for _, h := range c.hosts {
		if h.hasAddr(ip) && h.DeviceID != "" {
			return h.DeviceID
		}
	}
	return ""
}

// hostGroupLocked は機器のグループを返す。端末に結び付いた機器は端末のグループ。
func (c *Controller) hostGroupLocked(h *host) string {
	g := h.Group
	if d := c.devices[h.DeviceID]; d != nil {
		g = d.Group
	}
	if g == "" {
		g = policy.DefaultGroup
	}
	return g
}

// pushMembershipLocked は、端末のグループと隔離の状態を外部通信の制御に渡す。
func (c *Controller) pushMembershipLocked(isolated map[netip.Addr]policy.IsolationLevel) {
	if c.cfg.Egress == nil {
		return
	}
	m := egress.Membership{MACs: map[string]string{}, IPs: map[netip.Addr]string{}, Isolated: isolated}
	for _, h := range c.hosts {
		g := c.effectiveGroupLocked(c.hostGroupLocked(h), c.hostCanaryLocked(h))
		if g == policy.DefaultGroup {
			continue
		}
		m.MACs[h.MAC] = g
		for _, a := range h.addrs() {
			m.IPs[a] = g // DNS の問い合わせ元のアドレスでグループを決めるため、IPv6 アドレスも渡す
		}
	}
	for _, d := range c.devices {
		if g := c.effectiveGroupLocked(d.Group, c.deviceCanaryLocked(d)); g != policy.DefaultGroup && d.Addr.IsValid() {
			m.IPs[d.Addr] = g
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), enforceTimeout)
	defer cancel()
	if err := c.cfg.Egress.SetMembership(ctx, m); err != nil {
		c.log.Error("外部通信の制御に端末のグループを反映できません", "エラー", err)
	}
}

// refreshMembershipLocked は、隔離の状態を含めて所属を作り直して渡す。
func (c *Controller) refreshMembershipLocked() {
	addrs, _ := c.isolationLocked()
	c.pushMembershipLocked(addrs)
}

// validGroup はグループの名前を確かめる。既定のグループなら空を返す（台帳には空で記録する）。
func (c *Controller) validGroup(group string) (string, error) {
	if group == "" || group == policy.DefaultGroup {
		return "", nil
	}
	if !c.pol.HasGroup(group) && (c.canaryPol == nil || !c.canaryPol.HasGroup(group)) {
		return "", fmt.Errorf("ポリシーにないグループです: %q", group)
	}
	return group, nil
}
