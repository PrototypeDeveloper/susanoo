// Package dhcp は GW の DHCPv4 サーバー（G8）を実装する。
//
// 同じ機器（MAC アドレス）にはできるだけ同じアドレスを渡し続け、割り当ては状態ファイルに記録する。
// 割り当てるたびに OnLease で知らせ、CONTROLLER の台帳に反映する。リレー経由の要求には対応しない。
package dhcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"susanoo/internal/fsutil"
)

// 既定値。
const (
	DefaultLeaseTime = time.Hour
	offerTimeout     = 30 * time.Second // OFFER した後、REQUEST を待つ時間
	declineHold      = 10 * time.Minute // DECLINE されたアドレスを使わない時間
	maxRange         = 1 << 16
)

// Lease はアドレスの割り当て。
type Lease struct {
	MAC      string     `json:"mac"`
	IP       netip.Addr `json:"ip"`
	Hostname string     `json:"hostname,omitempty"`
	Expiry   time.Time  `json:"expiry"`
}

// Config は DHCP サーバーの設定。
type Config struct {
	ServerIP   netip.Addr   // GW の LAN 側のアドレス
	Prefix     netip.Prefix // LAN のネットワーク
	RangeStart netip.Addr   // 割り当てる範囲の最初
	RangeEnd   netip.Addr   // 割り当てる範囲の最後
	Router     netip.Addr   // 既定のゲートウェイ（通常は ServerIP）
	DNS        []netip.Addr // DNS サーバー
	LeaseTime  time.Duration
	StatePath  string // 割り当ての記録

	// OnLease は割り当てと解放を知らせる。released が true なら解放。
	OnLease func(l Lease, released bool)
	// Avoid が true を返すアドレスは割り当てない（隔離中の機器が使っていたアドレスなど）。
	Avoid func(netip.Addr) bool

	Logger *slog.Logger
	Now    func() time.Time
}

// Server は DHCP サーバー。
type Server struct {
	cfg Config
	log *slog.Logger

	mu       sync.Mutex
	leases   map[string]*Lease     // MAC → 割り当て（期限切れも残して、同じアドレスを渡すのに使う）
	byIP     map[netip.Addr]string // アドレス → MAC
	declined map[netip.Addr]time.Time
}

// New は設定を確かめ、記録を読み込んでサーバーを作る。
func New(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.LeaseTime <= 0 {
		cfg.LeaseTime = DefaultLeaseTime
	}
	if !cfg.Router.IsValid() {
		cfg.Router = cfg.ServerIP
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, log: cfg.Logger, leases: map[string]*Lease{}, byIP: map[netip.Addr]string{}, declined: map[netip.Addr]time.Time{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (c *Config) validate() error {
	if !c.ServerIP.Is4() || !c.Prefix.Addr().Is4() || !c.Prefix.Contains(c.ServerIP) {
		return errors.New("dhcp: サーバーのアドレスは LAN のネットワークの中の IPv4 アドレスにしてください")
	}
	if !c.Prefix.Contains(c.RangeStart) || !c.Prefix.Contains(c.RangeEnd) || c.RangeEnd.Less(c.RangeStart) {
		return fmt.Errorf("dhcp: 割り当ての範囲 %s-%s が LAN のネットワーク %s の中にありません", c.RangeStart, c.RangeEnd, c.Prefix)
	}
	if size(c.RangeStart, c.RangeEnd) > maxRange {
		return errors.New("dhcp: 割り当ての範囲が広すぎます")
	}
	return nil
}

func size(start, end netip.Addr) int {
	s, e := start.As4(), end.As4()
	return int(uint32(e[0])<<24|uint32(e[1])<<16|uint32(e[2])<<8|uint32(e[3])) -
		int(uint32(s[0])<<24|uint32(s[1])<<16|uint32(s[2])<<8|uint32(s[3])) + 1
}

// ParseRange は "10.0.0.100-10.0.0.199" の形の範囲を解析する。
func ParseRange(s string) (netip.Addr, netip.Addr, error) {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("範囲 %q は「最初-最後」の形で書いてください", s)
	}
	start, err1 := netip.ParseAddr(strings.TrimSpace(a))
	end, err2 := netip.ParseAddr(strings.TrimSpace(b))
	if err1 != nil || err2 != nil || !start.Is4() || !end.Is4() {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("範囲 %q のアドレスを解析できません", s)
	}
	return start, end, nil
}

// Handle は受信したメッセージへの応答を返す。応答しない場合は nil。
func (s *Server) Handle(req *Message) *Message {
	if req.Op != opRequest || req.HType != htypeEthernet || req.HLen != 6 {
		return nil
	}
	if req.GIAddr.IsValid() && !req.GIAddr.IsUnspecified() {
		return nil // リレー経由の要求には対応しない
	}
	mac := req.CHAddr.String()
	now := s.cfg.Now()

	s.mu.Lock()
	defer s.mu.Unlock()
	switch req.Type() {
	case Discover:
		ip, ok := s.allocateLocked(mac, req.AddrOption(OptRequestedIP), now)
		if !ok {
			s.log.Warn("DHCP: 割り当てられるアドレスがありません", "MAC", mac)
			return nil
		}
		name := hostname(req)
		if l := s.leases[mac]; l != nil && l.IP == ip && l.Expiry.After(now) {
			if name != "" {
				l.Hostname = name
			}
		} else {
			s.setLocked(&Lease{MAC: mac, IP: ip, Hostname: name, Expiry: now.Add(offerTimeout)})
		}
		return s.reply(req, Offer, ip)

	case Request:
		server := req.AddrOption(OptServerID)
		if server.IsValid() && server != s.cfg.ServerIP {
			return nil // クライアントは別のサーバーを選んだ
		}
		ip := req.AddrOption(OptRequestedIP)
		if !ip.IsValid() {
			ip = req.CIAddr
		}
		if !ip.Is4() || ip.IsUnspecified() {
			return nil
		}
		if !s.assignableLocked(mac, ip, now) {
			s.log.Info("DHCP: 要求されたアドレスを渡せません", "MAC", mac, "アドレス", ip)
			return s.reply(req, Nak, netip.Addr{})
		}
		name := hostname(req)
		if prev := s.leases[mac]; name == "" && prev != nil {
			name = prev.Hostname // REQUEST にホスト名がなければ、DISCOVER のときの名前を使う
		}
		l := &Lease{MAC: mac, IP: ip, Hostname: name, Expiry: now.Add(s.cfg.LeaseTime)}
		s.setLocked(l)
		s.saveLocked()
		if s.cfg.OnLease != nil {
			s.cfg.OnLease(*l, false)
		}
		return s.reply(req, Ack, ip)

	case Release:
		if l := s.leases[mac]; l != nil && l.IP == req.CIAddr {
			l.Expiry = now
			s.saveLocked()
			if s.cfg.OnLease != nil {
				s.cfg.OnLease(*l, true)
			}
		}
		return nil

	case Decline:
		ip := req.AddrOption(OptRequestedIP)
		if ip.IsValid() {
			s.declined[ip] = now.Add(declineHold)
			if l := s.leases[mac]; l != nil && l.IP == ip {
				delete(s.leases, mac)
				delete(s.byIP, ip)
				s.saveLocked()
			}
			s.log.Warn("DHCP: アドレスが使用中と報告されました", "MAC", mac, "アドレス", ip)
		}
		return nil

	case Inform:
		r := s.reply(req, Ack, netip.Addr{})
		r.CIAddr = req.CIAddr
		delete(r.Options, OptLeaseTime)
		delete(r.Options, OptRenewalTime)
		delete(r.Options, OptRebindTime)
		return r
	}
	return nil
}

// allocateLocked は mac に渡すアドレスを選ぶ。前回のアドレス、要求されたアドレス、
// 使われたことのないアドレス、期限の切れたアドレスの順に探す。
func (s *Server) allocateLocked(mac string, requested netip.Addr, now time.Time) (netip.Addr, bool) {
	if l := s.leases[mac]; l != nil && s.usableLocked(mac, l.IP, now) {
		return l.IP, true
	}
	if requested.IsValid() && s.usableLocked(mac, requested, now) {
		return requested, true
	}
	for _, reclaim := range []bool{false, true} {
		for ip := s.cfg.RangeStart; !s.cfg.RangeEnd.Less(ip); ip = ip.Next() {
			if _, used := s.byIP[ip]; used && !reclaim {
				continue
			}
			if s.usableLocked(mac, ip, now) {
				return ip, true
			}
		}
	}
	return netip.Addr{}, false
}

// usableLocked は ip を mac に新しく渡せるかを返す。
func (s *Server) usableLocked(mac string, ip netip.Addr, now time.Time) bool {
	if !s.inRange(ip) || ip == s.cfg.ServerIP || ip == s.cfg.Router {
		return false
	}
	if until, ok := s.declined[ip]; ok && now.Before(until) {
		return false
	}
	if owner, ok := s.byIP[ip]; ok && owner != mac {
		if l := s.leases[owner]; l != nil && l.Expiry.After(now) {
			return false
		}
	}
	if s.cfg.Avoid != nil && s.cfg.Avoid(ip) {
		if l := s.leases[mac]; l == nil || l.IP != ip {
			return false
		}
	}
	return true
}

// assignableLocked は REQUEST で求められた ip を mac に渡してよいかを返す。
// 記録がなくても、範囲の中の空いているアドレスなら渡す（サーバーの再起動後の更新など）。
func (s *Server) assignableLocked(mac string, ip netip.Addr, now time.Time) bool {
	if l := s.leases[mac]; l != nil && l.IP == ip {
		return true
	}
	return s.usableLocked(mac, ip, now)
}

func (s *Server) inRange(ip netip.Addr) bool {
	return ip.Is4() && !ip.Less(s.cfg.RangeStart) && !s.cfg.RangeEnd.Less(ip)
}

func (s *Server) setLocked(l *Lease) {
	if old := s.leases[l.MAC]; old != nil && s.byIP[old.IP] == l.MAC {
		delete(s.byIP, old.IP)
	}
	if prev, ok := s.byIP[l.IP]; ok && prev != l.MAC {
		delete(s.leases, prev)
	}
	s.leases[l.MAC] = l
	s.byIP[l.IP] = l.MAC
}

func (s *Server) reply(req *Message, t MessageType, yiaddr netip.Addr) *Message {
	r := &Message{
		Op:      opReply,
		HType:   htypeEthernet,
		HLen:    6,
		XID:     req.XID,
		Flags:   req.Flags,
		YIAddr:  yiaddr,
		CHAddr:  slices.Clone(req.CHAddr),
		Options: map[byte][]byte{OptMessageType: {byte(t)}},
	}
	r.SetAddrs(OptServerID, s.cfg.ServerIP)
	if t == Nak {
		return r
	}
	lease := uint32(s.cfg.LeaseTime / time.Second)
	r.SetUint32(OptLeaseTime, lease)
	r.SetUint32(OptRenewalTime, lease/2)
	r.SetUint32(OptRebindTime, lease/8*7)
	mask := net4Mask(s.cfg.Prefix.Bits())
	r.Options[OptSubnetMask] = mask[:]
	r.SetAddrs(OptRouter, s.cfg.Router)
	r.SetAddrs(OptDNS, s.cfg.DNS...)
	return r
}

func net4Mask(bits int) [4]byte {
	m := ^uint32(0) << (32 - bits)
	return [4]byte{byte(m >> 24), byte(m >> 16), byte(m >> 8), byte(m)}
}

// hostname はクライアントが名乗ったホスト名を、表示できる文字だけにして返す。
func hostname(m *Message) string {
	v := m.Options[OptHostname]
	b := make([]byte, 0, len(v))
	for _, c := range v {
		if c >= 0x21 && c <= 0x7e && len(b) < 63 {
			b = append(b, c)
		}
	}
	return string(b)
}

// Leases は割り当ての一覧を返す。
func (s *Server) Leases() []Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Lease, 0, len(s.leases))
	for _, l := range s.leases {
		out = append(out, *l)
	}
	slices.SortFunc(out, func(a, b Lease) int { return a.IP.Compare(b.IP) })
	return out
}

type stateFile struct {
	Leases []Lease `json:"leases"`
}

func (s *Server) load() error {
	if s.cfg.StatePath == "" {
		return nil
	}
	data, err := os.ReadFile(s.cfg.StatePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var st stateFile
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("dhcp: 割り当ての記録 %s を解析できません: %w", s.cfg.StatePath, err)
	}
	for i := range st.Leases {
		l := st.Leases[i]
		if s.inRange(l.IP) {
			s.setLocked(&l)
		}
	}
	return nil
}

func (s *Server) saveLocked() {
	if s.cfg.StatePath == "" {
		return
	}
	st := stateFile{Leases: make([]Lease, 0, len(s.leases))}
	for _, l := range s.leases {
		st.Leases = append(st.Leases, *l)
	}
	slices.SortFunc(st.Leases, func(a, b Lease) int { return a.IP.Compare(b.IP) })
	data, err := json.MarshalIndent(st, "", "  ")
	if err == nil {
		err = fsutil.WriteFileAtomic(s.cfg.StatePath, append(data, '\n'), 0o600)
	}
	if err != nil {
		s.log.Error("DHCP: 割り当ての記録を保存できません", "エラー", err)
	}
}
