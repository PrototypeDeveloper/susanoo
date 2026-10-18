package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/fsutil"
	"susanoo/internal/platform"
	"susanoo/internal/policy"
)

// device は端末台帳の 1 件（M1）。CLIENT の証明書の ID で識別する。
type device struct {
	ID             string                `json:"id"`
	Group          string                `json:"group,omitempty"`
	Addr           netip.Addr            `json:"addr,omitzero"`
	Hostname       string                `json:"hostname,omitempty"`
	FirstSeen      time.Time             `json:"first_seen"`
	LastSeen       time.Time             `json:"last_seen"`
	BootID         string                `json:"boot_id,omitempty"`
	Counter        uint64                `json:"counter,omitempty"`
	Features       []platform.Capability `json:"features,omitempty"`
	Applied        policy.IsolationLevel `json:"applied,omitempty"`         // CLIENT が報告した自己隔離の状態
	AppliedVersion uint64                `json:"applied_version,omitempty"` // CLIENT が報告した適用済みの版数

	Isolation policy.IsolationLevel `json:"isolation,omitempty"` // 指示している隔離
	Reason    string                `json:"reason,omitempty"`
	Since     time.Time             `json:"since,omitzero"`
	Version   uint64                `json:"version,omitempty"`  // 指示の版数
	Evidence  uint64                `json:"evidence,omitempty"` // 証拠を集める要求の番号（C11）
	Pending   string                `json:"pending,omitempty"`  // 承認待ちの隔離の理由
	Lost      bool                  `json:"lost,omitempty"`     // ハートビートの途絶を検知済み
	Away      bool                  `json:"away,omitempty"`     // ハートビートが途絶え、LAN にもいない（不在）

	CertExpiry time.Time `json:"cert_expiry,omitzero"` // 端末が最後に示した証明書の有効期限
	Revoked    time.Time `json:"revoked,omitzero"`     // 証明書を失効させた時刻
}

func (d *device) view(macs []string) api.Device {
	v := api.Device{
		ID:        d.ID,
		Group:     d.Group,
		Hostname:  d.Hostname,
		MACs:      macs,
		LastSeen:  d.LastSeen,
		Isolation: d.Isolation,
		Applied:   d.Applied,
		Reason:    d.Reason,
		Since:     d.Since,
		Pending:   d.Pending,
		Away:      d.Away,
		Features:  slices.Clone(d.Features),

		CertExpiry: d.CertExpiry,
		Revoked:    d.Revoked,
	}
	if v.Group == "" {
		v.Group = policy.DefaultGroup
	}
	if d.Addr.IsValid() {
		v.Addr = d.Addr.String()
	}
	return v
}

// host は LAN の機器の台帳の 1 件（G8）。MAC アドレスで識別する。
// CLIENT のある機器は DeviceID で端末と結び付く。CLIENT のない機器の隔離は、ここに記録する。
type host struct {
	MAC       string                `json:"mac"`
	IP        netip.Addr            `json:"ip,omitzero"`
	Hostname  string                `json:"hostname,omitempty"`
	FirstSeen time.Time             `json:"first_seen"`
	LastSeen  time.Time             `json:"last_seen"`
	Lease     time.Time             `json:"lease,omitzero"`  // DHCP の割り当ての期限
	Group     string                `json:"group,omitempty"` // CLIENT のない機器のグループ
	DeviceID  string                `json:"device_id,omitempty"`
	Isolation policy.IsolationLevel `json:"isolation,omitempty"`
	Reason    string                `json:"reason,omitempty"`
	Since     time.Time             `json:"since,omitzero"`
	Pending   string                `json:"pending,omitempty"`

	spoofAt time.Time // 最後になりすましを検知した時刻（保存しない）
}

func (h *host) view(group string) api.Host {
	v := api.Host{
		MAC:       h.MAC,
		Hostname:  h.Hostname,
		Group:     group,
		DeviceID:  h.DeviceID,
		FirstSeen: h.FirstSeen,
		LastSeen:  h.LastSeen,
		Lease:     h.Lease,
		Isolation: h.Isolation,
		Reason:    h.Reason,
		Since:     h.Since,
		Pending:   h.Pending,
	}
	if h.IP.IsValid() {
		v.IP = h.IP.String()
	}
	return v
}

// nextVersion は指示の新しい版数を返す。CONTROLLER の台帳が失われて版数が戻っても、
// CLIENT が適用済みの版数を下回らないよう、時刻（ナノ秒）以上の値にする。
func nextVersion(cur uint64, now time.Time) uint64 {
	return max(cur+1, uint64(now.UnixNano()))
}

type registryFile struct {
	Devices []*device `json:"devices"`
	Hosts   []*host   `json:"hosts"`
}

func loadRegistry(path string) (map[string]*device, map[string]*host, error) {
	devices, hosts := map[string]*device{}, map[string]*host{}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return devices, hosts, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var f registryFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, nil, fmt.Errorf("controller: 端末台帳 %s を解析できません: %w", path, err)
	}
	for _, d := range f.Devices {
		devices[d.ID] = d
	}
	for _, h := range f.Hosts {
		hosts[h.MAC] = h
	}
	return devices, hosts, nil
}

func saveRegistry(path string, devices map[string]*device, hosts map[string]*host) error {
	f := registryFile{Devices: make([]*device, 0, len(devices)), Hosts: make([]*host, 0, len(hosts))}
	for _, d := range devices {
		f.Devices = append(f.Devices, d)
	}
	for _, h := range hosts {
		f.Hosts = append(f.Hosts, h)
	}
	slices.SortFunc(f.Devices, func(a, b *device) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(f.Hosts, func(a, b *host) int { return strings.Compare(a.MAC, b.MAC) })
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, append(data, '\n'), 0o600)
}
