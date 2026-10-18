package controller

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/pki"
	"susanoo/internal/version"
)

// 全体の状態の表示とイベントの検索（M8）。

const (
	// certWarning より期限が近い端末の証明書は、更新が止まっているとみなして知らせる
	// （CLIENT は期限の 3 分の 1、90 日の証明書なら 30 日前から更新する）。
	certWarning    = 14 * 24 * time.Hour
	recentFindings = 10
)

// getStatus は全体の状態を返す。
func (c *Controller) getStatus(w http.ResponseWriter, _ *http.Request, _ pki.Identity) {
	now := c.now()
	c.mu.Lock()
	st := api.Status{Version: version.Version, StartedAt: c.started, Response: c.pol.Response, CertExpiry: c.certExpiry()}
	info := c.policyInfoLocked()
	st.Policy, st.Canary = info.Current, info.Canary
	for _, d := range c.devices {
		n := &st.Devices
		n.Total++
		switch {
		case !d.Revoked.IsZero():
			n.Revoked++
		case d.Away:
			n.Away++
		case !d.Lost && now.Sub(d.LastSeen) <= c.cfg.HeartbeatTimeout:
			n.Online++
		}
		if d.Isolation != "" {
			n.Isolated++
		}
		if d.Pending != "" {
			n.Pending++
		}
		if !d.CertExpiry.IsZero() && d.CertExpiry.Sub(now) < certWarning && d.Revoked.IsZero() {
			st.ExpiringCerts = append(st.ExpiringCerts, c.deviceViewLocked(d))
		}
	}
	for _, h := range c.hosts {
		n := &st.Hosts
		n.Total++
		if c.devices[h.DeviceID] == nil {
			n.Unregistered++
			if h.Isolation != "" {
				n.Isolated++
			}
			if h.Pending != "" {
				n.Pending++
			}
		}
	}
	st.Risky = c.riskyLocked()
	c.mu.Unlock()
	st.Rules = c.rulesVersion()
	st.Intel = c.intelSummary()
	slices.SortFunc(st.ExpiringCerts, func(a, b api.Device) int { return a.CertExpiry.Compare(b.CertExpiry) })

	classFilter := []byte(`"class_uid":` + strconv.Itoa(int(event.ClassDetectionFinding)) + `,`)
	if lines, err := c.events.Query(time.Time{}, recentFindings, func(line []byte) bool { return bytes.Contains(line, classFilter) }); err == nil {
		for _, l := range lines {
			var e event.Event
			if json.Unmarshal(l, &e) == nil {
				st.RecentFindings = append(st.RecentFindings, e)
			}
		}
	}
	writeJSON(w, http.StatusOK, st)
}

// certExpiry は CONTROLLER の証明書の期限を返す。
func (c *Controller) certExpiry() time.Time {
	cert := c.cert.Load()
	if cert.Leaf != nil {
		return cert.Leaf.NotAfter
	}
	if len(cert.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			return leaf.NotAfter
		}
	}
	return time.Time{}
}

// searchEvents は保存したイベントを検索する。新しいものから指定の件数までを、古い順に返す。
func (c *Controller) searchEvents(w http.ResponseWriter, r *http.Request, _ pki.Identity) {
	q, err := api.ParseEventQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	class, _ := q.ClassUID()
	minSeverity, _ := q.MinSeverity()
	var classFilter []byte
	if class != 0 {
		classFilter = []byte(`"class_uid":` + strconv.Itoa(int(class)) + `,`)
	}
	since, until := q.Since.UnixMilli(), q.Until.UnixMilli()
	match := func(line []byte) bool {
		if classFilter != nil && !bytes.Contains(line, classFilter) {
			return false // 解析する前に絞り込む
		}
		if q.Text != "" && !bytes.Contains(line, []byte(q.Text)) {
			return false
		}
		var e event.Event
		if json.Unmarshal(line, &e) != nil {
			return false
		}
		switch {
		case class != 0 && e.ClassUID != class,
			e.SeverityID < minSeverity,
			!q.Since.IsZero() && e.Time < since,
			!q.Until.IsZero() && e.Time > until,
			q.Device != "" && !eventOf(&e, q.Device):
			return false
		}
		return true
	}
	lines, err := c.events.Query(q.Since, q.Limit, match)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]json.RawMessage, len(lines))
	for i, l := range lines {
		out[i] = l
	}
	writeJSON(w, http.StatusOK, out)
}

// eventOf は、イベントが端末か機器 who（端末 ID、アドレス、MAC アドレス、ホスト名）のものかを返す。
func eventOf(e *event.Event, who string) bool {
	var ids []string
	if d := e.Device; d != nil {
		ids = append(ids, d.UID, d.IP, d.MAC, d.Hostname)
	}
	if s := e.SrcEndpoint; s != nil {
		ids = append(ids, s.UID, s.IP, s.MAC)
	}
	for _, id := range ids {
		if id != "" && strings.EqualFold(id, who) {
			return true
		}
	}
	return false
}
