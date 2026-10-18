package controller

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/intel"
	"susanoo/internal/pki"
	"susanoo/internal/sign"
)

// 脅威情報（G7）。
//
// 管理者が署名した脅威情報を受け取り、CONTROLLER も署名を確かめてから、GW の執行部（IntelManager）に渡す。
// 執行部は署名と版数を確かめて保存し、遮断の一覧のアドレスを nftables で落とし、ドメインを LAN 側の処理（DNS）に渡す。
// CONTROLLER は、DNS の問い合わせ（名前と応答）と通信の宛先（アドレス、SNI、HTTP の Host）をすべての一覧と照合し、
// 検知結果（threat_intel）にして検知ルールで評価する。同じ機器と同じ項目の検知結果は、intelRepeat に 1 回にまとめる。

const (
	ActionIntelApply = "intel.apply"
	intelTimeout     = 2 * time.Minute // 大きな一覧を nftables に入れる時間を見込む
	intelRepeat      = 10 * time.Minute
	maxIntelSeen     = 8192
)

// IntelManager は署名付きの脅威情報を確かめて保存し、GW に反映する（GW の執行部が満たす）。
type IntelManager interface {
	ApplyIntel(ctx context.Context, env sign.Envelope) error
}

// initIntel は、執行部が使っている脅威情報で照合を始める。
func (c *Controller) initIntel() {
	c.intelM.Store(intel.NewMatcher(c.cfg.IntelSet))
}

func intelInfo(s *intel.Set) api.IntelInfo {
	info := api.IntelInfo{Lists: []api.IntelListInfo{}}
	if s == nil {
		return info
	}
	info.Version, info.IssuedAt = s.Version, s.IssuedAt
	for _, l := range s.Lists {
		info.Lists = append(info.Lists, api.IntelListInfo{Name: l.Name, Action: string(l.Action), Source: l.Source, Updated: l.Updated, Domains: len(l.Domains), CIDRs: len(l.CIDRs)})
	}
	return info
}

func (c *Controller) getIntel(w http.ResponseWriter, _ *http.Request, _ pki.Identity) {
	writeJSON(w, http.StatusOK, intelInfo(c.intelM.Load().Set))
}

// getIntelPayload は今の版の中身を返す（ctl が一覧を足したり消したりして、署名し直すのに使う）。
func (c *Controller) getIntelPayload(w http.ResponseWriter, _ *http.Request, _ pki.Identity) {
	s := c.intelM.Load().Set
	if s == nil {
		writeError(w, http.StatusNotFound, "脅威情報はまだ配布していません")
		return
	}
	writeJSON(w, http.StatusOK, s)
}

// checkIntel は、名前かアドレスが脅威情報のどの一覧に当てはまるかを返す。
func (c *Controller) checkIntel(w http.ResponseWriter, r *http.Request, _ pki.Identity) {
	q := r.URL.Query().Get("q")
	m := c.intelM.Load()
	var ms []intel.Match
	if a, err := netip.ParseAddr(q); err == nil {
		ms = m.Addr(a)
	} else if d := intel.NormalizeDomain(q); d != "" {
		ms = m.Domain(d)
	} else {
		writeError(w, http.StatusBadRequest, "名前かアドレスを指定してください")
		return
	}
	out := []api.IntelMatch{}
	for _, x := range ms {
		out = append(out, api.IntelMatch{List: x.List, Action: string(x.Action), Indicator: x.Indicator})
	}
	writeJSON(w, http.StatusOK, out)
}

// pushIntel は署名付きの脅威情報を受け取り、執行部に反映させてから、照合に使う。
func (c *Controller) pushIntel(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, api.MaxIntelBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("本文が大きすぎます（%d バイトまで）", api.MaxIntelBytes))
		return
	}
	var req api.IntelPush
	if err := strictUnmarshal(data, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if c.cfg.Intel == nil || c.cfg.RulesKey == nil {
		writeError(w, http.StatusServiceUnavailable, "この CONTROLLER では脅威情報を配布できません")
		return
	}
	v, err := sign.NewVerifier(c.cfg.RulesKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	set, err := intel.ParseSigned(v, req.Envelope)
	if err != nil {
		writeError(w, http.StatusBadRequest, "脅威情報を適用できません: "+err.Error())
		return
	}
	if cur := c.intelM.Load().Set; cur != nil && set.Version <= cur.Version {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("脅威情報を適用できません: 版数 %d は今の版数 %d より新しくありません", set.Version, cur.Version))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), intelTimeout)
	defer cancel()
	if err := c.cfg.Intel.ApplyIntel(ctx, req.Envelope); err != nil {
		writeError(w, http.StatusBadRequest, "脅威情報を適用できません: "+err.Error())
		return
	}
	c.intelM.Store(intel.NewMatcher(set))
	info := intelInfo(set)
	actor := "admin/" + admin.ID
	c.mu.Lock()
	c.auditLocked(actor, ActionIntelApply, strconv.Itoa(set.Version), netip.Addr{}, map[string]any{"lists": info.Lists})
	c.mu.Unlock()
	c.log.Warn("脅威情報を適用しました", "版数", set.Version, "一覧", len(set.Lists), "操作", actor)
	writeJSON(w, http.StatusOK, info)
}

// intelHit は照合で当てはまった 1 件。
type intelHit struct {
	match   intel.Match
	what    string // 照合した値（名前かアドレス）
	dst     *event.Endpoint
	blocked bool // GW が遮断した
	dns     bool
}

// reportIntel は、当てはまった項目を検知結果にする（同じ機器と項目は intelRepeat に 1 回）。
func (c *Controller) reportIntel(h intelHit, t target, s subject) {
	now := c.now()
	// 遮断した試みと、遮断していない通信は別に数える（遮断が効いていることを確かめられるように）。
	key := fmt.Sprint(cmp.Or(t.key, s.ip.String()), "\x00", h.match.List, "\x00", h.match.Indicator, "\x00", h.blocked)
	c.mu.Lock()
	if c.intelSeen == nil {
		c.intelSeen = map[string]time.Time{}
	}
	if at, ok := c.intelSeen[key]; ok && now.Sub(at) < intelRepeat && now.Sub(at) >= 0 {
		c.mu.Unlock()
		return
	}
	if len(c.intelSeen) >= maxIntelSeen {
		for k, at := range c.intelSeen {
			if now.Sub(at) >= intelRepeat {
				delete(c.intelSeen, k)
			}
		}
		if len(c.intelSeen) >= maxIntelSeen {
			clear(c.intelSeen)
		}
	}
	c.intelSeen[key] = now
	c.mu.Unlock()

	name := t.name()
	if name == "-" && s.ip.IsValid() {
		name = s.ip.String()
	}
	verb, title := "接続しようとしました", "脅威情報に当てはまる通信"
	if h.dns {
		verb, title = "問い合わせました", "脅威情報に当てはまる問い合わせ"
	}
	result := "検知だけしています"
	switch {
	case h.blocked:
		result = "GW で遮断しました"
	case h.match.Action == intel.ActionBlock:
		result = "遮断の一覧です"
	}
	msg := fmt.Sprintf("機器 %s が、脅威情報の一覧「%s」にある %s（%s）に%s（%s）", name, h.match.List, h.what, h.match.Indicator, verb, result)
	dev := &event.Device{UID: t.device, MAC: cmp.Or(t.mac, s.mac)}
	if s.ip.IsValid() {
		dev.IP = s.ip.String()
	}
	e := c.finding(event.FindingTypeThreatIntel, title, msg, event.SeverityHigh, dev)
	e.DstEndpoint = h.dst
	e.Unmapped = map[string]any{"intel": map[string]any{"list": h.match.List, "action": string(h.match.Action), "indicator": h.match.Indicator, "blocked": h.blocked}}
	c.observe(e, s)
}

// intelDNS は DNS の問い合わせの名前と応答を脅威情報と照合する。
func (c *Controller) intelDNS(r DNSRecord, t target, s subject) {
	m := c.intelM.Load()
	if m.Empty() {
		return
	}
	if ms := m.Domain(r.Name); len(ms) > 0 {
		c.reportIntel(intelHit{match: ms[0], what: r.Name, dst: &event.Endpoint{Hostname: r.Name}, blocked: r.Action == "block" && ms[0].Action == intel.ActionBlock, dns: true}, t, s)
		return
	}
	for _, a := range r.Answers {
		var ms []intel.Match
		if ip, err := netip.ParseAddr(a); err == nil {
			ms = m.Addr(ip)
		} else {
			ms = m.Domain(a)
		}
		if len(ms) > 0 {
			c.reportIntel(intelHit{match: ms[0], what: r.Name + " → " + a, dst: &event.Endpoint{Hostname: r.Name}, dns: true}, t, s)
			return
		}
	}
}

// intelFlow は通信の宛先（アドレスと、SNI か HTTP の Host）を脅威情報と照合する。
func (c *Controller) intelFlow(r FlowRecord, t target, s subject) {
	m := c.intelM.Load()
	if m.Empty() {
		return
	}
	host := cmp.Or(r.SNI, r.HTTPHost)
	dst := &event.Endpoint{IP: r.Dst.Addr().String(), Port: int(r.Dst.Port()), Hostname: host}
	addr := net.JoinHostPort(r.Dst.Addr().String(), strconv.Itoa(int(r.Dst.Port())))
	if ms := m.Addr(r.Dst.Addr()); len(ms) > 0 {
		c.reportIntel(intelHit{match: ms[0], what: addr, dst: dst, blocked: r.Blocked}, t, s)
		return
	}
	if host != "" {
		if ms := m.Domain(host); len(ms) > 0 {
			c.reportIntel(intelHit{match: ms[0], what: host, dst: dst}, t, s)
		}
	}
}

// intelSummary は全体の状態に載せる脅威情報の概要を返す。
func (c *Controller) intelSummary() api.IntelInfo { return intelInfo(c.intelM.Load().Set) }
