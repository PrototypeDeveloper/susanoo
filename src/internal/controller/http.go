package controller

import (
	"bytes"
	"cmp"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/pki"
	"susanoo/internal/policy"
	"susanoo/internal/sign"
	"susanoo/internal/transport"
)

type handlerFunc func(w http.ResponseWriter, r *http.Request, id pki.Identity)

// Handler は管理通信の HTTP ハンドラーを返す。
func (c *Controller) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST "+api.PathHeartbeat, c.require(pki.RoleClient, c.heartbeat))
	mux.Handle("POST "+api.PathEvents, c.require(pki.RoleClient, c.postEvents))
	mux.Handle("GET "+api.PathDevices, c.require(pki.RoleAdmin, c.listDevices))
	mux.Handle("POST "+api.PathDevices+"/{id}/isolate", c.require(pki.RoleAdmin, c.isolateDevice))
	mux.Handle("POST "+api.PathDevices+"/{id}/release", c.require(pki.RoleAdmin, c.releaseDevice))
	mux.Handle("GET "+api.PathHosts, c.require(pki.RoleAdmin, c.listHosts))
	mux.Handle("POST "+api.PathHosts+"/{mac}/isolate", c.require(pki.RoleAdmin, c.isolateHost))
	mux.Handle("POST "+api.PathHosts+"/{mac}/release", c.require(pki.RoleAdmin, c.releaseHost))
	mux.Handle("POST "+api.PathDevices+"/{id}/group", c.require(pki.RoleAdmin, c.setDeviceGroup))
	mux.Handle("POST "+api.PathHosts+"/{mac}/group", c.require(pki.RoleAdmin, c.setHostGroup))
	mux.Handle("GET "+api.PathLearned, c.require(pki.RoleAdmin, c.listLearned))
	mux.Handle("GET "+api.PathLearnedSuggest, c.require(pki.RoleAdmin, c.suggestAllow))
	mux.Handle("POST "+api.PathCertificate, c.require(pki.RoleClient, c.renewCertificate))
	mux.Handle("POST "+api.PathDevices+"/{id}/revoke", c.require(pki.RoleAdmin, c.revokeDevice))
	mux.Handle("GET "+api.PathStatus, c.require(pki.RoleAdmin, c.getStatus))
	mux.Handle("GET "+api.PathEvents, c.require(pki.RoleAdmin, c.searchEvents))
	mux.Handle("GET "+api.PathPolicy, c.require(pki.RoleAdmin, c.getPolicy))
	mux.Handle("GET "+api.PathPolicy+"/versions/{version}", c.require(pki.RoleAdmin, c.getPolicyVersion))
	mux.Handle("POST "+api.PathPolicy, c.require(pki.RoleAdmin, c.pushPolicy))
	mux.Handle("POST "+api.PathPolicy+"/promote", c.require(pki.RoleAdmin, c.promotePolicy))
	mux.Handle("POST "+api.PathPolicy+"/abort", c.require(pki.RoleAdmin, c.abortPolicy))
	mux.Handle("GET "+api.PathRules, c.require(pki.RoleAdmin, c.getRules))
	mux.Handle("GET "+api.PathRules+"/versions/{version}", c.require(pki.RoleAdmin, c.getRulesVersion))
	mux.Handle("POST "+api.PathRules, c.require(pki.RoleAdmin, c.pushRules))
	mux.Handle("GET "+api.PathIntel, c.require(pki.RoleAdmin, c.getIntel))
	mux.Handle("GET "+api.PathIntel+"/payload", c.require(pki.RoleAdmin, c.getIntelPayload))
	mux.Handle("GET "+api.PathIntel+"/check", c.require(pki.RoleAdmin, c.checkIntel))
	mux.Handle("POST "+api.PathIntel, c.require(pki.RoleAdmin, c.pushIntel))
	mux.Handle("POST "+api.PathEvidence, c.require(pki.RoleClient, c.postEvidence))
	mux.Handle("GET "+api.PathEvidence, c.require(pki.RoleAdmin, c.listEvidence))
	mux.Handle("GET "+api.PathEvidence+"/{device}/{id}", c.require(pki.RoleAdmin, c.getEvidence))
	mux.Handle("POST "+api.PathDevices+"/{id}/evidence", c.require(pki.RoleAdmin, c.requestEvidence))
	mux.Handle("POST "+api.PathNotifyTest, c.require(pki.RoleAdmin, c.testNotify))
	mux.Handle("GET "+api.PathIncidents, c.require(pki.RoleAdmin, c.listIncidents))
	mux.Handle("POST "+api.PathIncidents, c.require(pki.RoleAdmin, c.openIncident))
	mux.Handle("GET "+api.PathIncidents+"/{id}", c.require(pki.RoleAdmin, c.getIncident))
	mux.Handle("POST "+api.PathIncidents+"/{id}", c.require(pki.RoleAdmin, c.updateIncident))
	mux.Handle("POST "+api.PathIncidents+"/{id}/steps/{step}", c.require(pki.RoleAdmin, c.updateStep))
	mux.Handle("GET "+api.PathIncidents+"/{id}/timeline", c.require(pki.RoleAdmin, c.incidentTimeline))
	mux.Handle("POST "+api.PathEnrollCodes, c.require(pki.RoleAdmin, c.createEnrollCode))
	mux.Handle("GET "+api.PathEnrollCodes, c.require(pki.RoleAdmin, c.listEnrollCodes))
	mux.Handle("DELETE "+api.PathEnrollCodes+"/{id}", c.require(pki.RoleAdmin, c.deleteEnrollCode))
	mux.HandleFunc("POST "+api.PathEnroll, c.enrollDevice) // 証明書なしで受け付ける唯一の窓口
	mux.Handle("GET "+api.PathReleases, c.require(pki.RoleAdmin, c.getRelease))
	mux.Handle("POST "+api.PathReleases, c.require(pki.RoleAdmin, c.pushRelease))
	mux.Handle("PUT "+api.PathReleases+"/files/{os}/{arch}", c.require(pki.RoleAdmin, c.uploadRelease))
	mux.Handle("GET "+api.PathReleases+"/files/{os}/{arch}", c.require(pki.RoleClient, c.downloadRelease))
	mux.Handle("POST "+api.PathReleases+"/promote", c.require(pki.RoleAdmin, c.promoteRelease))
	mux.Handle("POST "+api.PathReleases+"/abort", c.require(pki.RoleAdmin, c.abortRelease))
	return noCertGate(mux)
}

// require は接続相手の役割が role の場合だけ h を呼ぶ。
func (c *Controller) require(role pki.Role, h handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			writeError(w, http.StatusForbidden, "相互TLSで接続してください")
			return
		}
		id, err := transport.PeerIdentity(*r.TLS)
		if err != nil || id.Role != role {
			writeError(w, http.StatusForbidden, "この操作は許可されていません")
			return
		}
		// 失効させる前からの接続（HTTP/2 で続いているもの）も、要求ごとに確かめて拒む。
		if c.revokedCert(r.TLS.PeerCertificates[0]) {
			writeError(w, http.StatusForbidden, errRevoked.Error())
			return
		}
		h(w, r, id)
	})
}

func (c *Controller) heartbeat(w http.ResponseWriter, r *http.Request, id pki.Identity) {
	var env sign.Envelope
	if !decode(w, r, &env) {
		return
	}
	// ハートビートは、相互TLSで示した証明書の鍵で署名されている必要がある。
	pub, ok := r.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		writeError(w, http.StatusBadRequest, "ed25519 の証明書ではありません")
		return
	}
	v, err := sign.NewVerifier(pub)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	payload, err := v.Verify(sign.PurposeHeartbeat, env)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	var hb api.Heartbeat
	if err := strictUnmarshal(payload, &hb); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if hb.DeviceID != id.ID {
		writeError(w, http.StatusForbidden, "証明書と異なる端末 ID です")
		return
	}
	addr := remoteAddr(r)

	c.mu.Lock()
	d := c.ensureLocked(id.ID, addr)
	now := c.now()
	if hb.BootID == d.BootID && hb.Counter <= d.Counter {
		c.mu.Unlock()
		writeError(w, http.StatusConflict, "古いハートビートです")
		return
	}
	d.BootID, d.Counter = hb.BootID, hb.Counter
	d.Hostname = hb.Hostname
	d.Features = slices.Clone(hb.Capabilities.Features)
	d.Applied, d.AppliedVersion = hb.Isolation, hb.Applied
	d.AppControl = hb.AppControl
	c.recordSoftwareLocked(d, hb)
	c.recordResourcesLocked(d, hb)
	skew := c.recordClockLocked(d, hb, now)
	cert := r.TLS.PeerCertificates[0]
	d.CertExpiry = cert.NotAfter
	if !d.Revoked.IsZero() && pki.IssuedAt(cert).After(d.Revoked) {
		d.Revoked = time.Time{} // 失効の後に発行し直した証明書で入れ直した
	}
	c.touchLocked(d, addr)
	cmd, err := c.commandLocked(d)
	lag := c.checkLagLocked(d, hb.Applied, now)
	c.mu.Unlock()
	for _, f := range []*event.Event{skew, lag} {
		if f != nil {
			c.observe(f, subject{device: id.ID})
		}
	}
	respond(w, cmd, err)
}

func (c *Controller) postEvents(w http.ResponseWriter, r *http.Request, id pki.Identity) {
	var batch api.EventBatch
	if !decode(w, r, &batch) {
		return
	}
	if len(batch.Events) > api.MaxEventsPerBatch {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("イベントは 1 回に %d 件までです", api.MaxEventsPerBatch))
		return
	}
	addr := remoteAddr(r)
	c.mu.Lock()
	c.touchLocked(c.ensureLocked(id.ID, addr), addr)
	c.mu.Unlock()

	for i := range batch.Events {
		e := &batch.Events[i]
		// 端末の識別は、CLIENT の申告ではなく証明書による。
		if e.Device == nil {
			e.Device = &event.Device{}
		}
		e.Device.UID = id.ID
		if addr.IsValid() {
			e.Device.IP = addr.String()
		}
		if err := e.Validate(); err != nil {
			c.log.Warn("不正なイベントを捨てました", "端末", id.ID, "エラー", err)
			continue
		}
		// 検知ルールで評価し、危険度がしきい値を超えたら隔離する（既定のルールでは、おとりへの接触と大量の変更）。
		c.observe(e, subject{device: id.ID})
		if e.FindingInfo.HasType(event.FindingTypeARPPoisoning) {
			c.reportARPPoisoning(id.ID, e)
		}
	}

	c.mu.Lock()
	cmd, err := c.commandLocked(c.devices[id.ID])
	c.mu.Unlock()
	respond(w, cmd, err)
}

// respond は端末への指示を応答として返す。応答の書き込みはロックの外で行う。
func respond(w http.ResponseWriter, cmd sign.Envelope, err error) {
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, api.Desired{Command: cmd})
}

func (c *Controller) listDevices(w http.ResponseWriter, r *http.Request, _ pki.Identity) {
	c.mu.Lock()
	out := make([]api.Device, 0, len(c.devices))
	for _, d := range c.devices {
		out = append(out, c.deviceViewLocked(d))
	}
	c.mu.Unlock()
	slices.SortFunc(out, func(a, b api.Device) int { return strings.Compare(a.ID, b.ID) })
	writeJSON(w, http.StatusOK, out)
}

func (c *Controller) isolateDevice(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	var req api.IsolateRequest
	if !decodeOptional(w, r, &req) {
		return
	}
	c.mu.Lock()
	d := c.devices[r.PathValue("id")]
	if d == nil {
		c.mu.Unlock()
		writeError(w, http.StatusNotFound, "台帳にない端末です")
		return
	}
	level := req.Level
	if level == "" {
		level = c.groupLocked(d.Group, c.deviceCanaryLocked(d)).Isolation
	}
	if !validLevel(level) {
		c.mu.Unlock()
		writeError(w, http.StatusBadRequest, fmt.Sprintf("不明な隔離の段階です: %q", level))
		return
	}
	reason := req.Reason
	if reason == "" {
		reason = d.Pending
	}
	if reason == "" {
		reason = ReasonAdmin
	}
	if d.Isolation != level {
		c.isolateLocked(d, level, reason, "admin/"+admin.ID)
	}
	view := c.deviceViewLocked(d)
	c.mu.Unlock()
	writeJSON(w, http.StatusOK, view)
}

func (c *Controller) releaseDevice(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	c.mu.Lock()
	d := c.devices[r.PathValue("id")]
	if d == nil {
		c.mu.Unlock()
		writeError(w, http.StatusNotFound, "台帳にない端末です")
		return
	}
	if d.Isolation != "" || d.Pending != "" {
		c.releaseLocked(d, "admin/"+admin.ID)
	}
	view := c.deviceViewLocked(d)
	c.mu.Unlock()
	writeJSON(w, http.StatusOK, view)
}

func validLevel(l policy.IsolationLevel) bool {
	switch l {
	case policy.IsolateFull, policy.IsolateManagement, policy.IsolateManagementAndUpdates:
		return true
	}
	return false
}

func (c *Controller) listHosts(w http.ResponseWriter, r *http.Request, _ pki.Identity) {
	c.mu.Lock()
	out := make([]api.Host, 0, len(c.hosts))
	for _, h := range c.hosts {
		out = append(out, c.hostViewLocked(h))
	}
	c.mu.Unlock()
	slices.SortFunc(out, func(a, b api.Host) int { return strings.Compare(a.MAC, b.MAC) })
	writeJSON(w, http.StatusOK, out)
}

// isolateHost は LAN の機器を隔離する。端末に結び付いた機器なら、端末を隔離する（自己隔離も指示する）。
func (c *Controller) isolateHost(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	var req api.IsolateRequest
	if !decodeOptional(w, r, &req) {
		return
	}
	hw, err := net.ParseMAC(r.PathValue("mac"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "MAC アドレスの形が正しくありません")
		return
	}
	c.mu.Lock()
	h := c.hosts[hw.String()]
	if h == nil {
		c.mu.Unlock()
		writeError(w, http.StatusNotFound, "台帳にない機器です")
		return
	}
	d := c.devices[h.DeviceID]
	level := req.Level
	if level == "" {
		level = c.groupLocked(c.hostGroupLocked(h), c.hostCanaryLocked(h)).Isolation
	}
	if !validLevel(level) {
		c.mu.Unlock()
		writeError(w, http.StatusBadRequest, fmt.Sprintf("不明な隔離の段階です: %q", level))
		return
	}
	reason := cmp.Or(req.Reason, h.Pending, ReasonAdmin)
	actor := "admin/" + admin.ID
	switch {
	case d != nil && d.Isolation != level:
		c.isolateLocked(d, level, cmp.Or(req.Reason, d.Pending, ReasonAdmin), actor)
	case d == nil && h.Isolation != level:
		c.isolateHostLocked(h, level, reason, actor)
	}
	view := c.hostViewLocked(h)
	c.mu.Unlock()
	writeJSON(w, http.StatusOK, view)
}

// releaseHost は LAN の機器の隔離を解除する。端末に結び付いた機器なら、端末の隔離も解除する。
func (c *Controller) releaseHost(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	hw, err := net.ParseMAC(r.PathValue("mac"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "MAC アドレスの形が正しくありません")
		return
	}
	c.mu.Lock()
	h := c.hosts[hw.String()]
	if h == nil {
		c.mu.Unlock()
		writeError(w, http.StatusNotFound, "台帳にない機器です")
		return
	}
	actor := "admin/" + admin.ID
	if d := c.devices[h.DeviceID]; d != nil && (d.Isolation != "" || d.Pending != "") {
		c.releaseLocked(d, actor)
	}
	if h.Isolation != "" || h.Pending != "" {
		c.releaseHostLocked(h, actor)
	}
	view := c.hostViewLocked(h)
	c.mu.Unlock()
	writeJSON(w, http.StatusOK, view)
}

// setDeviceGroup は端末のグループを変える。端末に結び付いた機器も同じグループになる。
func (c *Controller) setDeviceGroup(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	var req api.GroupRequest
	if !decode(w, r, &req) {
		return
	}
	group, err := c.validGroup(req.Group)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	c.mu.Lock()
	d := c.devices[r.PathValue("id")]
	if d == nil {
		c.mu.Unlock()
		writeError(w, http.StatusNotFound, "台帳にない端末です")
		return
	}
	if d.Group != group {
		prev := d.Group
		d.Group = group
		c.saveLocked()
		c.auditLocked("admin/"+admin.ID, ActionDeviceGroup, d.ID, d.Addr, map[string]any{"group": req.Group, "previous": prev})
		c.refreshMembershipLocked()
	}
	view := c.deviceViewLocked(d)
	c.mu.Unlock()
	writeJSON(w, http.StatusOK, view)
}

// setHostGroup は CLIENT のない機器のグループを変える。端末に結び付いた機器は、端末のグループを変える。
func (c *Controller) setHostGroup(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	var req api.GroupRequest
	if !decode(w, r, &req) {
		return
	}
	group, err := c.validGroup(req.Group)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hw, err := net.ParseMAC(r.PathValue("mac"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "MAC アドレスの形が正しくありません")
		return
	}
	c.mu.Lock()
	h := c.hosts[hw.String()]
	if h == nil {
		c.mu.Unlock()
		writeError(w, http.StatusNotFound, "台帳にない機器です")
		return
	}
	if d := c.devices[h.DeviceID]; d != nil {
		c.mu.Unlock()
		writeError(w, http.StatusConflict, fmt.Sprintf("端末 %s に結び付いた機器です。端末のグループを変えてください", d.ID))
		return
	}
	if h.Group != group {
		prev := h.Group
		h.Group = group
		c.saveLocked()
		c.auditLocked("admin/"+admin.ID, ActionHostGroup, h.MAC, h.IP, map[string]any{"group": req.Group, "previous": prev})
		c.refreshMembershipLocked()
	}
	view := c.hostViewLocked(h)
	c.mu.Unlock()
	writeJSON(w, http.StatusOK, view)
}

func (c *Controller) listLearned(w http.ResponseWriter, r *http.Request, _ pki.Identity) {
	writeJSON(w, http.StatusOK, c.learnedList())
}

func remoteAddr(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// decode は本文の JSON を v に読む。失敗したらエラーを応答して false を返す。
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, api.MaxBodyBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "本文が大きすぎます")
		return false
	}
	if err := strictUnmarshal(data, v); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return false
	}
	return true
}

// decodeOptional は decode と同じだが、本文が空なら何もしない。
func decodeOptional(w http.ResponseWriter, r *http.Request, v any) bool {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, api.MaxBodyBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "本文が大きすぎます")
		return false
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return true
	}
	if err := strictUnmarshal(data, v); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return false
	}
	return true
}

func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("JSON を解析できません: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON の後に余分なデータがあります")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, api.Error{Error: msg})
}
