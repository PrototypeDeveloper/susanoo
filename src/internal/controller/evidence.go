package controller

import (
	"cmp"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/event"
	"susanoo/internal/fsutil"
	"susanoo/internal/pki"
	"susanoo/internal/sign"
)

// 証拠の保全（C11）。CLIENT の執行部が集めて端末の鍵で署名した証拠を受け取り、署名を確かめてから、署名付きのまま
// 状態のディレクトリの evidence/<端末>/ に保存する。中身のハッシュは監査ログに記録する（後から差し替えられていないことを
// 確かめられるように）。端末ごとに新しいものから maxEvidencePerDevice 個を残す。

const (
	evidenceDir           = "evidence"
	evidenceIndexFile     = "index.json"
	maxEvidencePerDevice  = 20
	ActionEvidenceReceive = "evidence.receive"
	ActionEvidenceRequest = "evidence.request"
)

var evidenceIDPattern = regexp.MustCompile(`^[A-Z2-7]{26}$`)

// initEvidence は保存した証拠の一覧を読む。
func (c *Controller) initEvidence() error {
	data, err := os.ReadFile(filepath.Join(c.cfg.Dir, evidenceDir, evidenceIndexFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &c.evidence); err != nil {
		return fmt.Errorf("controller: 証拠の一覧を解析できません: %w", err)
	}
	return nil
}

func (c *Controller) evidencePath(device, id string, at time.Time) string {
	return filepath.Join(c.cfg.Dir, evidenceDir, device, fmt.Sprintf("%013d-%s.json", at.UnixMilli(), id))
}

// postEvidence は CLIENT から証拠を受け取る。
func (c *Controller) postEvidence(w http.ResponseWriter, r *http.Request, id pki.Identity) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, api.MaxEvidenceBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "本文が大きすぎます")
		return
	}
	var up api.EvidenceUpload
	if err := strictUnmarshal(data, &up); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// 証拠は、相互TLSで示した証明書の鍵（執行部だけが持つ）で署名されている必要がある。
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
	payload, err := v.Verify(sign.PurposeEvidence, up.Envelope)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if len(payload) > api.MaxEvidencePayload {
		writeError(w, http.StatusRequestEntityTooLarge, "証拠が大きすぎます")
		return
	}
	var ev api.Evidence
	if err := strictUnmarshal(payload, &ev); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	switch {
	case ev.DeviceID != id.ID:
		writeError(w, http.StatusForbidden, "証明書と異なる端末 ID です")
		return
	case !evidenceIDPattern.MatchString(ev.ID) || ev.Time.IsZero():
		writeError(w, http.StatusBadRequest, "証拠の ID か時刻が不正です")
		return
	case ev.Reason != api.EvidenceReasonIsolation && ev.Reason != api.EvidenceReasonRequest:
		writeError(w, http.StatusBadRequest, "証拠を集めたきっかけが不正です")
		return
	}
	sum := sha256.Sum256(payload)
	info := api.EvidenceInfo{Device: id.ID, ID: ev.ID, Time: ev.Time, Received: c.now().UTC(), Reason: ev.Reason, SHA256: hex.EncodeToString(sum[:]),
		Bytes: len(payload), Processes: len(ev.Snapshot.Processes), Connections: len(ev.Snapshot.Connections), Logs: len(ev.Snapshot.Logs)}
	stored, err := c.storeEvidence(info, up.Envelope)
	if err != nil {
		c.log.Error("証拠を保存できません", "端末", id.ID, "エラー", err)
		writeError(w, http.StatusInternalServerError, "証拠を保存できません")
		return
	}
	addr := remoteAddr(r)
	c.mu.Lock()
	d := c.ensureLocked(id.ID, addr)
	if stored {
		c.auditLocked("client/"+id.ID, ActionEvidenceReceive, id.ID, addr, map[string]any{
			"id": ev.ID, "reason": ev.Reason, "sha256": info.SHA256, "bytes": info.Bytes, "time": ev.Time,
		})
	}
	if stored {
		c.refreshIncidentsLocked()
	}
	cmd, err := c.commandLocked(d)
	c.mu.Unlock()
	if stored {
		reason := map[string]string{api.EvidenceReasonIsolation: "隔離", api.EvidenceReasonRequest: "管理者の求め"}[ev.Reason]
		msg := fmt.Sprintf("端末 %s の証拠を保全しました（きっかけ %s、プロセス %d、接続 %d、ログ %d、ID %s）", id.ID, reason, info.Processes, info.Connections, info.Logs, ev.ID)
		e := c.finding(event.FindingTypeEvidence, "証拠の保全", msg, event.SeverityInformational, &event.Device{UID: id.ID, Hostname: ev.Hostname})
		e.Unmapped = map[string]any{"evidence": map[string]any{"id": ev.ID, "sha256": info.SHA256, "reason": ev.Reason}}
		c.record(e)
		c.log.Info("証拠を保全しました", "端末", id.ID, "ID", ev.ID, "きっかけ", ev.Reason, "プロセス", info.Processes, "接続", info.Connections)
	}
	respond(w, cmd, err)
}

// storeEvidence は署名付きの証拠を保存して一覧に加える。同じ証拠をもう受け取っていれば何もせず false を返す。
func (c *Controller) storeEvidence(info api.EvidenceInfo, env sign.Envelope) (bool, error) {
	c.evidenceMu.Lock()
	defer c.evidenceMu.Unlock()
	if slices.ContainsFunc(c.evidence, func(x api.EvidenceInfo) bool { return x.Device == info.Device && x.ID == info.ID }) {
		return false, nil
	}
	data, err := json.Marshal(env)
	if err != nil {
		return false, err
	}
	path := c.evidencePath(info.Device, info.ID, info.Time)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	if err := fsutil.WriteFileAtomic(path, data, 0o600); err != nil {
		return false, err
	}
	c.evidence = append(c.evidence, info)
	// 端末ごとに、新しいものから maxEvidencePerDevice 個を残す。
	var mine []api.EvidenceInfo
	for _, x := range c.evidence {
		if x.Device == info.Device {
			mine = append(mine, x)
		}
	}
	slices.SortFunc(mine, func(a, b api.EvidenceInfo) int { return a.Time.Compare(b.Time) })
	for _, old := range mine[:max(len(mine)-maxEvidencePerDevice, 0)] {
		os.Remove(c.evidencePath(old.Device, old.ID, old.Time))
		c.evidence = slices.DeleteFunc(c.evidence, func(x api.EvidenceInfo) bool { return x.Device == old.Device && x.ID == old.ID })
	}
	return true, saveJSON(filepath.Join(c.cfg.Dir, evidenceDir, evidenceIndexFile), c.evidence)
}

// listEvidence は保存した証拠の一覧を、新しい順に返す（?device= で端末を絞る）。
func (c *Controller) listEvidence(w http.ResponseWriter, r *http.Request, _ pki.Identity) {
	device := r.URL.Query().Get("device")
	c.evidenceMu.Lock()
	out := []api.EvidenceInfo{}
	for _, x := range c.evidence {
		if device == "" || x.Device == device {
			out = append(out, x)
		}
	}
	c.evidenceMu.Unlock()
	slices.SortFunc(out, func(a, b api.EvidenceInfo) int {
		return cmp.Or(b.Time.Compare(a.Time), strings.Compare(a.Device, b.Device))
	})
	writeJSON(w, http.StatusOK, out)
}

// getEvidence は証拠の中身（Evidence）を返す。?signed=1 なら、端末の署名付きのまま返す（ほかの場所に保管するため）。
func (c *Controller) getEvidence(w http.ResponseWriter, r *http.Request, _ pki.Identity) {
	device, id := r.PathValue("device"), r.PathValue("id")
	c.evidenceMu.Lock()
	i := slices.IndexFunc(c.evidence, func(x api.EvidenceInfo) bool { return x.Device == device && x.ID == id })
	var info api.EvidenceInfo
	if i >= 0 {
		info = c.evidence[i]
	}
	c.evidenceMu.Unlock()
	if i < 0 {
		writeError(w, http.StatusNotFound, "その証拠はありません")
		return
	}
	data, err := os.ReadFile(c.evidencePath(info.Device, info.ID, info.Time))
	if err != nil {
		writeError(w, http.StatusNotFound, "その証拠のファイルがありません")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Query().Get("signed") == "1" {
		w.Write(data)
		return
	}
	var env sign.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		writeError(w, http.StatusInternalServerError, "証拠のファイルを読めません")
		return
	}
	// 受け取ってから書き換えられていないことを、監査ログにも記録したハッシュで確かめる。
	if sum := sha256.Sum256(env.Payload); hex.EncodeToString(sum[:]) != info.SHA256 {
		writeError(w, http.StatusConflict, "証拠のファイルが受け取ったときと違います（書き換えられた恐れがあります）")
		return
	}
	w.Write(env.Payload)
}

// requestEvidence は、端末に証拠を集めさせる（次の応答の指示で知らせる）。
func (c *Controller) requestEvidence(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	id := r.PathValue("id")
	c.mu.Lock()
	defer c.mu.Unlock()
	d := c.devices[id]
	if d == nil {
		writeError(w, http.StatusNotFound, "その端末はありません")
		return
	}
	d.Version = nextVersion(d.Version, c.now())
	d.Evidence = d.Version
	c.saveLocked()
	c.auditLocked("admin/"+admin.ID, ActionEvidenceRequest, d.ID, d.Addr, map[string]any{"request": d.Evidence})
	c.log.Info("端末に証拠を集めさせます", "端末", d.ID, "操作", "admin/"+admin.ID)
	writeJSON(w, http.StatusOK, c.deviceViewLocked(d))
}
