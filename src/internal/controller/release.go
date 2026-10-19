package controller

import (
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
	"slices"
	"sort"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/pki"
	"susanoo/internal/release"
	"susanoo/internal/sign"
)

// リリースの配布（共通基盤の署名、非機能の更新）。
//
// 管理者が手元のポリシーの署名の鍵で目録に署名し（ctl release sign）、目録と実行ファイルを CONTROLLER に送る（ctl release push）。
// CONTROLLER は目録の署名と、実行ファイルのハッシュと大きさを確かめてから受け付け、先行適用の端末（端末 ID かグループ）にだけ、
// 指示の中で入れ替えを勧める。全体に広げると（promote）、すべての端末に勧める。CLIENT は目録の署名を自分で確かめ、今より新しい
// 版数だけを受け付け、ハッシュを照らしてから実行ファイルを入れ替える。配るのは一度に 1 つの版だけ。

const (
	releaseFile        = "release.json"
	releaseDir         = "releases"
	releaseIOTimeout   = 10 * time.Minute // 実行ファイルの送受信に許す時間
	ActionReleasePush  = "release.push"
	ActionReleaseFile  = "release.file"
	ActionReleaseOpen  = "release.promote"
	ActionReleaseAbort = "release.abort"
	ActionUpdate       = "device.update"
)

// releaseState は配布しているリリース。
type releaseState struct {
	Manifest     sign.Envelope     `json:"manifest"`
	Version      string            `json:"version"`
	IssuedAt     time.Time         `json:"issued_at"`
	PushedAt     time.Time         `json:"pushed_at"`
	Files        []api.ReleaseFile `json:"files"`
	Uploaded     []string          `json:"uploaded,omitempty"` // 受け取った実行ファイル（os/arch）
	Canary       []string          `json:"canary,omitempty"`
	CanaryGroups []string          `json:"canary_groups,omitempty"`
	Promoted     bool              `json:"promoted,omitempty"`
}

func fileKey(goos, goarch string) string { return goos + "/" + goarch }

func (c *Controller) releasePath(version, goos, goarch string) string {
	return filepath.Join(c.cfg.Dir, releaseDir, version, goos+"-"+goarch)
}

func (c *Controller) initRelease() error {
	data, err := os.ReadFile(filepath.Join(c.cfg.Dir, releaseFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var st releaseState
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("controller: %s を解析できません: %w", releaseFile, err)
	}
	c.release = &st
	return nil
}

func (c *Controller) saveReleaseLocked() {
	path := filepath.Join(c.cfg.Dir, releaseFile)
	if c.release == nil {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			c.log.Error("リリースの記録を消せません", "エラー", err)
		}
		return
	}
	if err := saveJSON(path, c.release); err != nil {
		c.log.Error("リリースの記録を保存できません", "エラー", err)
	}
}

func (c *Controller) releaseVerifier() (*sign.Verifier, error) {
	if len(c.cfg.RulesKey) == 0 {
		return nil, errors.New("この CONTROLLER にはポリシーの署名の公開鍵がないため、リリースを確かめられません")
	}
	return sign.NewVerifier(c.cfg.RulesKey)
}

// recordSoftwareLocked はハートビートで報告された CLIENT の版数と OS を記録する。版数が変わったら監査ログに残す。
func (c *Controller) recordSoftwareLocked(d *device, hb api.Heartbeat) {
	d.OS, d.Arch = hb.Capabilities.OS, hb.Capabilities.Arch
	if hb.Version == "" || hb.Version == d.Software {
		return
	}
	if d.Software != "" {
		c.auditLocked(d.ID, ActionUpdate, d.ID, d.Addr, map[string]any{"from": d.Software, "to": hb.Version})
		c.log.Info("端末の版数が変わりました", "端末", d.ID, "前", d.Software, "今", hb.Version)
	}
	d.Software = hb.Version
	c.dirty = true
}

// releaseTargetLocked は、配布しているリリースを端末に勧める対象とするか（先行適用の対象か、全体に広げたか）を返す。
func (c *Controller) releaseTargetLocked(d *device) bool {
	r := c.release
	if r == nil {
		return false
	}
	return r.Promoted || slices.Contains(r.Canary, d.ID) || slices.Contains(r.CanaryGroups, c.effectiveGroupLocked(d.Group, c.deviceCanaryLocked(d)))
}

// releaseOfferLocked は、端末に入れ替えを勧めるリリースを返す。対象で、端末の版数より新しく、端末の OS と CPU の
// 実行ファイルを受け取っていれば勧める。
func (c *Controller) releaseOfferLocked(d *device) *api.ReleaseOffer {
	r := c.release
	if r == nil || !c.releaseTargetLocked(d) || release.Compare(r.Version, d.Software) <= 0 || !slices.Contains(r.Uploaded, fileKey(d.OS, d.Arch)) {
		return nil
	}
	return &api.ReleaseOffer{Version: r.Version, Manifest: r.Manifest}
}

func (c *Controller) releaseInfoLocked() api.ReleaseInfo {
	r := c.release
	info := api.ReleaseInfo{Version: r.Version, IssuedAt: r.IssuedAt, PushedAt: r.PushedAt, Promoted: r.Promoted,
		Canary: r.Canary, CanaryGroups: r.CanaryGroups, Files: []string{}, Missing: []string{}, Updated: []string{}, Pending: []string{}}
	for _, f := range r.Files {
		k := fileKey(f.OS, f.Arch)
		info.Files = append(info.Files, k)
		if !slices.Contains(r.Uploaded, k) {
			info.Missing = append(info.Missing, k)
		}
	}
	for _, d := range c.devices {
		switch {
		case d.Software == r.Version:
			info.Updated = append(info.Updated, d.ID)
		case c.releaseOfferLocked(d) != nil:
			info.Pending = append(info.Pending, d.ID)
		}
	}
	sort.Strings(info.Updated)
	sort.Strings(info.Pending)
	return info
}

func (c *Controller) getRelease(w http.ResponseWriter, _ *http.Request, _ pki.Identity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.release == nil {
		writeError(w, http.StatusNotFound, "配布しているリリースはありません")
		return
	}
	writeJSON(w, http.StatusOK, c.releaseInfoLocked())
}

// pushRelease は署名したリリースの目録を受け付ける。配布しているリリースより新しい版数に限り、前の配布を置き換える。
func (c *Controller) pushRelease(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	v, err := c.releaseVerifier()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	var req api.ReleasePush
	if !decode(w, r, &req) {
		return
	}
	m, err := release.Verify(v, req.Manifest)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	for _, id := range req.Canary {
		if err := (pki.Identity{Role: pki.RoleClient, ID: id}).Validate(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, g := range req.CanaryGroups {
		if _, err := c.validGroup(g); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("グループ %q はポリシーにありません", g))
			return
		}
	}
	if prev := c.release; prev != nil {
		if release.Compare(m.Version, prev.Version) <= 0 {
			writeError(w, http.StatusConflict, fmt.Sprintf("配布している版 %s より新しい版数にしてください", prev.Version))
			return
		}
		os.RemoveAll(filepath.Join(c.cfg.Dir, releaseDir, prev.Version))
	}
	c.release = &releaseState{Manifest: req.Manifest, Version: m.Version, IssuedAt: m.IssuedAt, PushedAt: c.now().UTC(), Files: m.Files,
		Canary: req.Canary, CanaryGroups: req.CanaryGroups, Promoted: len(req.Canary) == 0 && len(req.CanaryGroups) == 0}
	c.saveReleaseLocked()
	c.auditLocked(admin.String(), ActionReleasePush, m.Version, remoteAddr(r), map[string]any{
		"files": len(m.Files), "canary": req.Canary, "canary_groups": req.CanaryGroups,
	})
	c.log.Info("リリースの目録を受け付けました", "版数", m.Version, "ファイル", len(m.Files), "先行適用", len(req.Canary)+len(req.CanaryGroups) > 0)
	writeJSON(w, http.StatusOK, c.releaseInfoLocked())
}

// uploadRelease は、目録に書いた実行ファイルを受け取る。大きさとハッシュが目録と合わなければ捨てる。
func (c *Controller) uploadRelease(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	goos, goarch := r.PathValue("os"), r.PathValue("arch")
	c.mu.Lock()
	rel := c.release
	var f api.ReleaseFile
	ok := false
	if rel != nil {
		f, ok = release.File(api.ReleaseManifest{Files: rel.Files}, goos, goarch)
	}
	version := ""
	if rel != nil {
		version = rel.Version
	}
	c.mu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("配布しているリリースの目録に %s/%s の実行ファイルはありません", goos, goarch))
		return
	}
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Now().Add(releaseIOTimeout))
	path := c.releasePath(version, goos, goarch)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".upload-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r.Body, f.Size+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "実行ファイルを受け取れません: "+err.Error())
		return
	}
	if n != f.Size || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		writeError(w, http.StatusForbidden, fmt.Sprintf("%s/%s の実行ファイルが目録と合いません（大きさ %d、目録 %d）", goos, goarch, n, f.Size))
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.release == nil || c.release.Version != version {
		writeError(w, http.StatusConflict, "送っている間に配布が変わりました")
		return
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !slices.Contains(c.release.Uploaded, fileKey(goos, goarch)) {
		c.release.Uploaded = append(c.release.Uploaded, fileKey(goos, goarch))
	}
	c.saveReleaseLocked()
	c.auditLocked(admin.String(), ActionReleaseFile, version, remoteAddr(r), map[string]any{"file": fileKey(goos, goarch), "sha256": f.SHA256})
	c.log.Info("リリースの実行ファイルを受け取りました", "版数", version, "ファイル", fileKey(goos, goarch))
	writeJSON(w, http.StatusOK, c.releaseInfoLocked())
}

// downloadRelease は、入れ替えを勧めている端末に実行ファイルを渡す。
func (c *Controller) downloadRelease(w http.ResponseWriter, r *http.Request, id pki.Identity) {
	goos, goarch := r.PathValue("os"), r.PathValue("arch")
	c.mu.Lock()
	d := c.devices[id.ID]
	var offer *api.ReleaseOffer
	if d != nil && d.OS == goos && d.Arch == goarch {
		offer = c.releaseOfferLocked(d)
	}
	path := ""
	if offer != nil {
		path = c.releasePath(offer.Version, goos, goarch)
	}
	c.mu.Unlock()
	if offer == nil {
		writeError(w, http.StatusNotFound, "この端末に勧めているリリースはありません")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(releaseIOTimeout))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(st.Size()))
	w.WriteHeader(http.StatusOK)
	io.Copy(w, f)
}

func (c *Controller) promoteRelease(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.release == nil {
		writeError(w, http.StatusNotFound, "配布しているリリースはありません")
		return
	}
	c.release.Promoted = true
	c.saveReleaseLocked()
	c.auditLocked(admin.String(), ActionReleaseOpen, c.release.Version, remoteAddr(r), map[string]any{})
	c.log.Info("リリースを全体に広げました", "版数", c.release.Version)
	writeJSON(w, http.StatusOK, c.releaseInfoLocked())
}

func (c *Controller) abortRelease(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.release == nil {
		writeError(w, http.StatusNotFound, "配布しているリリースはありません")
		return
	}
	version := c.release.Version
	os.RemoveAll(filepath.Join(c.cfg.Dir, releaseDir, version))
	c.release = nil
	c.saveReleaseLocked()
	c.auditLocked(admin.String(), ActionReleaseAbort, version, remoteAddr(r), map[string]any{})
	c.log.Info("リリースの配布をやめました（入れ替えた端末はそのまま）", "版数", version)
	writeJSON(w, http.StatusOK, api.ReleaseInfo{Version: version})
}
