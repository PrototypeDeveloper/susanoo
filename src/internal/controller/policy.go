package controller

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/pki"
	"susanoo/internal/policy"
	"susanoo/internal/sign"
)

// ポリシーの配布と版の管理（M2）。
//
// 管理者は、ポリシー専用の鍵（CONTROLLER は持たない）で署名した版を送る。CONTROLLER はそれを PolicyManager
// （GW の執行部）に渡し、執行部が署名と版数を確かめて保存し、GW に反映する。CONTROLLER は、執行部が受け付けた
// 今の版と先行適用の版を使う。版の写しは一覧と中身の表示（ロールバックのため）に残す。
//
// 先行適用（段階的な適用）では、指定した端末（ID か MAC アドレス）とグループの端末だけを、新しい版のグループ
// （policy.CanaryGroupName）に入れる。ほかの端末は今の版のグループのまま。

// 監査ログの操作。
const (
	ActionPolicyApply   = "policy.apply"
	ActionPolicyCanary  = "policy.canary"
	ActionPolicyPromote = "policy.promote"
	ActionPolicyAbort   = "policy.abort"
	policyTimeout       = 30 * time.Second
	policyDir           = "policies"
	canaryFile          = "canary.json"
)

// PolicyState は執行部が使っている今の版と、先行適用の版（なければ空）。
type PolicyState struct {
	Current []byte `json:"current"`
	Canary  []byte `json:"canary,omitempty"`
}

// PolicyManager は署名付きのポリシーを確かめて保存し、GW に反映する（GW の執行部が満たす）。
type PolicyManager interface {
	ApplyPolicy(ctx context.Context, env sign.Envelope, canary bool) (PolicyState, error)
	PromotePolicy(ctx context.Context) (PolicyState, error)
	AbortPolicy(ctx context.Context) (PolicyState, error)
}

// canarySelection は先行適用する端末とグループ。
type canarySelection struct {
	Version int      `json:"version"`
	Devices []string `json:"devices,omitempty"` // 端末 ID か MAC アドレス
	Groups  []string `json:"groups,omitempty"`
}

// policyRecord は版の写しの索引の 1 件。
type policyRecord = api.PolicyVersion

// initPolicy は、版の写しを用意し、先行適用の選択を読む。
func (c *Controller) initPolicy() error {
	if err := os.MkdirAll(filepath.Join(c.cfg.Dir, policyDir), 0o700); err != nil {
		return err
	}
	for _, p := range []*policy.Policy{c.pol, c.canaryPol} {
		if p != nil {
			if err := c.saveCopy(p); err != nil {
				return err
			}
		}
	}
	data, err := os.ReadFile(filepath.Join(c.cfg.Dir, canaryFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var sel canarySelection
	if err := json.Unmarshal(data, &sel); err != nil {
		return fmt.Errorf("controller: %s を解析できません: %w", canaryFile, err)
	}
	if c.canaryPol != nil && sel.Version == c.canaryPol.Version {
		c.canarySel = sel
	}
	return nil
}

// saveCopy は版の写しを保存する（既にあれば何もしない）。
func (c *Controller) saveCopy(p *policy.Policy) error {
	path := filepath.Join(c.cfg.Dir, policyDir, fmt.Sprintf("v%d.json", p.Version))
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := saveJSONRaw(path, data); err != nil {
		return err
	}
	index, _ := c.loadIndex()
	index = append(index, policyRecord{Version: p.Version, Name: p.Name, IssuedAt: p.IssuedAt, AppliedAt: c.now().UTC()})
	slices.SortFunc(index, func(a, b policyRecord) int { return a.Version - b.Version })
	return saveJSON(filepath.Join(c.cfg.Dir, policyDir, "index.json"), index)
}

func (c *Controller) loadIndex() ([]policyRecord, error) {
	data, err := os.ReadFile(filepath.Join(c.cfg.Dir, policyDir, "index.json"))
	if err != nil {
		return nil, err
	}
	var index []policyRecord
	return index, json.Unmarshal(data, &index)
}

func saveJSONRaw(path string, data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	return saveJSON(path, v)
}

// groupLocked は、グループ group の端末に使うグループの設定を返す（先行適用の端末は新しい版から）。
func (c *Controller) groupLocked(group string, canary bool) *policy.Group {
	if canary && c.canaryPol != nil {
		return c.canaryPol.Group(group)
	}
	return c.pol.Group(group)
}

// effectiveGroupLocked は、外部通信の制御に渡すグループの名前を返す（先行適用の端末は新しい版のグループ）。
func (c *Controller) effectiveGroupLocked(group string, canary bool) string {
	if canary && c.canaryPol != nil {
		return policy.CanaryGroupName(c.canaryPol, group)
	}
	return cmp.Or(group, policy.DefaultGroup)
}

// deviceCanaryLocked は端末が先行適用の対象かを返す。
func (c *Controller) deviceCanaryLocked(d *device) bool {
	if c.canaryPol == nil {
		return false
	}
	return slices.Contains(c.canarySel.Devices, d.ID) || slices.Contains(c.canarySel.Groups, cmp.Or(d.Group, policy.DefaultGroup))
}

// hostCanaryLocked は機器が先行適用の対象かを返す。端末に結び付いた機器は端末に従う。
func (c *Controller) hostCanaryLocked(h *host) bool {
	if c.canaryPol == nil {
		return false
	}
	if d := c.devices[h.DeviceID]; d != nil {
		return c.deviceCanaryLocked(d)
	}
	return slices.Contains(c.canarySel.Devices, h.MAC) || slices.Contains(c.canarySel.Groups, c.hostGroupLocked(h))
}

// applyPolicyStateLocked は執行部が使っている版に切り替える。
func (c *Controller) applyPolicyStateLocked(st PolicyState) error {
	cur, err := policy.Parse(st.Current)
	if err != nil {
		return err
	}
	var canary *policy.Policy
	if len(st.Canary) > 0 {
		if canary, err = policy.Parse(st.Canary); err != nil {
			return err
		}
	}
	c.pol, c.canaryPol = cur, canary
	c.syncLearningLocked()
	for _, p := range []*policy.Policy{cur, canary} {
		if p != nil {
			if err := c.saveCopy(p); err != nil {
				c.log.Error("ポリシーの写しを保存できません", "エラー", err)
			}
		}
	}
	return nil
}

func (c *Controller) saveCanaryLocked(sel canarySelection) {
	c.canarySel = sel
	if err := saveJSON(filepath.Join(c.cfg.Dir, canaryFile), sel); err != nil {
		c.log.Error("先行適用の選択を保存できません", "エラー", err)
	}
}

// policyInfoLocked はポリシーの状態を返す。
func (c *Controller) policyInfoLocked() api.PolicyInfo {
	index, _ := c.loadIndex()
	find := func(p *policy.Policy) policyRecord {
		for _, r := range index {
			if r.Version == p.Version {
				return r
			}
		}
		return policyRecord{Version: p.Version, Name: p.Name, IssuedAt: p.IssuedAt}
	}
	info := api.PolicyInfo{Current: find(c.pol), Versions: index}
	if c.canaryPol != nil {
		info.Canary = &api.PolicyCanary{PolicyVersion: find(c.canaryPol), Devices: c.canarySel.Devices, Groups: c.canarySel.Groups}
	}
	if info.Versions == nil {
		info.Versions = []policyRecord{}
	}
	return info
}

func (c *Controller) getPolicy(w http.ResponseWriter, _ *http.Request, _ pki.Identity) {
	c.mu.Lock()
	info := c.policyInfoLocked()
	c.mu.Unlock()
	writeJSON(w, http.StatusOK, info)
}

func (c *Controller) getPolicyVersion(w http.ResponseWriter, r *http.Request, _ pki.Identity) {
	v, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || v < 1 {
		writeError(w, http.StatusBadRequest, "版数が不正です")
		return
	}
	data, err := os.ReadFile(filepath.Join(c.cfg.Dir, policyDir, fmt.Sprintf("v%d.json", v)))
	if err != nil {
		writeError(w, http.StatusNotFound, "その版はありません")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// pushPolicy は署名付きのポリシーを受け取り、執行部に反映させる。先行適用の指定があれば、その端末にだけ先に適用する。
func (c *Controller) pushPolicy(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	var req api.PolicyPush
	if !decode(w, r, &req) {
		return
	}
	if c.cfg.Policies == nil {
		writeError(w, http.StatusServiceUnavailable, "この CONTROLLER ではポリシーを配布できません")
		return
	}
	sel := canarySelection{}
	for _, d := range req.CanaryDevices {
		if hw, err := net.ParseMAC(d); err == nil && len(hw) == 6 {
			sel.Devices = append(sel.Devices, hw.String())
		} else if err := (pki.Identity{Role: pki.RoleClient, ID: d}).Validate(); err == nil {
			sel.Devices = append(sel.Devices, d)
		} else {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("先行適用の端末 %q は端末 ID か MAC アドレスで指定してください", d))
			return
		}
	}
	for _, g := range req.CanaryGroups {
		if g == "" || strings.Contains(g, "~") {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("先行適用のグループ %q が不正です", g))
			return
		}
		sel.Groups = append(sel.Groups, g)
	}
	canary := len(sel.Devices) > 0 || len(sel.Groups) > 0
	ctx, cancel := context.WithTimeout(r.Context(), policyTimeout)
	defer cancel()
	st, err := c.cfg.Policies.ApplyPolicy(ctx, req.Envelope, canary)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ポリシーを適用できません: "+err.Error())
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.applyPolicyStateLocked(st); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	actor := "admin/" + admin.ID
	if canary {
		sel.Version = c.canaryPol.Version
		c.saveCanaryLocked(sel)
		c.auditLocked(actor, ActionPolicyCanary, strconv.Itoa(sel.Version), netip.Addr{}, map[string]any{"devices": sel.Devices, "groups": sel.Groups})
		c.log.Warn("ポリシーを先行適用しました", "版数", sel.Version, "端末", sel.Devices, "グループ", sel.Groups, "操作", actor)
	} else {
		c.saveCanaryLocked(canarySelection{})
		c.auditLocked(actor, ActionPolicyApply, strconv.Itoa(c.pol.Version), netip.Addr{}, map[string]any{"name": c.pol.Name})
		c.log.Warn("ポリシーを適用しました", "版数", c.pol.Version, "名前", c.pol.Name, "操作", actor)
	}
	c.syncLocked()
	writeJSON(w, http.StatusOK, c.policyInfoLocked())
}

// promotePolicy は先行適用の版を全体に広げる。
func (c *Controller) promotePolicy(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	c.changeCanary(w, r, admin, ActionPolicyPromote, PolicyManager.PromotePolicy)
}

// abortPolicy は先行適用の版を取り消す。
func (c *Controller) abortPolicy(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	c.changeCanary(w, r, admin, ActionPolicyAbort, PolicyManager.AbortPolicy)
}

func (c *Controller) changeCanary(w http.ResponseWriter, r *http.Request, admin pki.Identity, action string, op func(PolicyManager, context.Context) (PolicyState, error)) {
	if c.cfg.Policies == nil {
		writeError(w, http.StatusServiceUnavailable, "この CONTROLLER ではポリシーを配布できません")
		return
	}
	c.mu.Lock()
	canary := c.canaryPol
	c.mu.Unlock()
	if canary == nil {
		writeError(w, http.StatusConflict, "先行適用している版がありません")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), policyTimeout)
	defer cancel()
	st, err := op(c.cfg.Policies, ctx)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.applyPolicyStateLocked(st); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	c.saveCanaryLocked(canarySelection{})
	actor := "admin/" + admin.ID
	c.auditLocked(actor, action, strconv.Itoa(canary.Version), netip.Addr{}, map[string]any{})
	c.log.Warn("先行適用の版を変えました", "操作", action, "版数", canary.Version, "今の版数", c.pol.Version, "管理者", actor)
	c.syncLocked()
	writeJSON(w, http.StatusOK, c.policyInfoLocked())
}
