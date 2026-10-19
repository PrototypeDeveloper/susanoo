package controller

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/pki"
)

// 管理者の証明書の失効と、認証局の証明書の更新（2m-3）。
//
//   - 管理者の証明書の失効：端末と同じく、その時刻より前に発行したその管理者の証明書をすべて無効にする（revocations.json）。
//     自分と同じ ID を失効させるときは、今使っている証明書より前に発行したものだけを失効させる（手元の鍵をなくしたときは、
//     新しい証明書を発行してから、その証明書で失効させる）。今使っている証明書まで失効させる操作は断る
//   - 認証局の証明書の更新：CLIENT はハートビートで信頼している認証局の証明書のハッシュを知らせ、CONTROLLER は今の認証局の
//     証明書と違えば、署名付きの指示に新しい証明書を入れる。CLIENT は同じ鍵と名前で期限の延びたものだけを受け入れる

// ActionAdminRevoke は管理者の証明書の失効の監査ログの操作。
const ActionAdminRevoke = "admin.revoke"

// revokeAdmin は管理者の証明書を失効させる。
func (c *Controller) revokeAdmin(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	target := pki.Identity{Role: pki.RoleAdmin, ID: r.PathValue("id")}
	if err := target.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req api.AdminRevokeRequest
	if r.ContentLength != 0 {
		if !decode(w, r, &req) {
			return
		}
	}
	now := c.now()
	own := pki.IssuedAt(r.TLS.PeerCertificates[0])
	before := now
	switch {
	case !req.Before.IsZero():
		before = req.Before
		if before.After(now) {
			before = now // これから発行する証明書は失効させない
		}
	case admin.ID == target.ID:
		before = own.Add(-time.Second) // 今使っている証明書より前に発行したもの
	}
	if admin.ID == target.ID && !own.After(before) {
		writeError(w, http.StatusConflict, "この操作では、今使っている管理者の証明書も失効します。新しい証明書を発行してから、その証明書で失効させてください")
		return
	}
	c.revMu.Lock()
	key := target.String()
	if prev, ok := c.revoked[key]; ok && prev.After(before) {
		before = prev // 失効を取り消す向きには変えない
	}
	c.revoked[key] = before
	err := saveJSON(filepath.Join(c.cfg.Dir, revocationFile), c.revoked)
	c.revMu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "失効の記録を保存できません")
		return
	}
	actor := "admin/" + admin.ID
	c.mu.Lock()
	c.auditLocked(actor, ActionAdminRevoke, target.ID, remoteAddr(r), map[string]any{"revoked_before": before.UTC()})
	c.mu.Unlock()
	c.log.Warn("管理者の証明書を失効させました", "管理者", target.ID, "これより前に発行したもの", before.Local().Format(time.DateTime), "操作", actor)
	writeJSON(w, http.StatusOK, api.AdminRevocation{ID: target.ID, RevokedBefore: before})
}

// listAdmins は失効させた管理者の証明書の一覧を返す。
func (c *Controller) listAdmins(w http.ResponseWriter, _ *http.Request, admin pki.Identity) {
	out := api.AdminList{Self: admin.ID, Revoked: []api.AdminRevocation{}}
	c.revMu.Lock()
	for k, t := range c.revoked {
		if u, err := url.Parse(k); err == nil && u.Host == string(pki.RoleAdmin) {
			out.Revoked = append(out.Revoked, api.AdminRevocation{ID: strings.TrimPrefix(u.Path, "/"), RevokedBefore: t})
		}
	}
	c.revMu.Unlock()
	slices.SortFunc(out.Revoked, func(a, b api.AdminRevocation) int { return strings.Compare(a.ID, b.ID) })
	writeJSON(w, http.StatusOK, out)
}

// caHash は認証局の証明書の SHA-256 を返す（CLIENT が知らせるものと同じ形）。
func caHash(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// caForLocked は、端末に渡す認証局の証明書を返す（端末が今の証明書を信頼していれば、知らせていなければ nil）。
func (c *Controller) caForLocked(d *device) []byte {
	root := c.cfg.Root
	if root == nil || d.CAHash == "" || d.CAHash == caHash(root) {
		return nil
	}
	return root.Raw
}

// caExpiry は認証局（二段構えならルート）の証明書の期限を返す。
func (c *Controller) caExpiry() *time.Time {
	if c.cfg.Root == nil {
		return nil
	}
	t := c.cfg.Root.NotAfter
	return &t
}

// warnCA は、認証局の証明書の期限が近ければ警告する。
func (c *Controller) warnCA() {
	if t := c.caExpiry(); t != nil && t.Sub(c.now()) < pki.CAWarning {
		c.log.Warn("認証局の証明書の期限が近づいています。ctl ca renew で同じ鍵のまま発行し直してください", "期限", t.Local().Format("2006-01-02"))
	}
}
