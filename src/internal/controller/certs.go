package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/fsutil"
	"susanoo/internal/pki"
	"susanoo/internal/policy"
	"susanoo/internal/transport"
)

// 証明書の更新と失効（M1）。
//
//   - 更新：CLIENT は、証明書の有効期間の残りが 3 分の 1 を切ったら、同じ鍵のまま新しい証明書を求める。
//     CONTROLLER は認証局の秘密鍵を持たず、発行は Issuer（GW の執行部）に頼む。時期より前の更新は断る
//   - 失効：管理者が端末の証明書を失効させると、その時刻より前に発行したその端末の証明書は、接続の時と要求ごとに拒む。
//     端末は全遮断で隔離する（指示を届けられないため、GW の遮断で止める）。入れ直すときは ctl issue で発行し直す
//   - CONTROLLER 自身の証明書は、GW の執行部が更新して SetCertificate で渡す。接続を止めずに切り替える

// 監査ログの操作と、隔離の理由。
const (
	ActionRenew    = "device.renew"
	ActionRevoke   = "device.revoke"
	ReasonRevoked  = "証明書の失効"
	issueTimeout   = 10 * time.Second
	revocationFile = "revocations.json"
)

// Issuer は端末の証明書を発行する（GW の執行部が満たす）。役割は端末に限る。
// 返すのは、発行した証明書を先頭に、連ねる認証局の証明書（二段構えの発行用の認証局）を続けたもの。
type Issuer interface {
	IssueClient(ctx context.Context, id string, pub ed25519.PublicKey) ([]*x509.Certificate, error)
}

var errRevoked = errors.New("controller: 証明書は失効しています")

// loadRevocations は失効の記録（持ち主の URI → 失効させた時刻）を読む。
func loadRevocations(path string) (map[string]time.Time, error) {
	m := map[string]time.Time{}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("controller: 失効の記録 %s を解析できません: %w", path, err)
	}
	return m, nil
}

// revokedCert は証明書が失効しているかを返す（持ち主が失効させられた時刻より前に発行したもの）。
func (c *Controller) revokedCert(cert *x509.Certificate) bool {
	id, err := pki.IdentityFromCert(cert)
	if err != nil {
		return true
	}
	c.revMu.Lock()
	t, ok := c.revoked[id.String()]
	c.revMu.Unlock()
	return ok && !pki.IssuedAt(cert).After(t)
}

// tlsConfig は管理通信の TLS の設定を返す。自分の証明書は SetCertificate で切り替えられ、
// 失効した証明書の接続は受け付けない。
func (c *Controller) tlsConfig() *tls.Config {
	cfg := transport.ServerConfig(c.cfg.CA, c.cfg.Cert, pki.RoleClient, pki.RoleAdmin)
	cfg.Certificates = nil
	cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return c.cert.Load(), nil }
	verify := cfg.VerifyConnection
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if err := verify(cs); err != nil {
			return err
		}
		if c.revokedCert(cs.PeerCertificates[0]) {
			return errRevoked
		}
		return nil
	}
	return cfg
}

// SetCertificate は CONTROLLER の証明書を切り替える。新しい接続から使う。
func (c *Controller) SetCertificate(cert tls.Certificate) {
	c.cert.Store(&cert)
	if cert.Leaf != nil {
		c.log.Info("CONTROLLER の証明書を切り替えました", "期限", cert.Leaf.NotAfter.Local().Format(time.DateTime))
	}
}

// renewCertificate は CLIENT の証明書を同じ鍵で更新する。
func (c *Controller) renewCertificate(w http.ResponseWriter, r *http.Request, id pki.Identity) {
	if c.cfg.Issuer == nil {
		writeError(w, http.StatusServiceUnavailable, "この CONTROLLER では証明書を更新できません")
		return
	}
	cur := r.TLS.PeerCertificates[0]
	if !pki.RenewalDue(cur, c.now()) {
		writeError(w, http.StatusConflict, "まだ証明書を更新する時期ではありません")
		return
	}
	pub, ok := cur.PublicKey.(ed25519.PublicKey)
	if !ok {
		writeError(w, http.StatusBadRequest, "ed25519 の証明書ではありません")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), issueTimeout)
	defer cancel()
	chain, err := c.cfg.Issuer.IssueClient(ctx, id.ID, pub)
	if err == nil && len(chain) == 0 {
		err = errors.New("発行した証明書がありません")
	}
	if err != nil {
		c.log.Error("端末の証明書を発行できません", "端末", id.ID, "エラー", err)
		writeError(w, http.StatusInternalServerError, "証明書を発行できません")
		return
	}
	cert := chain[0]
	c.mu.Lock()
	c.auditLocked(id.String(), ActionRenew, id.ID, remoteAddr(r), map[string]any{
		"serial": cert.SerialNumber.Text(16), "not_after": cert.NotAfter.UTC(),
	})
	c.mu.Unlock()
	c.log.Info("端末の証明書を更新しました", "端末", id.ID, "期限", cert.NotAfter.Local().Format(time.DateTime))
	resp := api.CertificateResponse{Certificate: cert.Raw}
	for _, inter := range chain[1:] {
		resp.Chain = append(resp.Chain, inter.Raw)
	}
	writeJSON(w, http.StatusOK, resp)
}

// revokeDevice は端末の証明書を失効させ、端末を全遮断で隔離する。台帳にまだない端末（盗まれて一度も
// 接続していない端末など）も失効させられる。
func (c *Controller) revokeDevice(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	target := pki.Identity{Role: pki.RoleClient, ID: r.PathValue("id")}
	if err := target.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := c.now()
	c.revMu.Lock()
	c.revoked[target.String()] = now
	err := saveJSON(filepath.Join(c.cfg.Dir, revocationFile), c.revoked)
	c.revMu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "失効の記録を保存できません")
		return
	}

	c.mu.Lock()
	actor := "admin/" + admin.ID
	c.auditLocked(actor, ActionRevoke, target.ID, netip.Addr{}, map[string]any{"revoked_at": now.UTC()})
	c.log.Warn("端末の証明書を失効させました", "端末", target.ID, "操作", actor)
	d := c.devices[target.ID]
	if d == nil {
		c.mu.Unlock()
		writeJSON(w, http.StatusOK, api.Device{ID: target.ID, Group: policy.DefaultGroup, Revoked: now})
		return
	}
	d.Revoked = now
	if d.Isolation != policy.IsolateFull {
		c.isolateLocked(d, policy.IsolateFull, ReasonRevoked, actor)
	} else {
		c.saveLocked()
	}
	view := c.deviceViewLocked(d)
	c.mu.Unlock()
	writeJSON(w, http.StatusOK, view)
}

// saveJSON は v を JSON で path に保存する。
func saveJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, append(data, '\n'), 0o600)
}
