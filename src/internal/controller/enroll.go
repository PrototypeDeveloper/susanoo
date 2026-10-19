package controller

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/enroll"
	"susanoo/internal/event"
	"susanoo/internal/pki"
)

// 一回限りの登録コードによる端末の初回登録（M1）。
//
// 管理者が端末 ID ごとに登録コードを作り（ctl enroll create）、端末で入力する（client enroll）。端末は証明書なしの TLS で
// つなぎ、コードと TLS の exporter で計算した HMAC で、コードを知っていることを示す（enroll パッケージ）。CONTROLLER は
// 確かめたらコードを消し、GW の執行部に端末の証明書の発行を頼み、認証局の証明書と指示の公開鍵を添えて、同じように HMAC を
// 付けて返す。証明書なしの TLS の接続は、有効な登録コードがある間だけ受け付け、登録の窓口のほかには通さない。

const (
	enrollFile        = "enroll.json"
	enrollDefaultTTL  = 24 * time.Hour
	enrollMaxTTL      = 7 * 24 * time.Hour
	enrollMaxFailures = 5           // 誤った証明がこの回数に達したら、そのコードを消す
	enrollMaxCodes    = 256         // 同時に有効なコードの数の上限
	enrollRateWindow  = time.Minute // 登録の要求の数を数える時間
	enrollRateLimit   = 20          // enrollRateWindow の間に受け付ける登録の要求の数
	enrollMsgRejected = "登録コードが正しくないか、期限が切れています"

	ActionEnrollCreate = "device.enroll.create"
	ActionEnrollDelete = "device.enroll.delete"
	ActionEnroll       = "device.enroll"
	ActionEnrollFail   = "device.enroll.fail"
	ActionEnrollLock   = "device.enroll.lock"
)

// enrollCode は保存する登録コード。コードそのものではなく、コードから導いた HMAC の鍵を持つ。
type enrollCode struct {
	Key      []byte    `json:"key"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
	Failures int       `json:"failures,omitempty"`
	By       string    `json:"by"`
}

// initEnroll は登録コードを読む。
func (c *Controller) initEnroll() error {
	c.enrollCodes = map[string]*enrollCode{}
	data, err := os.ReadFile(filepath.Join(c.cfg.Dir, enrollFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &c.enrollCodes); err != nil {
		return fmt.Errorf("controller: %s を解析できません: %w", enrollFile, err)
	}
	return nil
}

// saveEnrollLocked は登録コードを保存する（enrollMu を持って呼ぶ）。
func (c *Controller) saveEnrollLocked() {
	if err := saveJSON(filepath.Join(c.cfg.Dir, enrollFile), c.enrollCodes); err != nil {
		c.log.Error("登録コードを保存できません", "エラー", err)
	}
}

// pruneEnrollLocked は期限の切れたコードを消す。消したら true を返す。
func (c *Controller) pruneEnrollLocked(now time.Time) bool {
	pruned := false
	for id, e := range c.enrollCodes {
		if !now.Before(e.Expires) {
			delete(c.enrollCodes, id)
			pruned = true
		}
	}
	return pruned
}

// enrollWindowOpen は、有効な登録コードがあるかを返す。ないときは、証明書なしの TLS の接続を断る。
func (c *Controller) enrollWindowOpen() bool {
	if !c.canEnroll() {
		return false
	}
	now := c.now()
	c.enrollMu.Lock()
	defer c.enrollMu.Unlock()
	for _, e := range c.enrollCodes {
		if now.Before(e.Expires) {
			return true
		}
	}
	return false
}

// activeEnrollCodes は有効な登録コードの数を返す。
func (c *Controller) activeEnrollCodes(now time.Time) int {
	c.enrollMu.Lock()
	defer c.enrollMu.Unlock()
	n := 0
	for _, e := range c.enrollCodes {
		if now.Before(e.Expires) {
			n++
		}
	}
	return n
}

// canEnroll は、この CONTROLLER で端末を登録できるか（証明書を発行でき、認証局の証明書を渡せるか）を返す。
func (c *Controller) canEnroll() bool { return c.cfg.Issuer != nil && c.cfg.Root != nil }

// noCertGate は、証明書なしの TLS の接続からの要求を、登録の窓口のほかには通さない。
func noCertGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) == 0 && (r.Method != http.MethodPost || r.URL.Path != api.PathEnroll) {
			writeError(w, http.StatusForbidden, "相互TLSで接続してください")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// createEnrollCode は登録コードを作る。同じ端末のコードがあれば置き換える。
func (c *Controller) createEnrollCode(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	if !c.canEnroll() {
		writeError(w, http.StatusServiceUnavailable, "この CONTROLLER では端末を登録できません")
		return
	}
	var req api.EnrollCodeCreate
	if !decode(w, r, &req) {
		return
	}
	if err := (pki.Identity{Role: pki.RoleClient, ID: req.ID}).Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ttl := enrollDefaultTTL
	if req.TTL != "" {
		d, err := time.ParseDuration(req.TTL)
		if err != nil || d <= 0 || d > enrollMaxTTL {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("有効期間は 0 より長く %s までにしてください", enrollMaxTTL))
			return
		}
		ttl = d
	}
	code, err := enroll.NewCode()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	key, err := enroll.Key(code)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := c.now()
	rec := &enrollCode{Key: key, Created: now, Expires: now.Add(ttl), By: admin.ID}
	c.enrollMu.Lock()
	c.pruneEnrollLocked(now)
	if _, ok := c.enrollCodes[req.ID]; !ok && len(c.enrollCodes) >= enrollMaxCodes {
		c.enrollMu.Unlock()
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("有効な登録コードは %d 個までです", enrollMaxCodes))
		return
	}
	c.enrollCodes[req.ID] = rec
	c.saveEnrollLocked()
	c.enrollMu.Unlock()
	c.mu.Lock()
	c.auditLocked(admin.String(), ActionEnrollCreate, req.ID, remoteAddr(r), map[string]any{"expires": rec.Expires.UTC()})
	c.mu.Unlock()
	c.log.Info("登録コードを作りました", "端末", req.ID, "期限", rec.Expires.Local().Format(time.DateTime))
	writeJSON(w, http.StatusOK, api.EnrollCode{ID: req.ID, Code: code, Created: rec.Created, Expires: rec.Expires})
}

// listEnrollCodes は有効な登録コードの一覧（コードそのものは含まない）を返す。
func (c *Controller) listEnrollCodes(w http.ResponseWriter, _ *http.Request, _ pki.Identity) {
	c.enrollMu.Lock()
	if c.pruneEnrollLocked(c.now()) {
		c.saveEnrollLocked()
	}
	out := make([]api.EnrollCode, 0, len(c.enrollCodes))
	for id, e := range c.enrollCodes {
		out = append(out, api.EnrollCode{ID: id, Created: e.Created, Expires: e.Expires, Failures: e.Failures})
	}
	c.enrollMu.Unlock()
	slices.SortFunc(out, func(a, b api.EnrollCode) int { return strings.Compare(a.ID, b.ID) })
	writeJSON(w, http.StatusOK, out)
}

// deleteEnrollCode は登録コードを取り消す。
func (c *Controller) deleteEnrollCode(w http.ResponseWriter, r *http.Request, admin pki.Identity) {
	id := r.PathValue("id")
	c.enrollMu.Lock()
	_, ok := c.enrollCodes[id]
	if ok {
		delete(c.enrollCodes, id)
		c.saveEnrollLocked()
	}
	c.enrollMu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("端末 %s の登録コードはありません", id))
		return
	}
	c.mu.Lock()
	c.auditLocked(admin.String(), ActionEnrollDelete, id, remoteAddr(r), map[string]any{})
	c.mu.Unlock()
	writeJSON(w, http.StatusOK, api.EnrollCode{ID: id})
}

// allowEnrollAttemptLocked は、登録の要求の数が上限の内かを確かめて数える（enrollMu を持って呼ぶ）。
func (c *Controller) allowEnrollAttemptLocked(now time.Time) bool {
	c.enrollAttempts = slices.DeleteFunc(c.enrollAttempts, func(t time.Time) bool { return now.Sub(t) >= enrollRateWindow })
	if len(c.enrollAttempts) >= enrollRateLimit {
		return false
	}
	c.enrollAttempts = append(c.enrollAttempts, now)
	return true
}

// enrollDevice は、証明書なしの TLS で届いた端末の登録の要求を受け付ける。
func (c *Controller) enrollDevice(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) > 0 {
		writeError(w, http.StatusBadRequest, "証明書を持つ端末は、証明書の更新を使ってください")
		return
	}
	if !c.canEnroll() {
		writeError(w, http.StatusServiceUnavailable, "この CONTROLLER では端末を登録できません")
		return
	}
	addr := remoteAddr(r)
	now := c.now()
	c.enrollMu.Lock()
	ok := c.allowEnrollAttemptLocked(now)
	c.enrollMu.Unlock()
	if !ok {
		writeError(w, http.StatusTooManyRequests, "登録の要求が多すぎます。しばらく待ってから試し直してください")
		return
	}
	var req api.EnrollRequest
	if !decode(w, r, &req) {
		return
	}
	if err := (pki.Identity{Role: pki.RoleClient, ID: req.ID}).Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.PublicKey) != ed25519.PublicKeySize {
		writeError(w, http.StatusBadRequest, "ed25519 の公開鍵ではありません")
		return
	}
	exporter, err := enroll.Exporter(*r.TLS)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// コードを確かめて消す（発行に失敗したら戻す）。誤った証明が続いたら、そのコードを消す。
	c.enrollMu.Lock()
	rec := c.enrollCodes[req.ID]
	if rec != nil && !now.Before(rec.Expires) {
		delete(c.enrollCodes, req.ID)
		c.saveEnrollLocked()
		rec = nil
	}
	if rec == nil || !enroll.Equal(req.Proof, enroll.RequestProof(rec.Key, exporter, req.ID, req.PublicKey)) {
		locked := false
		if rec != nil {
			rec.Failures++
			if rec.Failures >= enrollMaxFailures {
				delete(c.enrollCodes, req.ID)
				locked = true
			}
			c.saveEnrollLocked()
		}
		c.enrollMu.Unlock()
		c.mu.Lock()
		c.auditLocked("enroll", ActionEnrollFail, req.ID, addr, map[string]any{"code_exists": rec != nil})
		if locked {
			c.auditLocked(actorSystem, ActionEnrollLock, req.ID, addr, map[string]any{"failures": enrollMaxFailures})
		}
		c.mu.Unlock()
		c.log.Warn("端末の登録を断りました", "端末", req.ID, "アドレス", addr)
		if locked {
			c.log.Warn("誤った登録の証明が続いたため、登録コードを消しました", "端末", req.ID)
			msg := fmt.Sprintf("端末 %s の登録コードに、%s から誤った証明が %d 回続いたため、コードを消しました（コードの総当たりの疑い）。"+
				"登録するときは ctl enroll create で作り直してください", req.ID, addr, enrollMaxFailures)
			c.observe(c.finding(event.FindingTypeEnrollLock, "登録コードの総当たり", msg, event.SeverityMedium, nil), subject{})
		}
		writeError(w, http.StatusForbidden, enrollMsgRejected)
		return
	}
	delete(c.enrollCodes, req.ID)
	c.saveEnrollLocked()
	c.enrollMu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), issueTimeout)
	defer cancel()
	chain, err := c.cfg.Issuer.IssueClient(ctx, req.ID, ed25519.PublicKey(req.PublicKey))
	if err == nil && len(chain) == 0 {
		err = errors.New("発行した証明書がありません")
	}
	if err != nil {
		c.enrollMu.Lock()
		if _, ok := c.enrollCodes[req.ID]; !ok {
			c.enrollCodes[req.ID] = rec // 管理者が作り直していなければ戻す
			c.saveEnrollLocked()
		}
		c.enrollMu.Unlock()
		c.log.Error("端末の証明書を発行できません", "端末", req.ID, "エラー", err)
		writeError(w, http.StatusInternalServerError, "証明書を発行できません")
		return
	}
	cert := chain[0]
	resp := api.EnrollResponse{Certificate: cert.Raw, CA: c.cfg.Root.Raw, CommandKey: c.cfg.Signer.PublicKey()}
	for _, inter := range chain[1:] {
		resp.Chain = append(resp.Chain, inter.Raw)
	}
	resp.Proof = enroll.ResponseProof(rec.Key, exporter, resp.Certificate, resp.Chain, resp.CA, resp.CommandKey)
	c.mu.Lock()
	c.auditLocked("enroll", ActionEnroll, req.ID, addr, map[string]any{
		"serial": cert.SerialNumber.Text(16), "not_after": cert.NotAfter.UTC(), "code_by": rec.By,
	})
	c.mu.Unlock()
	c.log.Info("端末を登録しました", "端末", req.ID, "アドレス", addr, "期限", cert.NotAfter.Local().Format(time.DateTime))
	writeJSON(w, http.StatusOK, resp)
}
