package controller

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/platform"
	"susanoo/internal/policy"
	"susanoo/internal/sign"
)

// raw は本文をそのまま送り、状態と本文を返す。
func (d *peer) raw(method, path string, body []byte) (int, []byte) {
	d.f.t.Helper()
	req, err := http.NewRequest(method, "https://"+d.f.addr+path, bytes.NewReader(body))
	if err != nil {
		d.f.t.Fatal(err)
	}
	resp, err := d.http.Do(req)
	if err != nil {
		d.f.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

// heartbeatVersion は、版数 version の linux/amd64 の CLIENT としてハートビートを送り、指示を返す。
func (d *peer) heartbeatVersion(version string) api.Command {
	d.f.t.Helper()
	d.count++
	status, body := d.do(http.MethodPost, api.PathHeartbeat, d.signedHeartbeat(api.Heartbeat{
		DeviceID: d.id, BootID: d.boot, Counter: d.count, Time: time.Now(), Hostname: d.id, Version: version,
		Capabilities: platform.Capabilities{OS: "linux", Arch: "amd64"},
	}))
	return d.command(status, body)
}

func releaseManifest(t *testing.T, s *sign.Signer, p sign.Purpose, version string, body []byte) sign.Envelope {
	t.Helper()
	sum := sha256.Sum256(body)
	data, _ := json.Marshal(api.ReleaseManifest{Version: version, IssuedAt: time.Now().UTC(), Files: []api.ReleaseFile{
		{OS: "linux", Arch: "amd64", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body))},
	}})
	return s.Sign(p, data)
}

// 署名した目録と、ハッシュの合う実行ファイルだけを受け付け、先行適用の端末にだけ勧める。全体に広げると全員に勧め、
// 入れ替えた端末には勧めない。古い版数の目録と、ほかの鍵や用途の署名は断る。
func TestRelease(t *testing.T) {
	env := pkitest.New(t)
	signer := newPolicySigner(t)
	dir := t.TempDir()
	f := startRules(t, env, dir, testPolicy(policy.ResponseEnforce, false), signer)
	admin := f.peer(pki.RoleAdmin, "admin")
	pc1, pc2 := f.peer(pki.RoleClient, "pc-001"), f.peer(pki.RoleClient, "pc-002")
	pc1.heartbeatVersion("0.1.0")
	pc2.heartbeatVersion("0.1.0")
	bin := []byte("new susanoo binary")
	files := api.PathReleases + "/files/linux/amd64"

	if status, _ := admin.do(http.MethodGet, api.PathReleases, nil); status != http.StatusNotFound {
		t.Errorf("配布していないときの状態 = %d", status)
	}
	status, body := admin.do(http.MethodPost, api.PathReleases, api.ReleasePush{Manifest: releaseManifest(t, signer, sign.PurposeRelease, "0.2.0", bin), Canary: []string{"pc-001"}})
	var info api.ReleaseInfo
	if status != http.StatusOK || json.Unmarshal(body, &info) != nil || !slices.Equal(info.Missing, []string{"linux/amd64"}) || info.Promoted {
		t.Fatalf("目録の配布 = %d %s", status, body)
	}
	if cmd := pc1.heartbeatVersion("0.1.0"); cmd.Release != nil {
		t.Error("実行ファイルを受け取る前に勧めた")
	}
	if status, _ := admin.raw(http.MethodPut, files, []byte("tampered binary!!!")); status != http.StatusForbidden {
		t.Errorf("目録と合わない実行ファイルの応答 = %d", status)
	}
	if status, body := admin.raw(http.MethodPut, files, bin); status != http.StatusOK {
		t.Fatalf("実行ファイルの受け取り = %d %s", status, body)
	}
	if status, _ := admin.raw(http.MethodPut, api.PathReleases+"/files/linux/arm64", bin); status != http.StatusNotFound {
		t.Errorf("目録にないファイルの応答 = %d", status)
	}
	cmd := pc1.heartbeatVersion("0.1.0")
	if cmd.Release == nil || cmd.Release.Version != "0.2.0" {
		t.Fatalf("先行適用の端末への勧め = %+v", cmd.Release)
	}
	if cmd := pc2.heartbeatVersion("0.1.0"); cmd.Release != nil {
		t.Error("先行適用でない端末に勧めた")
	}
	if status, got := pc1.raw(http.MethodGet, files, nil); status != http.StatusOK || !bytes.Equal(got, bin) {
		t.Errorf("勧めた端末の受け取り = %d", status)
	}
	if status, _ := pc2.raw(http.MethodGet, files, nil); status != http.StatusNotFound {
		t.Errorf("勧めていない端末の受け取り = %d", status)
	}
	// 古い版、ほかの鍵、ほかの用途の署名、端末からの配布は断る。
	other := newPolicySigner(t)
	for name, tc := range map[string]struct {
		p      *peer
		push   api.ReleasePush
		status int
	}{
		"同じ版":      {admin, api.ReleasePush{Manifest: releaseManifest(t, signer, sign.PurposeRelease, "0.2.0", bin)}, http.StatusConflict},
		"古い版":      {admin, api.ReleasePush{Manifest: releaseManifest(t, signer, sign.PurposeRelease, "0.1.5", bin)}, http.StatusConflict},
		"ほかの鍵":     {admin, api.ReleasePush{Manifest: releaseManifest(t, other, sign.PurposeRelease, "0.3.0", bin)}, http.StatusForbidden},
		"ポリシーの用途":  {admin, api.ReleasePush{Manifest: releaseManifest(t, signer, sign.PurposePolicy, "0.3.0", bin)}, http.StatusForbidden},
		"知らないグループ": {admin, api.ReleasePush{Manifest: releaseManifest(t, signer, sign.PurposeRelease, "0.3.0", bin), CanaryGroups: []string{"nope"}}, http.StatusBadRequest},
		"端末からの配布":  {pc1, api.ReleasePush{Manifest: releaseManifest(t, signer, sign.PurposeRelease, "0.3.0", bin)}, http.StatusForbidden},
	} {
		if status, body := tc.p.do(http.MethodPost, api.PathReleases, tc.push); status != tc.status {
			t.Errorf("%s の応答 = %d %s", name, status, body)
		}
	}
	// 全体に広げると全員に勧める。入れ替えた端末には勧めず、版数の変化を監査ログに残す。
	if status, _ := admin.do(http.MethodPost, api.PathReleases+"/promote", nil); status != http.StatusOK {
		t.Fatal("全体に広げられない")
	}
	if cmd := pc2.heartbeatVersion("0.1.0"); cmd.Release == nil {
		t.Error("全体に広げた後も勧めない")
	}
	if cmd := pc1.heartbeatVersion("0.2.0"); cmd.Release != nil {
		t.Error("入れ替えた端末に勧めた")
	}
	_, body = admin.do(http.MethodGet, api.PathReleases, nil)
	json.Unmarshal(body, &info)
	if !info.Promoted || !slices.Equal(info.Updated, []string{"pc-001"}) || !slices.Equal(info.Pending, []string{"pc-002"}) {
		t.Errorf("配布の状態 = %+v", info)
	}
	if !slices.Contains(auditActions(t, dir), ActionUpdate+":pc-001") {
		t.Errorf("監査ログ = %v", auditActions(t, dir))
	}
	if d := f.devices(admin)["pc-001"]; d.Software != "0.2.0" {
		t.Errorf("台帳の版数 = %q", d.Software)
	}
	// 配布をやめると、勧めない。
	if status, _ := admin.do(http.MethodPost, api.PathReleases+"/abort", nil); status != http.StatusOK {
		t.Fatal("配布をやめられない")
	}
	if cmd := pc2.heartbeatVersion("0.1.0"); cmd.Release != nil {
		t.Error("配布をやめた後も勧めた")
	}
	if status, _ := admin.do(http.MethodGet, api.PathReleases, nil); status != http.StatusNotFound {
		t.Error("やめた配布が残っている")
	}
}
