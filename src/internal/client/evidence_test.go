package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/honeytoken"
	"susanoo/internal/notify"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/platform"
	"susanoo/internal/platform/platformtest"
	"susanoo/internal/sign"
	"susanoo/internal/transport"
)

var capsEvidence = platform.Capabilities{OS: "linux", Features: []platform.Capability{platform.CapHoneytoken, platform.CapIsolation, platform.CapEvidence}}

// hooks は偽の webhook の受け口（ループバック）に届いた本文を記録する。
type hooks struct {
	mu     sync.Mutex
	bodies []map[string]any
}

func (h *hooks) has(kind, target string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.ContainsFunc(h.bodies, func(b map[string]any) bool { return b["kind"] == kind && b["target"] == target })
}

func startHooks(t *testing.T) (*hooks, *notify.Notifier) {
	t.Helper()
	h := &hooks{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		h.mu.Lock()
		h.bodies = append(h.bodies, b)
		h.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	n, err := notify.New(notify.Config{Destinations: []notify.Destination{{Name: "hook", Type: "webhook", URL: srv.URL}}}, notify.Options{Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	return h, n
}

func adminGet(t *testing.T, env *pkitest.Env, addr netip.AddrPort, path string, out any) {
	t.Helper()
	tr := &http.Transport{TLSClientConfig: transport.ClientConfig(env.CA.Pool(), env.Leaf(t, pki.RoleAdmin, "admin"), pki.RoleController)}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr}).Get("https://" + addr.String() + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s の応答 = %s %s", path, resp.Status, b)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

func evidenceList(t *testing.T, env *pkitest.Env, addr netip.AddrPort) []api.EvidenceInfo {
	var list []api.EvidenceInfo
	adminGet(t, env, addr, api.PathEvidence+"?device=pc-001", &list)
	return list
}

// 隔離の指示を受けた執行部は証拠を集めて署名し、解析部が CONTROLLER に送る。管理者は隔離しなくても集めさせられる。
// 隔離と解除は通知される。
func TestEvidenceAndNotification(t *testing.T) {
	env := pkitest.New(t)
	h, n := startHooks(t)
	addr := startControllerWith(t, env, &fakeEnforcer{}, n)
	fake := platformtest.New(capsEvidence)
	stateDir := t.TempDir()
	agent := newAgent(t, env, addr, stateDir, fake)
	run(t, agent)

	e := honeytoken.Finding(honeytoken.Token{Path: "/home/u/.aws/credentials", Kind: honeytoken.KindAWS}, honeytoken.OpOpen, nil, time.Now())
	if err := fake.Emit(context.Background(), *e); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "隔離の証拠", func() bool { return len(evidenceList(t, env, addr)) == 1 })
	info := evidenceList(t, env, addr)[0]
	if info.Reason != api.EvidenceReasonIsolation || info.Processes != 2 || info.Connections != 1 || len(info.SHA256) != 64 {
		t.Errorf("証拠の概要 = %+v", info)
	}
	var ev api.Evidence
	adminGet(t, env, addr, api.PathEvidence+"/pc-001/"+info.ID, &ev)
	if ev.DeviceID != "pc-001" || ev.Isolation == "" || ev.Snapshot.Processes[1].Exe != "/tmp/.x/run" {
		t.Errorf("証拠の中身 = %+v", ev)
	}
	// 署名付きのまま取り出した証拠は、端末の鍵で確かめられる。
	var signed sign.Envelope
	adminGet(t, env, addr, api.PathEvidence+"/pc-001/"+info.ID+"?signed=1", &signed)
	pub := agent.cert.Leaf.PublicKey.(ed25519.PublicKey)
	if v, _ := sign.NewVerifier(pub); v == nil {
		t.Fatal("検証の鍵を作れない")
	} else if _, err := v.Verify(sign.PurposeEvidence, signed); err != nil {
		t.Errorf("署名を確かめられない: %v", err)
	}
	waitFor(t, "隔離の通知", func() bool { return h.has("isolate", "pc-001") })

	// 管理者が求めると、隔離の状態は変えずに（自己隔離をかけ直さずに）、もう一度集める。
	adminPost(t, env, addr, api.PathDevices+"/pc-001/evidence")
	waitFor(t, "求めた証拠", func() bool { return len(evidenceList(t, env, addr)) == 2 })
	if got := evidenceList(t, env, addr)[0].Reason; got != api.EvidenceReasonRequest {
		t.Errorf("新しい証拠のきっかけ = %s", got)
	}
	isolates := 0
	for _, x := range fake.History() {
		if strings.HasPrefix(x, "isolate:") {
			isolates++
		}
	}
	if isolates != 1 {
		t.Errorf("自己隔離を %d 回かけた（履歴 %v）", isolates, fake.History())
	}
	// 端末には送った証拠の控えが残る。
	sent, _ := filepath.Glob(filepath.Join(stateDir, "evidence", "*"+sentSuffix))
	kept, _ := filepath.Glob(filepath.Join(stateDir, "evidence", "*.json"))
	if len(sent) != 2 || len(kept) != 2 {
		t.Errorf("端末の証拠 = %v、送った印 = %v", kept, sent)
	}

	adminPost(t, env, addr, api.PathDevices+"/pc-001/release")
	waitFor(t, "解除の通知", func() bool { return h.has("release", "pc-001") })
	if len(evidenceList(t, env, addr)) != 2 {
		t.Error("解除で証拠を集めた")
	}
}

// 証拠は端末の証明書の鍵で署名されていなければ受け付けない。ほかの端末を名乗る証拠も受け付けない。
func TestEvidenceRejectsForgery(t *testing.T) {
	env := pkitest.New(t)
	addr := startController(t, env, &fakeEnforcer{})
	cert := env.Leaf(t, pki.RoleClient, "pc-001")
	tr := &http.Transport{TLSClientConfig: transport.ClientConfig(env.CA.Pool(), cert, pki.RoleController)}
	defer tr.CloseIdleConnections()
	post := func(env sign.Envelope) int {
		data, _ := json.Marshal(api.EvidenceUpload{Envelope: env})
		resp, err := (&http.Client{Transport: tr}).Post("https://"+addr.String()+api.PathEvidence, "application/json", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	payload := func(ev api.Evidence) []byte { b, _ := json.Marshal(ev); return b }
	good := api.Evidence{DeviceID: "pc-001", ID: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", Time: time.Now(), Reason: api.EvidenceReasonRequest}
	own, _ := sign.NewSigner(cert.PrivateKey.(ed25519.PrivateKey))
	other, _ := sign.NewSigner(env.Leaf(t, pki.RoleClient, "pc-002").PrivateKey.(ed25519.PrivateKey))

	spoofed := good
	spoofed.DeviceID = "pc-002"
	badReason := good
	badReason.Reason = "whatever"
	for name, tc := range map[string]struct {
		env  sign.Envelope
		want int
	}{
		"ほかの鍵の署名":   {other.Sign(sign.PurposeEvidence, payload(good)), http.StatusForbidden},
		"用途が違う署名":   {own.Sign(sign.PurposeHeartbeat, payload(good)), http.StatusForbidden},
		"ほかの端末を名乗る": {own.Sign(sign.PurposeEvidence, payload(spoofed)), http.StatusForbidden},
		"きっかけが不正":   {own.Sign(sign.PurposeEvidence, payload(badReason)), http.StatusBadRequest},
		"正しい証拠":     {own.Sign(sign.PurposeEvidence, payload(good)), http.StatusOK},
		"同じ証拠の再送":   {own.Sign(sign.PurposeEvidence, payload(good)), http.StatusOK},
	} {
		if got := post(tc.env); got != tc.want {
			t.Errorf("%s の応答 = %d、期待値 %d", name, got, tc.want)
		}
	}
	if list := evidenceList(t, env, addr); len(list) != 1 {
		t.Errorf("証拠の一覧 = %+v（1 件のはず）", list)
	}
}

// 端末に残す証拠は新しいものから 10 個。CONTROLLER が中身を理由に受け付けない証拠は、送り直さずに次へ進む。
func TestLocalEvidenceKeepAndSkip(t *testing.T) {
	env := pkitest.New(t)
	addr := startController(t, env, &fakeEnforcer{})
	fake := platformtest.New(capsEvidence)
	stateDir := t.TempDir()
	l := newLocal(t, env, addr, stateDir, fake)
	for range maxLocalEvidence + 3 {
		l.collect(api.EvidenceReasonRequest, 1, "")
		time.Sleep(2 * time.Millisecond) // ファイルの名前（ミリ秒）を変える
	}
	if files, _ := filepath.Glob(filepath.Join(stateDir, "evidence", "*.json")); len(files) != maxLocalEvidence {
		t.Errorf("残した証拠 = %d 個", len(files))
	}
	if err := l.AckEvidence(context.Background(), "../../etc/passwd"); err == nil {
		t.Error("不正な ID を受け付けた")
	}
	// CONTROLLER が受け付けない証拠（きっかけが不正）を、執行部の鍵で署名して置く。
	files, _ := filepath.Glob(filepath.Join(stateDir, "evidence", "*.json"))
	for _, f := range files {
		os.Remove(f)
	}
	bad, _ := json.Marshal(api.Evidence{DeviceID: "pc-001", ID: "AAAAAAAAAAAAAAAAAAAAAAAAAA", Time: time.Now(), Reason: "bogus"})
	data, _ := json.Marshal(l.signer.Sign(sign.PurposeEvidence, bad))
	os.WriteFile(filepath.Join(stateDir, "evidence", "0000000000001-AAAAAAAAAAAAAAAAAAAAAAAAAA.json"), data, 0o600)
	l.collect(api.EvidenceReasonRequest, 2, "")

	a, err := New(Config{Controller: addr, CA: env.CA.Pool(), Chain: l.cfg.Cert.Certificate, HeartbeatInterval: 50 * time.Millisecond, Executor: l, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	run(t, a)
	waitFor(t, "正しい証拠の送信", func() bool { return len(evidenceList(t, env, addr)) == 1 })
	if _, ok := os.Stat(filepath.Join(stateDir, "evidence", "0000000000001-AAAAAAAAAAAAAAAAAAAAAAAAAA"+sentSuffix)); ok != nil {
		t.Error("受け付けられない証拠を飛ばしていない")
	}
}
