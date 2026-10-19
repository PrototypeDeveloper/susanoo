package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/keys"
	"susanoo/internal/pki"
	"susanoo/internal/pki/pkitest"
	"susanoo/internal/platform/platformtest"
	"susanoo/internal/sign"
	"susanoo/internal/transport"
)

// releaseServer は、相互TLSで実行ファイルを渡す偽の CONTROLLER。body を返し、受け取りの回数を数える。
type releaseServer struct {
	mu   sync.Mutex
	body []byte
	hits atomic.Int32
	addr netip.AddrPort
}

func startReleaseServer(t *testing.T, env *pkitest.Env, body []byte) *releaseServer {
	t.Helper()
	s := &releaseServer{body: body}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.addr = netip.MustParseAddrPort(ln.Addr().String())
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+api.PathReleases+"/files/{os}/{arch}", func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Write(s.body)
	})
	srv := &http.Server{Handler: mux, TLSConfig: transport.ServerConfig(env.CA.Pool(), env.Leaf(t, pki.RoleController, "main"), pki.RoleClient)}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
	return s
}

// script は「susanoo <版数>」と答える実行ファイル（シェルスクリプト）の中身を返す。
func script(version string) []byte {
	return []byte("#!/bin/sh\necho 'susanoo " + version + "'\n")
}

func signedManifest(t *testing.T, s *sign.Signer, version string, body []byte) sign.Envelope {
	t.Helper()
	sum := sha256.Sum256(body)
	m := api.ReleaseManifest{Version: version, IssuedAt: time.Now().UTC(), Files: []api.ReleaseFile{
		{OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body))},
	}}
	data, _ := json.Marshal(m)
	return s.Sign(sign.PurposeRelease, data)
}

// 執行部は、管理者の鍵で署名した目録の、今より新しい版で、ハッシュが合い、起動して版数を答える実行ファイルだけに入れ替える。
func TestLocalUpdate(t *testing.T) {
	env := pkitest.New(t)
	adminKey, _ := keys.Generate()
	admin, _ := sign.NewSigner(adminKey)
	next := script("0.2.0")
	srv := startReleaseServer(t, env, next)
	exe := filepath.Join(t.TempDir(), "susanoo")
	os.WriteFile(exe, script("0.1.0"), 0o755)
	updated := make(chan string, 1)
	l := newLocal(t, env, srv.addr, t.TempDir(), platformtest.New(caps))
	l.cfg.ReleaseKey, l.cfg.Executable, l.cfg.Version = admin.PublicKey(), exe, "0.1.0"
	l.cfg.OnUpdate = func(v string) { updated <- v }
	ctx := context.Background()
	offer := func(env2 sign.Envelope, version string) {
		t.Helper()
		cmd := api.Command{DeviceID: "pc-001", Version: 1, Release: &api.ReleaseOffer{Version: version, Manifest: env2}}
		if err := l.Apply(ctx, command(t, env.Signer, sign.PurposeCommand, cmd)); err != nil {
			t.Fatal(err)
		}
	}
	waitIdle := func() {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			l.updMu.Lock()
			busy := l.updating
			l.updMu.Unlock()
			if !busy {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("入れ替えが終わらない")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	unchanged := func(what string) {
		t.Helper()
		waitIdle()
		if got, _ := os.ReadFile(exe); string(got) != string(script("0.1.0")) {
			t.Fatalf("%s で入れ替えた", what)
		}
		select {
		case v := <-updated:
			t.Fatalf("%s で起動し直そうとした（%s）", what, v)
		default:
		}
	}

	// 古い版、別の鍵の署名、目録と合わない実行ファイル、版数を答えない実行ファイルには入れ替えない。
	offer(signedManifest(t, admin, "0.0.9", next), "0.0.9")
	unchanged("古い版")
	otherKey, _ := keys.Generate()
	forger, _ := sign.NewSigner(otherKey)
	offer(signedManifest(t, forger, "0.2.0", next), "0.2.0")
	unchanged("別の鍵の署名")
	offer(env.Signer.Sign(sign.PurposeRelease, nil), "0.2.0") // CONTROLLER の指示の鍵では署名できない
	unchanged("CONTROLLER の鍵の署名")
	if srv.hits.Load() != 0 {
		t.Fatalf("確かめる前に受け取った: %d 回", srv.hits.Load())
	}
	l.updFailed = map[string]time.Time{}
	offer(signedManifest(t, admin, "0.2.0", script("0.2.1")), "0.2.0") // 目録は別の中身のハッシュ
	unchanged("ハッシュの合わない実行ファイル")
	// 失敗した版数は、間をおくまで受け取り直さない。
	hits := srv.hits.Load()
	offer(signedManifest(t, admin, "0.2.0", script("0.2.1")), "0.2.0")
	unchanged("失敗の直後")
	if srv.hits.Load() != hits {
		t.Error("失敗の直後に受け取り直した")
	}
	l.updFailed = map[string]time.Time{}
	srv.mu.Lock()
	srv.body = script("9.9.9")
	srv.mu.Unlock()
	offer(signedManifest(t, admin, "0.2.0", script("9.9.9")), "0.2.0")
	unchanged("版数を答えない実行ファイル")

	// 正しいリリースに入れ替え、前の実行ファイルを残して、起動し直す。
	l.updFailed = map[string]time.Time{}
	srv.mu.Lock()
	srv.body = next
	srv.mu.Unlock()
	offer(signedManifest(t, admin, "0.2.0", next), "0.2.0")
	select {
	case v := <-updated:
		if v != "0.2.0" {
			t.Errorf("起動し直す版 = %s", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("入れ替えない")
	}
	if got, _ := os.ReadFile(exe); string(got) != string(next) {
		t.Error("実行ファイルを入れ替えていない")
	}
	if got, _ := os.ReadFile(exe + ".prev"); string(got) != string(script("0.1.0")) {
		t.Error("前の実行ファイルを残していない")
	}
	// ハートビートで今の版数を知らせる。
	hb, _ := l.Heartbeat(ctx)
	var h api.Heartbeat
	json.Unmarshal(hb.Payload, &h)
	if h.Version != "0.1.0" {
		t.Errorf("ハートビートの版数 = %q", h.Version)
	}
}

// リリースの公開鍵がなければ、勧められても受け取らない。
func TestLocalUpdateWithoutKey(t *testing.T) {
	env := pkitest.New(t)
	srv := startReleaseServer(t, env, script("0.2.0"))
	l := newLocal(t, env, srv.addr, t.TempDir(), platformtest.New(caps))
	l.cfg.Version = "0.1.0"
	cmd := api.Command{DeviceID: "pc-001", Version: 1, Release: &api.ReleaseOffer{Version: "0.2.0"}}
	if err := l.Apply(context.Background(), command(t, env.Signer, sign.PurposeCommand, cmd)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if srv.hits.Load() != 0 {
		t.Error("公開鍵がないのに受け取った")
	}
}
