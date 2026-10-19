package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/pki"
	"susanoo/internal/release"
	"susanoo/internal/sign"
	"susanoo/internal/transport"
	"susanoo/internal/version"
)

// リリースの入れ替え（共通基盤の署名、非機能の更新）。
//
// CONTROLLER は指示の中で入れ替えを勧める（api.ReleaseOffer）。執行部は、目録の署名を管理者の鍵（ReleaseKey）で確かめ、
// 今より新しい版数で、この OS と CPU の実行ファイルがあるときだけ、CONTROLLER から受け取って大きさとハッシュを照らし、
// 受け取ったファイルを起動して版数を答えることを確かめてから、実行ファイルを入れ替える。前の実行ファイルは「.prev」に残す。
// 入れ替えたら OnUpdate を呼び、CLIENT は終わって systemd などに起動し直してもらう（権限を手放した執行部は、自分を起動し直せない）。

const (
	updateTimeout    = 10 * time.Minute // 受け取りと入れ替えに許す時間
	updateRetryAfter = 10 * time.Minute // 失敗したら、同じ版数をこの間は試さない
)

// currentVersion は今の版数を返す。
func (l *Local) currentVersion() string {
	if l.cfg.Version != "" {
		return l.cfg.Version
	}
	return version.Version
}

// offerRelease は、勧められたリリースを、入れ替えるべきなら別のゴルーチンで入れ替える。
func (l *Local) offerRelease(offer *api.ReleaseOffer) {
	if l.cfg.ReleaseKey == nil {
		l.updMu.Lock()
		warned := l.noKeyWarned
		l.noKeyWarned = true
		l.updMu.Unlock()
		if !warned {
			l.log.Warn("リリースの公開鍵（release.pub）がないため、勧められたリリースに入れ替えません", "版数", offer.Version)
		}
		return
	}
	if release.Compare(offer.Version, l.currentVersion()) <= 0 {
		return
	}
	now := l.cfg.Now()
	l.updMu.Lock()
	if l.updating || now.Sub(l.updFailed[offer.Version]) < updateRetryAfter {
		l.updMu.Unlock()
		return
	}
	l.updating = true
	l.updMu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
		defer cancel()
		err := l.update(ctx, offer)
		l.updMu.Lock()
		l.updating = false
		if err != nil {
			l.updFailed[offer.Version] = l.cfg.Now()
		}
		l.updMu.Unlock()
		if err != nil {
			l.log.Error("リリースに入れ替えられません。間をおいて試し直します", "版数", offer.Version, "エラー", err)
			return
		}
		l.log.Warn("新しい版に入れ替えました。CLIENT を起動し直します", "前", l.currentVersion(), "今", offer.Version)
		if l.cfg.OnUpdate != nil {
			l.cfg.OnUpdate(offer.Version)
		}
	}()
}

// update は勧められたリリースを確かめて、実行ファイルを入れ替える。
func (l *Local) update(ctx context.Context, offer *api.ReleaseOffer) error {
	v, err := sign.NewVerifier(l.cfg.ReleaseKey)
	if err != nil {
		return err
	}
	m, err := release.Verify(v, offer.Manifest)
	if err != nil {
		return err
	}
	if m.Version != offer.Version || release.Compare(m.Version, l.currentVersion()) <= 0 {
		return fmt.Errorf("目録の版数 %s は今の版 %s より新しくありません", m.Version, l.currentVersion())
	}
	f, ok := release.File(m, runtime.GOOS, runtime.GOARCH)
	if !ok {
		return fmt.Errorf("目録に %s/%s の実行ファイルがありません", runtime.GOOS, runtime.GOARCH)
	}
	exe := l.cfg.Executable
	if exe == "" {
		if exe, err = os.Executable(); err != nil {
			return err
		}
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(exe), "."+filepath.Base(exe)+".new-*")
	if err != nil {
		return fmt.Errorf("入れ替えるファイルを作れません: %w", err)
	}
	defer os.Remove(tmp.Name())
	n, sum, err := l.download(ctx, f, tmp)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != f.Size || sum != f.SHA256 {
		return fmt.Errorf("受け取った実行ファイルが目録と合いません（大きさ %d、目録 %d）", n, f.Size)
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	// 受け取ったファイルが、この端末で動き、目録の版数を答えることを確かめる。
	vctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(vctx, tmp.Name(), "version").Output()
	if err != nil || strings.TrimSpace(string(out)) != "susanoo "+m.Version {
		return fmt.Errorf("受け取った実行ファイルが動かないか、版数が違います（%q、%v）", bytes.TrimSpace(out), err)
	}
	prev := exe + ".prev"
	os.Remove(prev)
	if err := os.Link(exe, prev); err != nil {
		l.log.Warn("前の実行ファイルを残せません", "エラー", err)
	}
	if err := os.Rename(tmp.Name(), exe); err != nil {
		return fmt.Errorf("実行ファイルを入れ替えられません: %w", err)
	}
	return nil
}

// download は、CONTROLLER から実行ファイルを受け取って w に書き、大きさと SHA-256 を返す。
func (l *Local) download(ctx context.Context, f api.ReleaseFile, w io.Writer) (int64, string, error) {
	if l.cfg.CA == nil {
		return 0, "", errors.New("認証局がないため、CONTROLLER に接続できません")
	}
	l.mu.Lock()
	cert := tls.Certificate{Certificate: l.chain, PrivateKey: l.key, Leaf: l.leaf}
	l.mu.Unlock()
	tr := &http.Transport{TLSClientConfig: transport.ClientConfig(l.cfg.CA, cert, pki.RoleController), ForceAttemptHTTP2: true}
	defer tr.CloseIdleConnections()
	url := fmt.Sprintf("https://%s%s/files/%s/%s", l.cfg.Controller, api.PathReleases, f.OS, f.Arch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("実行ファイルを受け取れません: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("実行ファイルを受け取れません: %s", resp.Status)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(resp.Body, f.Size+1))
	if err != nil {
		return n, "", fmt.Errorf("実行ファイルを受け取れません: %w", err)
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}
