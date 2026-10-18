package client

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"susanoo/internal/api"
	"susanoo/internal/fsutil"
	"susanoo/internal/platform"
	"susanoo/internal/policy"
	"susanoo/internal/sign"
)

// 証拠の保全（C11）。執行部は、隔離の指示を受けたときと、管理者が求めたとき（指示の Evidence が増えたとき）に、
// Platform から端末の状態（プロセス、接続、ログなど）を集め、端末の鍵で署名して状態のディレクトリに保存する。
// 解析部は保存した証拠を 1 つずつ受け取って CONTROLLER に送り、受け取られたら執行部に知らせる。
// 送った証拠も、新しいものから maxLocalEvidence 個は端末に残す（CONTROLLER に届かない場合の控え）。
// 署名は執行部だけが作れるので、乗っ取られた解析部は証拠を偽造できない。

const (
	evidenceDirName  = "evidence"
	maxLocalEvidence = 10
	evidenceTimeout  = time.Minute
	sentSuffix       = ".sent"
)

// evidenceIDPattern は証拠の ID（crypto/rand.Text の形）。
var evidenceIDPattern = regexp.MustCompile(`^[A-Z2-7]{26}$`)

// ValidEvidenceID は証拠の ID の形が正しいかを返す。
func ValidEvidenceID(id string) bool { return evidenceIDPattern.MatchString(id) }

func (l *Local) evidenceDir() string { return filepath.Join(l.cfg.StateDir, evidenceDirName) }

// startCollect は、reason が空でなければ、証拠を集める処理を始める（待たずに返る）。
func (l *Local) startCollect(reason string, version uint64, iso policy.IsolationLevel) {
	if reason == "" {
		return
	}
	go l.collect(reason, version, iso)
}

// collect は証拠を集め、署名して保存する。同時には 1 つずつ集める。
func (l *Local) collect(reason string, version uint64, iso policy.IsolationLevel) {
	l.collectMu.Lock()
	defer l.collectMu.Unlock()
	c, ok := l.cfg.Platform.(platform.Collector)
	if !ok || !l.cfg.Platform.Capabilities().Has(platform.CapEvidence) {
		l.log.Warn("この端末では証拠を集められません", "きっかけ", reason)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), evidenceTimeout)
	defer cancel()
	snap, err := c.Snapshot(ctx)
	if snap == nil {
		l.log.Error("証拠を集められません", "きっかけ", reason, "エラー", err)
		return
	}
	if err != nil {
		snap.Errors = append(snap.Errors, "集める途中で止めました: "+err.Error())
	}
	ev := api.Evidence{DeviceID: l.id.ID, ID: rand.Text(), Time: l.cfg.Now().UTC(), Reason: reason, Command: version, Isolation: iso,
		Hostname: l.hostname, Snapshot: *snap}
	payload, err := fitEvidence(&ev)
	if err != nil {
		l.log.Error("証拠を記録できません", "エラー", err)
		return
	}
	env := l.signer.Sign(sign.PurposeEvidence, payload)
	data, err := json.Marshal(env)
	if err != nil {
		return
	}
	l.fileMu.Lock()
	defer l.fileMu.Unlock()
	if err := os.MkdirAll(l.evidenceDir(), 0o700); err != nil {
		l.log.Error("証拠を保存できません", "エラー", err)
		return
	}
	name := fmt.Sprintf("%013d-%s.json", ev.Time.UnixMilli(), ev.ID)
	if err := fsutil.WriteFileAtomic(filepath.Join(l.evidenceDir(), name), data, 0o600); err != nil {
		l.log.Error("証拠を保存できません", "エラー", err)
		return
	}
	l.pruneEvidenceLocked()
	l.log.Warn("証拠を保全しました。CONTROLLER に送ります", "きっかけ", reason, "ID", ev.ID,
		"プロセス", len(ev.Snapshot.Processes), "接続", len(ev.Snapshot.Connections), "ログ", len(ev.Snapshot.Logs), "バイト", len(payload))
}

// fitEvidence は証拠を JSON にする。api.MaxEvidencePayload を超えたら、ログ、接続、プロセスの順に削って、削ったことを書き添える。
func fitEvidence(ev *api.Evidence) ([]byte, error) {
	payload, err := json.Marshal(ev)
	for step := 0; err == nil && len(payload) > api.MaxEvidencePayload; step++ {
		s := &ev.Snapshot
		switch {
		case len(s.Logs) > 0:
			s.Logs = nil
			s.Errors = append(s.Errors, "大きすぎるため、ログを省きました")
		case len(s.Connections) > 1000:
			s.Connections = s.Connections[:1000]
			s.Errors = append(s.Errors, "大きすぎるため、接続を 1000 件に減らしました")
		case len(s.Processes) > 100:
			n := len(s.Processes) / 2
			s.Processes = s.Processes[:n]
			s.Errors = append(s.Errors, fmt.Sprintf("大きすぎるため、プロセスを %d 件に減らしました", n))
		default:
			return nil, errors.New("証拠が大きすぎます")
		}
		payload, err = json.Marshal(ev)
	}
	return payload, err
}

// pruneEvidenceLocked は、新しいものから maxLocalEvidence 個を残して、古い証拠を消す。fileMu を持って呼ぶ。
func (l *Local) pruneEvidenceLocked() {
	names := l.evidenceFilesLocked()
	for len(names) > maxLocalEvidence {
		base := filepath.Join(l.evidenceDir(), strings.TrimSuffix(names[0], ".json"))
		os.Remove(base + ".json")
		os.Remove(base + sentSuffix)
		names = names[1:]
	}
}

// evidenceFilesLocked は保存した証拠のファイルの名前を古い順に返す。fileMu を持って呼ぶ。
func (l *Local) evidenceFilesLocked() []string {
	entries, _ := os.ReadDir(l.evidenceDir())
	var names []string
	for _, e := range entries {
		if n := e.Name(); strings.HasSuffix(n, ".json") && e.Type().IsRegular() {
			names = append(names, n)
		}
	}
	slices.Sort(names) // 名前は時刻（ミリ秒、13 桁）から始まる
	return names
}

func evidenceIDOf(name string) string {
	_, id, _ := strings.Cut(strings.TrimSuffix(name, ".json"), "-")
	return id
}

// NextEvidence は、まだ CONTROLLER に受け取られていない最も古い証拠を返す。なければ ok が false。
func (l *Local) NextEvidence(context.Context) (string, sign.Envelope, bool, error) {
	l.fileMu.Lock()
	defer l.fileMu.Unlock()
	for _, name := range l.evidenceFilesLocked() {
		path := filepath.Join(l.evidenceDir(), name)
		if _, err := os.Stat(strings.TrimSuffix(path, ".json") + sentSuffix); err == nil {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", sign.Envelope{}, false, err
		}
		var env sign.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			return "", sign.Envelope{}, false, fmt.Errorf("client: 証拠のファイル %s を読めません: %w", name, err)
		}
		return evidenceIDOf(name), env, true, nil
	}
	return "", sign.Envelope{}, false, nil
}

// AckEvidence は、証拠 id が CONTROLLER に受け取られたことを記録する（ファイルは控えとして残す）。
func (l *Local) AckEvidence(_ context.Context, id string) error {
	if !ValidEvidenceID(id) {
		return errors.New("client: 証拠の ID の形が正しくありません")
	}
	l.fileMu.Lock()
	defer l.fileMu.Unlock()
	for _, name := range l.evidenceFilesLocked() {
		if evidenceIDOf(name) == id {
			return os.WriteFile(filepath.Join(l.evidenceDir(), strings.TrimSuffix(name, ".json")+sentSuffix), nil, 0o600)
		}
	}
	return fmt.Errorf("client: 証拠 %s はありません", id)
}
