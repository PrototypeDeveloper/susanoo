package honeytoken

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"susanoo/internal/event"
)

var now = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func TestGenerate(t *testing.T) {
	tests := []struct {
		kind Kind
		re   string
	}{
		{KindAWS, `(?m)^aws_access_key_id = AKIA[A-Z2-7]{16}$`},
		{KindSSH, `^-----BEGIN OPENSSH PRIVATE KEY-----\n`},
		{KindEnv, `(?m)^ANTHROPIC_API_KEY=sk-ant-api03-[A-Za-z0-9_-]{93}AA$`},
		{KindText, `PW: [A-Za-z0-9]{14}`},
	}
	for _, tt := range tests {
		a, err := Generate(tt.kind)
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(tt.re).Match(a) {
			t.Errorf("%s: 形が違う\n%s", tt.kind, a)
		}
		b, err := Generate(tt.kind)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(a, b) {
			t.Errorf("%s: 毎回同じ中身になる", tt.kind)
		}
	}
	if _, err := Generate("unknown"); err == nil {
		t.Error("不明な種類を受け付けた")
	}
}

func TestSSHKeyIsReadableByOpenSSH(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen がない")
	}
	key, err := Generate(KindSSH)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(keygen, "-y", "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen が鍵を読めない: %v\n%s", err, out)
	}
	if !strings.HasPrefix(string(out), "ssh-ed25519 ") {
		t.Errorf("公開鍵 = %q", out)
	}
}

func TestPlant(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	specs := []Spec{
		{Path: filepath.Join(dir, "home", ".aws", "credentials"), Kind: KindAWS},
		{Path: filepath.Join(dir, "home", ".ssh", "id_ed25519"), Kind: KindSSH},
	}

	tokens, warnings, err := Plant(specs, statePath, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 || len(tokens) != 2 {
		t.Fatalf("おとり = %v, 警告 = %v", tokens, warnings)
	}
	for _, tok := range tokens {
		fi, err := os.Stat(tok.Path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s の権限 = %v", tok.Path, fi.Mode().Perm())
		}
		di, err := os.Stat(filepath.Dir(tok.Path))
		if err != nil {
			t.Fatal(err)
		}
		if di.Mode().Perm() != 0o700 {
			t.Errorf("%s の権限 = %v", filepath.Dir(tok.Path), di.Mode().Perm())
		}
	}

	// 2 回目は同じおとりをそのまま使う。
	again, warnings, err := Plant(specs, statePath, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 || len(again) != 2 || again[0] != tokens[0] || again[1] != tokens[1] {
		t.Errorf("2 回目: おとり = %v, 警告 = %v", again, warnings)
	}
}

func TestPlantNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "credentials")
	if err := os.WriteFile(real, []byte("本物の認証情報"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "target"), link); err != nil {
		t.Fatal(err)
	}

	tokens, warnings, err := Plant([]Spec{
		{Path: real, Kind: KindAWS},
		{Path: link, Kind: KindAWS},
	}, filepath.Join(dir, "state.json"), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 0 || len(warnings) != 2 {
		t.Errorf("おとり = %v, 警告 = %v", tokens, warnings)
	}
	if got, _ := os.ReadFile(real); string(got) != "本物の認証情報" {
		t.Errorf("既存のファイルが書き換えられた: %q", got)
	}
	if _, err := os.Lstat(filepath.Join(dir, "target")); err == nil {
		t.Error("シンボリックリンクの先にファイルが作られた")
	}
}

func TestPlantRecovers(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	aws := Spec{Path: filepath.Join(dir, "a", "credentials"), Kind: KindAWS}
	env := Spec{Path: filepath.Join(dir, "b", ".env"), Kind: KindEnv}
	first, _, err := Plant([]Spec{aws, env}, statePath, now)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(aws.Path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.Path, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}

	tokens, warnings, err := Plant([]Spec{aws, env}, statePath, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 || len(warnings) != 2 {
		t.Fatalf("おとり = %v, 警告 = %v", tokens, warnings)
	}
	if tokens[0].SHA256 == first[0].SHA256 {
		t.Error("消えたおとりが置き直されていない")
	}
	if tokens[1] != first[1] {
		t.Error("中身が変わったおとりの記録が変わった")
	}
	if !strings.Contains(warnings[0].Error(), "置き直しました") || !strings.Contains(warnings[1].Error(), "変わっています") {
		t.Errorf("警告 = %v", warnings)
	}
}

func TestPlantRejectsInvalidSpecs(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x")
	tokens, warnings, err := Plant([]Spec{
		{Path: "relative/path", Kind: KindAWS},
		{Path: p, Kind: "unknown"},
		{Path: filepath.Join(dir, "y"), Kind: KindText},
		{Path: filepath.Join(dir, "y"), Kind: KindText},
	}, filepath.Join(dir, "state.json"), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 1 || len(warnings) != 3 {
		t.Errorf("おとり = %v, 警告 = %v", tokens, warnings)
	}
	if _, err := os.Lstat(p); err == nil {
		t.Error("不明な種類のおとりが置かれた")
	}
}

func TestFinding(t *testing.T) {
	tok := Token{Path: "/home/user/.aws/credentials", Kind: KindAWS}
	e := Finding(tok, OpOpen, &event.Process{PID: 4242, Name: "cat"}, now)
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	if !e.FindingInfo.HasType(event.FindingTypeHoneytoken) {
		t.Error("検知の種類に honeytoken がない")
	}
	if want := "おとり /home/user/.aws/credentials が cat（PID 4242） によって開かれました"; e.Message != want {
		t.Errorf("説明 = %q, 期待値 %q", e.Message, want)
	}
	if e.Evidences[0].File.Path != tok.Path {
		t.Errorf("根拠のファイル = %+v", e.Evidences[0].File)
	}

	unknown := Finding(tok, OpAccess, nil, now)
	if !strings.Contains(unknown.Message, "不明なプロセス") {
		t.Errorf("説明 = %q", unknown.Message)
	}
}
