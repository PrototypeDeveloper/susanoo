//go:build lab

package lab

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

var susanooNext = flag.String("susanoo-next", "", "リリースの入れ替えの試験で配る、版数だけを変えた susanoo の実行ファイル")

func init() {
	extraHelpers["supervise"] = supervise
}

// supervise は「実行ファイル|設定ファイル」の CLIENT を動かし、起動し直しを求めて終わったら（終了コード 75）起動し直す
// （systemd の Restart の代わり）。SIGTERM を受けたら CLIENT に送って終わる。
func supervise(arg string) int {
	exe, cfg, _ := strings.Cut(arg, "|")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	for {
		cmd := exec.Command(exe, "client", "-config", cfg)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			fmt.Println(err)
			return 1
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-sig:
			cmd.Process.Signal(syscall.SIGTERM)
			<-done
			return 0
		case err := <-done:
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != 75 {
				fmt.Println("CLIENT が終わりました:", err)
				return 1
			}
			fmt.Println("CLIENT が起動し直しを求めて終わりました（新しい版への入れ替えか、認証局の証明書の更新）。起動し直します")
		}
	}
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}

func copyExecutable(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestUpgrade は、署名付きのリリースの段階的な配布と、CLIENT の入れ替え（共通基盤の署名、非機能の更新）を確かめる。
func TestUpgrade(t *testing.T) {
	if *susanooBin == "" || *susanooNext == "" {
		t.Fatal("-susanoo と -susanoo-next で susanoo の実行ファイルを指定してください")
	}
	nextVersion := strings.TrimPrefix(strings.TrimSpace(sh(t, *susanooNext, "version")), "susanoo ")
	curVersion := strings.TrimPrefix(strings.TrimSpace(sh(t, *susanooBin, "version")), "susanoo ")
	pc1 := &machine{ns: "sus-c1", id: "pc-001", agent: true, port: "p-c1"} // 先行適用
	pc2 := &machine{ns: "sus-c2", id: "pc-002", agent: true, port: "p-c2"}
	machines := []*machine{pc1, pc2}
	l := &lab{t: t, dir: t.TempDir()}
	buildTopology(t, machines)
	l.setup(machines)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start(t, "GW", nsGW, nil, *susanooBin, "gw", "-config", filepath.Join(l.dir, "gw.json"))
	waitFor(t, "GW の起動", 10*time.Second, func() bool { return l.devices() != nil })
	exes := map[string]string{}
	for _, m := range machines {
		l.dhcp(m)
		// 端末ごとに実行ファイルを写し、それを入れ替えさせる。
		exe := filepath.Join(l.dir, m.id+"-bin", "susanoo")
		os.MkdirAll(filepath.Dir(exe), 0o755)
		copyExecutable(t, *susanooBin, exe)
		exes[m.id] = exe
		start(t, "CLIENT "+m.id, m.ns, []string{helperEnv + "=supervise:" + exe + "|" + filepath.Join(l.dir, m.id+".json")}, self)
	}
	waitFor(t, "端末の登録と版数の報告", 15*time.Second, func() bool {
		d := l.devices()
		return d[pc1.id].Software == curVersion && d[pc2.id].Software == curVersion
	})
	ctl := func(args ...string) string {
		t.Helper()
		out, err := inNS(nsGW, append(append([]string{*susanooBin, "ctl", "upgrade"}, args...), "-dir", l.ctrlDir, "-server", controllerAddr)...).CombinedOutput()
		if err != nil {
			t.Fatalf("ctl upgrade %s: %v\n%s", args[0], err, out)
		}
		return string(out)
	}

	t.Log("段階1: 管理者の鍵で目録に署名し、先行適用の端末にだけ配ると、その端末だけが新しい版に入れ替えて起動し直す")
	rel := filepath.Join(l.dir, "rel")
	l.susanoo("ctl", "upgrade", "sign", "-dir", l.ctrlDir, "-version", nextVersion, "-bin", runtime.GOOS+"/"+runtime.GOARCH+"="+*susanooNext, "-out", rel)
	ctl("push", rel, "-canary", pc1.id)
	waitFor(t, "先行適用の端末の入れ替え", 30*time.Second, func() bool { return l.devices()[pc1.id].Software == nextVersion })
	if got, want := fileSHA256(t, exes[pc1.id]), fileSHA256(t, *susanooNext); got != want {
		t.Errorf("入れ替えた実行ファイルのハッシュ = %s（%s のはず）", got, want)
	}
	if got, want := fileSHA256(t, exes[pc1.id]+".prev"), fileSHA256(t, *susanooBin); got != want {
		t.Error("前の実行ファイルを残していません")
	}
	time.Sleep(3 * time.Second)
	if v := l.devices()[pc2.id].Software; v != curVersion {
		t.Errorf("先行適用でない端末が入れ替えました: %s", v)
	}
	if out := ctl("status"); !strings.Contains(out, "入れ替えた端末 "+pc1.id) {
		t.Errorf("ctl upgrade status:\n%s", out)
	}

	t.Log("段階2: 全体に広げると、残りの端末も入れ替える。入れ替えは監査ログに残る")
	ctl("promote")
	waitFor(t, "全体の入れ替え", 30*time.Second, func() bool { return l.devices()[pc2.id].Software == nextVersion })
	actions := l.auditActions()
	for _, want := range []string{"release.push:" + nextVersion, "release.promote:" + nextVersion, "device.update:" + pc1.id, "device.update:" + pc2.id} {
		if !slices.Contains(actions, want) {
			t.Errorf("監査ログに %s がありません: %v", want, actions)
		}
	}
	// 入れ替えた端末は、新しい版のまま接続を続ける。
	before := l.devices()[pc1.id].LastSeen
	waitFor(t, "入れ替えた後の接続", 10*time.Second, func() bool { return l.devices()[pc1.id].LastSeen.After(before) })
}
