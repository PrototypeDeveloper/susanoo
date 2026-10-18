package rules

import (
	"fmt"
	"path"
	"slices"
	"testing"

	"susanoo/internal/event"
)

// launch はプロセスの起動のイベントを作る。agent が空でなければ、AI エージェントの帰属を付ける。
func launch(exe, parent, agent string) *event.Event {
	e := event.New(event.ClassProcessActivity, event.ProcessLaunch, event.SeverityInformational, now)
	e.Device = &event.Device{UID: "pc-001"}
	e.Process = &event.Process{PID: 100, Name: "x", File: &event.File{Name: path.Base(exe), Path: exe}}
	if parent != "" {
		e.Process.Parent = &event.Process{PID: 50, Name: parent}
	}
	if agent != "" {
		e.Unmapped = map[string]any{"agent": map[string]any{"name": agent, "pid": 40}}
	}
	return e
}

func connection(dst string, direction int) *event.Event {
	e := event.New(event.ClassNetworkActivity, event.NetworkOpen, event.SeverityInformational, now)
	e.Device = &event.Device{UID: "pc-001"}
	e.SrcEndpoint = &event.Endpoint{IP: "192.168.10.20", Port: 40000}
	e.DstEndpoint = &event.Endpoint{IP: dst, Port: 445}
	e.Connection = &event.Connection{ProtocolName: "tcp", DirectionID: direction}
	return e
}

func clientFinding(typ, agent string) *event.Event {
	e := finding(typ)
	if agent != "" {
		e.Unmapped = map[string]any{"agent": map[string]any{"name": agent, "pid": 40}}
	}
	return e
}

// 既定の条件のルール（2c-2）は、構造で判断する。
func TestDefaultConditionRules(t *testing.T) {
	e := NewEngine(nil)
	sub := Subject{Key: "device:pc-001", Group: "default", IDs: []string{"pc-001"}}
	eval := func(ev *event.Event, c *Counter) []string {
		return ids(e.Evaluate(ev, sub, c, now))
	}
	var c Counter
	for name, tc := range map[string]struct {
		ev   *event.Event
		want []string
	}{
		"サービスからのシェル":    {launch("/usr/bin/dash", "nginx", ""), []string{"shell-from-service"}},
		"アプリからのシェル":     {launch("/usr/bin/bash", "firefox", ""), []string{"shell-from-app"}},
		"ふつうのシェル":       {launch("/usr/bin/bash", "bash", ""), nil},
		"サービスからのほかの命令":  {launch("/usr/bin/cat", "nginx", ""), nil},
		"一時的な場所からの実行":   {launch("/tmp/.x/agent", "bash", ""), []string{"exec-from-temp"}},
		"共有メモリからの実行":    {launch("/dev/shm/run", "bash", ""), []string{"exec-from-temp"}},
		"ふつうの場所からの実行":   {launch("/usr/bin/ls", "bash", ""), nil},
		"エージェントの sudo":  {launch("/usr/bin/sudo", "bash", "claude"), []string{"agent-privilege"}},
		"利用者の sudo":     {launch("/usr/bin/sudo", "bash", ""), nil},
		"エージェントのふつうの命令": {launch("/usr/bin/ls", "bash", "claude"), nil},
	} {
		if got := eval(tc.ev, &c); !slices.Equal(got, tc.want) {
			t.Errorf("%s = %v, 期待値 %v", name, got, tc.want)
		}
	}
	// シンボリックリンクで起動した命令は、実体の名前が違っても、起動したときの名前で当てはまる。
	viaLink := launch("/usr/lib/cargo/bin/sudo-rs", "bash", "claude")
	viaLink.Process.Name = "sudo"
	if got := eval(viaLink, &c); !slices.Equal(got, []string{"agent-privilege"}) {
		t.Errorf("起動したときの名前が sudo = %v", got)
	}
	shAsDash := launch("/usr/bin/dash", "nginx", "")
	shAsDash.Process.Name = "sh"
	if got := eval(shAsDash, &c); !slices.Equal(got, []string{"shell-from-service"}) {
		t.Errorf("sh として起動した dash = %v", got)
	}

	// 連続する列挙：情報を調べる命令が 2 分に 10 回で検知する。ほかの命令（cat、ls）は数えない。
	var c2 Counter
	for i, cmd := range []string{"id", "whoami", "uname", "hostname", "ip", "ps", "ss", "env", "cat", "ls", "mount", "lsof"} {
		got := eval(launch("/usr/bin/"+cmd, "bash", ""), &c2)
		switch {
		case cmd == "lsof": // 列挙の命令の 10 回目
			if !slices.Equal(got, []string{"enumeration"}) {
				t.Errorf("10 回目（%s）= %v", cmd, got)
			}
		case len(got) != 0:
			t.Errorf("%d 回目（%s）で検知した: %v", i+1, cmd, got)
		}
	}

	// LAN の中への多数の接続：外向きで LAN のアドレスへの接続が 1 分に 30 回で検知する。外部や内向きは数えない。
	var c3 Counter
	for i := range 29 {
		if got := eval(connection(fmt.Sprintf("192.168.10.%d", 10+i), 2), &c3); len(got) != 0 {
			t.Fatalf("%d 回目で検知した: %v", i+1, got)
		}
	}
	if got := eval(connection("203.0.113.9", 2), &c3); len(got) != 0 {
		t.Errorf("外部への接続を数えた: %v", got)
	}
	if got := eval(connection("192.168.10.77", 1), &c3); len(got) != 0 {
		t.Errorf("内向きの接続を数えた: %v", got)
	}
	if got := eval(connection("10.77.0.9", 2), &c3); !slices.Equal(got, []string{"internal-connections-burst"}) {
		t.Errorf("30 回目 = %v", got)
	}

	// AI エージェントによる要注意の操作：帰属の付いた検知結果に、その種類のルールと重ねて当てはまる。
	if got := eval(clientFinding(event.FindingTypePersistence, "claude"), &c); !slices.Equal(got, []string{"persistence", "agent-sensitive-action"}) {
		t.Errorf("エージェントの永続化 = %v", got)
	}
	if got := eval(clientFinding(event.FindingTypePersistence, ""), &c); !slices.Equal(got, []string{"persistence"}) {
		t.Errorf("利用者の永続化 = %v", got)
	}
	if got := eval(clientFinding(event.FindingTypeNewDevice, "claude"), &c); len(got) != 0 {
		t.Errorf("要注意でない操作 = %v", got)
	}
	for _, r := range e.Rules {
		if r.Finding == "" && r.Mode != ModeMonitor {
			t.Errorf("既定の条件のルール %s は試験運用から始める", r.ID)
		}
	}
}
