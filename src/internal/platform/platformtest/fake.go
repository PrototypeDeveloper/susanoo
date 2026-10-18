// Package platformtest は試験用の Platform の実装を提供する。
// OS には一切触れず、受けた指示を記録し、試験から渡されたイベントを流す。
package platformtest

import (
	"context"
	"sync"

	"susanoo/internal/event"
	"susanoo/internal/platform"
)

// Fake は試験用の Platform。
type Fake struct {
	Caps   platform.Capabilities
	events chan event.Event

	mu       sync.Mutex
	isolated *platform.Isolation
	history  []string
}

var _ platform.Platform = (*Fake)(nil)

// New は caps の機能を申告する Fake を作る。
func New(caps platform.Capabilities) *Fake {
	return &Fake{Caps: caps, events: make(chan event.Event)}
}

func (f *Fake) Capabilities() platform.Capabilities { return f.Caps }

// Emit は Watch している側にイベントを渡す。受け取られるか ctx が終わるまで待つ。
func (f *Fake) Emit(ctx context.Context, e event.Event) error {
	select {
	case f.events <- e:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *Fake) Watch(ctx context.Context, out chan<- event.Event) error {
	for {
		select {
		case e := <-f.events:
			select {
			case out <- e:
			case <-ctx.Done():
				return ctx.Err()
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (f *Fake) Isolate(_ context.Context, iso platform.Isolation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.isolated = &iso
	f.history = append(f.history, "isolate:"+string(iso.Level))
	return nil
}

func (f *Fake) Release(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.isolated = nil
	f.history = append(f.history, "release")
	return nil
}

func (f *Fake) IsolationActive(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.isolated != nil, nil
}

// Tamper は、攻撃者が自己隔離のルールを消した状態を再現する。
func (f *Fake) Tamper() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.isolated = nil
	f.history = append(f.history, "tamper")
}

// Isolated は今の隔離の指示を返す。隔離していなければ nil。
func (f *Fake) Isolated() *platform.Isolation {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.isolated == nil {
		return nil
	}
	iso := *f.isolated
	return &iso
}

// Snapshot は証拠として、決まった中身（試験用のプロセスと接続）を返す（platform.Collector）。集めた回数を数える。
func (f *Fake) Snapshot(ctx context.Context) (*platform.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.history = append(f.history, "snapshot")
	return &platform.Snapshot{
		Processes:   []platform.SnapshotProcess{{PID: 1, Name: "init"}, {PID: 4242, PPID: 1, UID: "1000", Name: "suspicious", Exe: "/tmp/.x/run"}},
		Connections: []platform.SnapshotConn{{Proto: "tcp", State: "established", Local: "192.0.2.10:40000", Remote: "203.0.113.9:443", PID: 4242, Process: "suspicious"}},
	}, ctx.Err()
}

var _ platform.Collector = (*Fake)(nil)

// History は受けた指示の履歴を返す。
func (f *Fake) History() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.history...)
}
