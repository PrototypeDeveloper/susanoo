package platformtest

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"susanoo/internal/event"
	"susanoo/internal/platform"
	"susanoo/internal/policy"
)

func TestFake(t *testing.T) {
	f := New(platform.Capabilities{OS: "linux", Features: []platform.Capability{platform.CapHoneytoken, platform.CapIsolation}})
	if !f.Capabilities().Has(platform.CapHoneytoken) || f.Capabilities().Has(platform.CapProcessEvents) {
		t.Errorf("申告した機能が違う: %+v", f.Capabilities())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out := make(chan event.Event)
	done := make(chan error, 1)
	go func() { done <- f.Watch(ctx, out) }()

	e := event.New(event.ClassDetectionFinding, event.FindingCreate, event.SeverityHigh, time.Now())
	go f.Emit(ctx, *e)
	select {
	case got := <-out:
		if got.Metadata.UID != e.Metadata.UID {
			t.Errorf("別のイベントを受け取った")
		}
	case <-ctx.Done():
		t.Fatal("イベントが届かない")
	}

	if err := f.Isolate(ctx, platform.Isolation{Level: policy.IsolateManagement}); err != nil {
		t.Fatal(err)
	}
	if iso := f.Isolated(); iso == nil || iso.Level != policy.IsolateManagement {
		t.Errorf("隔離の状態 = %+v", iso)
	}
	if err := f.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if f.Isolated() != nil {
		t.Error("解除後も隔離されている")
	}
	if got, want := f.History(), []string{"isolate:management", "release"}; !slices.Equal(got, want) {
		t.Errorf("履歴 = %v, 期待値 %v", got, want)
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Watch の戻り値 = %v", err)
	}
}
