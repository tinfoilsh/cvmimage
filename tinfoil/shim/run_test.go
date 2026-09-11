package shim

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestArtifactWaitStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	called := make(chan struct{}, 1)
	result := make(chan error, 1)
	go func() {
		_, err := waitForArtifact(ctx, "test artifact", func() (string, error) {
			select {
			case called <- struct{}{}:
			default:
			}
			return "", errors.New("not ready")
		})
		result <- err
	}()
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("loader did not run")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("artifact wait ignored cancellation")
	}
}

func TestCanceledUpgradeDoesNotProbeArtifacts(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := waitUntil(ctx, func() bool { t.Fatal("probed after cancellation"); return true }); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	_, err := waitForArtifact(ctx, "unused", func() (string, error) { t.Fatal("loaded after cancellation"); return "", nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}
