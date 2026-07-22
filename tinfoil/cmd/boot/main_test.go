package main

import (
	"context"
	"os"
	"reflect"
	"syscall"
	"testing"
)

func TestCommandContextLeavesModelsSignalsAtDefaults(t *testing.T) {
	notifyCalled := false
	ctx, stop := commandContext("models", func(context.Context, ...os.Signal) (context.Context, context.CancelFunc) {
		notifyCalled = true
		return context.WithCancel(context.Background())
	})
	defer stop()
	if notifyCalled {
		t.Fatal("models command captured process signals")
	}
	if ctx.Done() != nil {
		t.Fatal("models command received a cancellable context")
	}
}

func TestCommandContextCapturesSignalsForCancellableBootPaths(t *testing.T) {
	for _, command := range []string{"", "containers"} {
		t.Run(command, func(t *testing.T) {
			var gotSignals []os.Signal
			ctx, stop := commandContext(command, func(parent context.Context, signals ...os.Signal) (context.Context, context.CancelFunc) {
				gotSignals = append(gotSignals, signals...)
				return context.WithCancel(parent)
			})
			if !reflect.DeepEqual(gotSignals, []os.Signal{syscall.SIGTERM, syscall.SIGINT}) {
				t.Fatalf("captured signals = %v", gotSignals)
			}
			stop()
			select {
			case <-ctx.Done():
			default:
				t.Fatal("signal stop did not cancel command context")
			}
		})
	}
}
