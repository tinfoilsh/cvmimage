package main

import (
	"context"
	"errors"
	"testing"
)

type fakeRunner struct {
	configured bool
	runCalls   int
	runErr     error
}

func (f *fakeRunner) Configured() bool {
	return f.configured
}

func (f *fakeRunner) Run(ctx context.Context) error {
	f.runCalls++
	if f.runErr != nil {
		return f.runErr
	}
	<-ctx.Done()
	return nil
}

func TestRunWithPropagatesRefreshFailure(t *testing.T) {
	wantErr := errors.New("refresh failed")
	runner := &fakeRunner{configured: true, runErr: wantErr}
	err := runWith(context.Background(), func() (egressRunner, error) { return runner, nil })
	if !errors.Is(err, wantErr) {
		t.Fatalf("runWith error = %v, want %v", err, wantErr)
	}
}

func TestRunWithStartsRefreshLoopWithoutInitialPopulation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &fakeRunner{configured: true}
	if err := runWith(ctx, func() (egressRunner, error) { return runner, nil }); err != nil {
		t.Fatal(err)
	}
	if runner.runCalls != 1 {
		t.Fatalf("Run calls = %d, want 1", runner.runCalls)
	}
}

func TestRunWithPropagatesLoadFailure(t *testing.T) {
	wantErr := errors.New("load failed")
	err := runWith(context.Background(), func() (egressRunner, error) {
		return nil, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("runWith error = %v, want %v", err, wantErr)
	}
}

func TestRunWithSkipsUnconfiguredEngine(t *testing.T) {
	runner := &fakeRunner{}
	if err := runWith(context.Background(), func() (egressRunner, error) { return runner, nil }); err != nil {
		t.Fatal(err)
	}
	if runner.runCalls != 0 {
		t.Fatalf("Run calls = %d, want 0", runner.runCalls)
	}
}
