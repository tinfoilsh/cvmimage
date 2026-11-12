package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWaitForClockRequiresSuccessfulSynchronization(t *testing.T) {
	for _, test := range []struct {
		name      string
		script    string
		canceled  bool
		wantError bool
	}{
		{name: "synchronized", script: "#!/bin/sh\nexit 0\n"},
		{name: "not synchronized", script: "#!/bin/sh\nexit 1\n", wantError: true},
		{name: "canceled startup", script: "#!/bin/sh\nexit 0\n", canceled: true, wantError: true},
		{name: "missing client", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := filepath.Join(t.TempDir(), "chronyc")
			if test.script != "" {
				if err := os.WriteFile(client, []byte(test.script), 0700); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.canceled {
				cancel()
			}
			err := waitForClock(ctx, client)
			if (err != nil) != test.wantError {
				t.Fatalf("waitForClock error = %v", err)
			}
			if test.canceled && !errors.Is(err, context.Canceled) {
				t.Fatalf("startup cancellation lost: %v", err)
			}
		})
	}
}
