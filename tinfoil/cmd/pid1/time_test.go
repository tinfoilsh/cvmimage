package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"tinfoil/internal/pid1/supervisor"
)

func TestQueryTimeCapturesSupervisedOutput(t *testing.T) {
	const report = "00000000,,0,0,0,0,0,0,0,0,1,1,0,Not synchronised\n"
	data, err := queryTime(context.Background(), func(ctx context.Context, command supervisor.Command) error {
		_, err := command.Stdout.WriteString(report)
		return err
	})
	if err != nil || string(data) != report {
		t.Fatalf("queryTime = %q, %v", data, err)
	}
}

func TestQueryTimeRejectsFailedOrOversizedOutput(t *testing.T) {
	queryErr := errors.New("query exited unsuccessfully")
	for _, test := range []struct {
		name string
		size int
		err  error
	}{
		{"oversized", trackingOutputLimit + 1, nil},
		{"failed with output", 1, queryErr},
		{"canceled", 0, context.Canceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, err := queryTime(context.Background(), func(ctx context.Context, command supervisor.Command) error {
				if _, err := command.Stdout.Write(bytes.Repeat([]byte("x"), test.size)); err != nil {
					t.Fatal(err)
				}
				return test.err
			})
			if err == nil || data != nil || (test.err != nil && !errors.Is(err, test.err)) {
				t.Fatalf("queryTime = %q, %v", data, err)
			}
		})
	}
}
