//go:build !tinfoil_gpu

package main

import (
	"testing"
	"time"
	"tinfoil/internal/boot"
)

func TestCPUImageRejectsGPUConfig(t *testing.T) {
	for _, count := range []int{-1, 0, 1, 8} {
		var stages []boot.Stage
		err := attestGPU(&Config{GPUs: count}, func(name, status string, duration time.Duration, detail string) {
			stages = append(stages, boot.Stage{Name: name, Status: status, Duration: duration, Detail: detail})
		})
		wantStatus := boot.StatusSkipped
		if count != 0 {
			if err == nil {
				t.Fatalf("accepted %d GPUs", count)
			}
			wantStatus = boot.StatusFailed
		} else if err != nil {
			t.Fatal(err)
		}
		if len(stages) != 1 || stages[0].Name != boot.StageGPUAttestation || stages[0].Status != wantStatus {
			t.Fatalf("%d GPUs: stages = %+v, want %s", count, stages, wantStatus)
		}
		if err != nil && stages[0].Detail != err.Error() {
			t.Fatalf("%d GPUs: failure detail = %q, want %q", count, stages[0].Detail, err)
		}
	}
}
