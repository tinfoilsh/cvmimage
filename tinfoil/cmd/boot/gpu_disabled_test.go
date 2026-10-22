//go:build !tinfoil_gpu

package main

import (
	"testing"
	"tinfoil/internal/boot"
)

func TestCPUImageRejectsGPUConfig(t *testing.T) {
	for _, count := range []int{-1, 1, 8} {
		if err := attestGPU(&Config{GPUs: count}, boot.NewTracker(nil)); err == nil {
			t.Fatalf("accepted %d GPUs", count)
		}
	}
	if err := attestGPU(&Config{}, boot.NewTracker(nil)); err != nil {
		t.Fatal(err)
	}
}
