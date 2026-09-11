package main

import "testing"

func TestValidateGPUCount(t *testing.T) {
	for count := range maxGPUCount + 1 {
		if err := validateGPUCount(count); err != nil {
			t.Fatalf("expected GPU count %d to be valid: %v", count, err)
		}
	}

	for _, count := range []int{-1, 9} {
		if err := validateGPUCount(count); err == nil {
			t.Fatalf("expected GPU count %d to be invalid", count)
		}
	}
}
