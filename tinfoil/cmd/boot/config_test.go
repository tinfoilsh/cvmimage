package main

import "testing"

func TestValidateGPUCount(t *testing.T) {
	for _, count := range []int{0, 1, 2, 4, 6, 8} {
		if err := validateGPUCount(count); err != nil {
			t.Fatalf("expected GPU count %d to be valid: %v", count, err)
		}
	}

	for _, count := range []int{-1, 3, 5, 7, 9} {
		if err := validateGPUCount(count); err == nil {
			t.Fatalf("expected GPU count %d to be invalid", count)
		}
	}
}
