package runtimeconfig

import "testing"

func TestValidateModelCount(t *testing.T) {
	for _, count := range []int{0, 1, 24} {
		if err := validateModelCount(count); err != nil {
			t.Fatalf("model count %d rejected: %v", count, err)
		}
	}
	for _, count := range []int{-1, 25} {
		if err := validateModelCount(count); err == nil {
			t.Fatalf("model count %d accepted", count)
		}
	}
}
