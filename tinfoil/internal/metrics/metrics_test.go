package metrics

import (
	"testing"

	"tinfoil/internal/config"
)

func TestDeviceMetricsAreOptIn(t *testing.T) {
	plain, err := collectMetrics(&config.Metadata{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plain.GPUType != "" || plain.GPUMemTotal != 0 || plain.GPUUtil != 0 {
		t.Fatalf("device metrics without a provider: %#v", plain)
	}
	calls := 0
	withDevice, err := collectMetrics(&config.Metadata{}, func(m *Metrics) error {
		calls++
		m.GPUType = "test device"
		m.GPUMemTotal = 80
		m.GPUUtil = 17
		return nil
	})
	if err != nil || calls != 1 || withDevice.GPUType != "test device" || withDevice.GPUMemTotal != 80 || withDevice.GPUUtil != 17 {
		t.Fatalf("device metrics = %#v, calls = %d, error = %v", withDevice, calls, err)
	}
}
