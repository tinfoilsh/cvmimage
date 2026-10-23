//go:build !tinfoil_gpu

package attestation

import (
	"fmt"
	envelope "github.com/tinfoilsh/tinfoil-go/verify/document"
)

func CollectDeviceEvidence(_ [32]byte, expectedGPUs int) ([]envelope.DeviceEvidenceItem, error) {
	if expectedGPUs != 0 {
		return nil, fmt.Errorf("CPU runtime does not support GPUs")
	}
	return nil, nil
}
