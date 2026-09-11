package variant

import (
	"fmt"
	"reflect"
	"testing"
)

func TestInferenceShimRetainsNVIDIADeviceAccess(t *testing.T) {
	want := []string{
		"null", "tdx_guest", "sev-guest", "nvidiactl", "nvidia-uvm",
		"nvidia-uvm-tools", "nvidia-caps", "nvidia-nvswitchctl", "nvidia-nvlink",
	}
	for index := 0; index < 16; index++ {
		want = append(want, fmt.Sprintf("nvidia%d", index), fmt.Sprintf("nvidia-nvswitch%d", index))
	}
	policy := ShimPolicy()
	if !reflect.DeepEqual(policy.AttestationDevices, want) {
		t.Fatalf("shim devices = %v, want %v", policy.AttestationDevices, want)
	}
	policy.AttestationDevices[0] = "changed"
	if ShimPolicy().AttestationDevices[0] != "null" {
		t.Fatal("policy declarations share mutable device lists")
	}
}
