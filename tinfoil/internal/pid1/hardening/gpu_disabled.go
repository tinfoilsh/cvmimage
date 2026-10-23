//go:build !tinfoil_gpu

package hardening

func attestationDevicePaths() []string { return []string{"null", "tdx_guest", "sev-guest"} }
