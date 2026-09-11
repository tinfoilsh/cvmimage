package boot

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	runtimeconfig "github.com/tinfoilsh/tinfoil-config"

	"tinfoil/internal/attestation"
	"tinfoil/internal/secretstore"
)

func TestInputVerificationPrecedesWorkloadDeclaration(t *testing.T) {
	config := []byte("cvm-version: 0.11.0\nshim:\n  upstream-port: 8080\n")
	configPath := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(configPath, append(config, 0, 0), 0600); err != nil {
		t.Fatal(err)
	}
	options := Options{ConfigHash: secretstore.ConfigDigest(config)}
	calls := 0
	spec := Spec{Configure: func(value *runtimeconfig.Config) (Workload, error) {
		calls++
		if value.ShimCfg.UpstreamPort != 8080 {
			t.Fatal("declaration did not receive decoded config")
		}
		return Workload{DeviceEvidence: attestation.NoDeviceEvidence}, nil
	}}
	bad := options
	bad.ConfigHash = secretstore.ConfigDigest([]byte("different config"))
	if _, err := loadMeasuredInputs(configPath, bad, spec); err == nil || calls != 0 {
		t.Fatal("unverified config reached the variant")
	}
	loaded, err := loadMeasuredInputs(configPath, options, spec)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || string(loaded.configSource) != string(config) {
		t.Fatal("input loading lost original bytes or configured workload more than once")
	}

	wantErr := errors.New("variant rejected config")
	spec.Configure = func(*runtimeconfig.Config) (Workload, error) { return Workload{}, wantErr }
	if _, err := loadMeasuredInputs(configPath, options, spec); !errors.Is(err, wantErr) {
		t.Fatalf("variant error = %v", err)
	}
	spec.Configure = func(*runtimeconfig.Config) (Workload, error) { return Workload{}, nil }
	if _, err := loadMeasuredInputs(configPath, options, spec); err == nil {
		t.Fatal("missing evidence provider accepted")
	}
}
