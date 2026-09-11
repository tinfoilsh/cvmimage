package boot

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"

	"tinfoil/internal/attestation"
	shimconfig "tinfoil/internal/config"
)

func TestCollateralRequestPublicationPreservesCPUQuote(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collateral-request.json")
	cpu := &attestation.CPU{RawReport: []byte("raw quote"), Platform: "sev-snp"}
	external := &shimconfig.ExternalConfig{Metadata: shimconfig.Metadata{Repo: "tinfoilsh/workload", Tag: "v1.2.3"}}
	request, err := writeCollateralRequest(path, cpu, external)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted wire.Request
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted != request || request.Repo != external.Metadata.Repo || request.Tag != external.Metadata.Tag || request.Platform != cpu.Platform || request.QuoteBase64 != base64.StdEncoding.EncodeToString(cpu.RawReport) {
		t.Fatal("CPU collateral request changed during publication")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("collateral request is not private")
	}
}
