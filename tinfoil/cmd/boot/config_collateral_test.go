package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"

	"tinfoil/internal/attestationmaterial"
)

func TestConfigCollateralRequestPersistsAndReachesATC(t *testing.T) {
	ref := &collateral.ConfigReference{Name: "/org/project/v1", Digest: strings.Repeat("a", 64)}
	runtime := &collateral.RuntimeReference{Repo: "tinfoilsh/cvmimage", Tag: "v0.15.0", Digest: strings.Repeat("b", 64)}
	external, err := decodeExternalConfig([]byte(fmt.Sprintf(`
metadata:
  config:
    name: %s
    digest: %s
  runtime:
    repo: %s
    tag: %s
    digest: %s
network:
  address: 100.64.0.42/20
  gateway: 100.64.0.1
`, ref.Name, ref.Digest, runtime.Repo, runtime.Tag, runtime.Digest)))
	if err != nil {
		t.Fatal(err)
	}
	expected := wire.Request{Profile: wire.ProfileIGVMV1, Config: ref, Runtime: runtime, Platform: "sev-snp", QuoteBase64: "cXVvdGU="}
	collateral := []collateral.Entry{{ID: collateral.ConfigID, Role: collateral.RoleReferenceValues,
		Format: collateral.ConfigEndorsementV1Format, Data: []byte(`{"endorsement_ref":"test-reference"}`)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request wire.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Path != "/attestation-collaterals" || !reflect.DeepEqual(request, expected) {
			t.Errorf("unexpected ATC request: %s %#v", r.URL.Path, request)
		}
		_ = json.NewEncoder(w).Encode(wire.Response{Format: wire.FormatV2, ExpiresAt: time.Now().Add(time.Hour), Collateral: collateral})
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "collateral-request.json")
	request, err := writeCollateralRequest(path, &CPUAttestation{RawReport: []byte("quote"), Platform: "sev-snp"},
		external)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted wire.Request
	if err := json.Unmarshal(data, &persisted); err != nil || !reflect.DeepEqual(persisted, request) {
		t.Fatalf("persisted request = %#v, error = %v", persisted, err)
	}
	client, err := attestationmaterial.NewClient(server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Fetch(context.Background(), persisted)
	if err != nil || !reflect.DeepEqual(got.Collateral, collateral) {
		t.Fatalf("collateral = %#v, error = %v", got.Collateral, err)
	}
}
