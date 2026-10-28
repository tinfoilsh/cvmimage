package main

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
	"tinfoil/internal/attestationmaterial"
)

func TestLoadCollateralRequest(t *testing.T) {
	for _, want := range []attestationmaterial.Request{
		{Version: attestationmaterial.RequestVersionDocument, Profile: wire.FormatV3, Document: json.RawMessage(`{}`), Repo: "org/project", Tag: "v1", Digest: strings.Repeat("a", 64)},
		{Version: attestationmaterial.RequestVersionDocument, Profile: wire.FormatV3, Document: json.RawMessage(`{}`), Runtime: "v0.15.0@sha256:" + strings.Repeat("b", 64), Digest: strings.Repeat("a", 64)},
	} {
		data, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		path := t.TempDir() + "/collateral-request.json"
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := loadCollateralRequest(path)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("request = %#v, error = %v", got, err)
		}
		if err := os.WriteFile(path, []byte(`{"version":1,"platform":"tdx","quote_base64":"quote"}`), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadCollateralRequest(path); err == nil {
			t.Fatal("raw collateral request accepted")
		}
	}
}
