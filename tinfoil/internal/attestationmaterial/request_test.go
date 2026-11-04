package attestationmaterial

import (
	"encoding/json"
	"strings"
	"testing"

	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
)

func TestRequestRejectsIncompleteAndMixedSources(t *testing.T) {
	valid := Request{Version: RequestVersionDocument, Profile: wire.FormatV3, Document: json.RawMessage(`{}`), Config: []byte("config")}
	for _, mutate := range []func(*Request){
		func(r *Request) { r.Version = 0 },
		func(r *Request) { r.Document = nil },
		func(r *Request) { r.Document = json.RawMessage(` null `) },
		func(r *Request) { r.Profile = "" },
		func(r *Request) { r.Repo = "org/project" },
		func(r *Request) { r.Tag = "v1" },
		func(r *Request) { r.Digest = "digest" },
		func(r *Request) { r.Runtime = "v0.15.3-rc.1" },
		func(r *Request) { r.Config = nil },
	} {
		request := valid
		mutate(&request)
		if err := request.Validate(); err == nil {
			t.Fatalf("accepted invalid request: %#v", request)
		}
	}
}

func TestRequestRejectsInvalidLocalRuntimeReferences(t *testing.T) {
	digest := strings.Repeat("a", 64)
	valid := Request{Version: RequestVersionDocument, Profile: wire.FormatV3, Document: json.RawMessage(`{}`), Digest: digest, Runtime: "v0.15.3-rc.1@sha256:" + digest}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Request){
		func(r *Request) { r.Repo = "org/project" },
		func(r *Request) { r.Tag = "revision" },
		func(r *Request) { r.Config = []byte("config") },
		func(r *Request) { r.Digest = "" },
		func(r *Request) { r.Digest = strings.ToUpper(digest) },
		func(r *Request) { r.Runtime = "v0.15.3-rc.1" },
		func(r *Request) { r.Runtime = "invalid@sha256:" + digest },
	} {
		request := valid
		mutate(&request)
		if err := request.Validate(); err == nil {
			t.Fatalf("accepted invalid request: %#v", request)
		}
	}
}
