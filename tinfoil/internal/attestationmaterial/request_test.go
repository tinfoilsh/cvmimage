package attestationmaterial

import (
	"encoding/json"
	"testing"
)

func TestRequestRequiresDocument(t *testing.T) {
	for _, request := range []Request{
		{Version: RequestVersionDocument, Repo: "repo"},
		{Version: RequestVersionDocument, Repo: "repo", Document: json.RawMessage(` null `)},
		{Version: RequestVersionDocument, Document: json.RawMessage(`{}`)},
		{Repo: "repo", Document: json.RawMessage(`{}`)},
		{Version: RequestVersionDocument + 1, Repo: "repo", Document: json.RawMessage(`{}`)},
	} {
		if err := request.Validate(); err == nil {
			t.Fatalf("accepted incomplete request: %#v", request)
		}
	}
}
