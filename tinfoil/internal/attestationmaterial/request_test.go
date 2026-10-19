package attestationmaterial

import (
	"encoding/json"
	"testing"
)

func TestRequestVersionsRejectAmbiguousEvidence(t *testing.T) {
	for _, request := range []Request{
		{Version: RequestVersionDocument},
		{Version: RequestVersionDocument, Document: json.RawMessage(`null`)},
		{Version: RequestVersionDocument, Document: json.RawMessage(`{}`), Platform: "tdx"},
		{Version: RequestVersionDocument, Document: json.RawMessage(`{}`), QuoteBase64: "quote"},
		{Version: RequestVersionLegacy, Document: json.RawMessage(`{}`), Platform: "tdx", QuoteBase64: "quote"},
		{Version: RequestVersionDocument + 1, Document: json.RawMessage(`{}`)},
	} {
		if err := request.Validate(); err == nil {
			t.Fatalf("accepted ambiguous request: %#v", request)
		}
	}
}
