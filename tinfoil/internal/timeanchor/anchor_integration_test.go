//go:build integration

package timeanchor

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

const liveAuthorityLimit = 10 * time.Second

// liveAuthorities are the public endpoints of the pinned authorities.
var liveAuthorities = map[string]string{
	"certum":   "http://time.certum.pl",
	"digicert": "http://timestamp.digicert.com",
	"sectigo":  "http://timestamp.sectigo.com",
	"sigstore": "https://timestamp.sigstore.dev/api/v1/timestamp",
}

// TestPinnedRootsAuthenticateLiveAuthorities asks each pinned authority for a
// fresh timestamp and requires its own pinned root to authenticate the reply.
func TestPinnedRootsAuthenticateLiveAuthorities(t *testing.T) {
	if os.Getenv("TINFOIL_TIME_ANCHOR_INTEGRATION") != "1" {
		t.Skip("set TINFOIL_TIME_ANCHOR_INTEGRATION=1 to run")
	}
	authorities, err := PinnedAuthorities()
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: liveAuthorityLimit}
	for _, authority := range authorities {
		endpoint, listed := liveAuthorities[authority.Name]
		if !listed {
			t.Fatalf("no live endpoint is listed for pinned authority %s", authority.Name)
		}
		asked, err := newQuery()
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Post(endpoint, queryType, bytes.NewReader(asked.encoded))
		if err != nil {
			t.Fatalf("%s: %v", authority.Name, err)
		}
		reply, err := io.ReadAll(io.LimitReader(response.Body, maxReplyBytes))
		response.Body.Close()
		if err != nil {
			t.Fatalf("%s: %v", authority.Name, err)
		}
		name, _, err := asked.verify(reply, authorities)
		if err != nil || name != authority.Name {
			t.Fatalf("%s reply verified as %q: %v", authority.Name, name, err)
		}
	}
}
