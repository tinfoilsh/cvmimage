package secretstore

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestResolveRequiresExactKeyserverResponse(t *testing.T) {
	for _, response := range []map[string]string{
		{}, {"API_KEY": ""}, {"API_KEY": "null"}, {"OTHER": "value"},
		{"API_KEY": "value", "OTHER": "value"},
	} {
		source := Source{Keyserver: func(context.Context, []string) (map[string]string, error) { return response, nil }}
		if _, _, err := source.Resolve(context.Background(), []string{"API_KEY"}); err == nil {
			t.Fatal("invalid keyserver response accepted")
		}
	}
}

func TestResolveKeepsSourcesSeparate(t *testing.T) {
	for _, test := range []struct {
		name          string
		remote, debug bool
		wantError     string
	}{
		{name: "host"},
		{name: "production keyserver", remote: true, wantError: "must come from the keyserver"},
		{name: "debug keyserver", remote: true, debug: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			host := Store{"API_KEY": "host", "UNREQUESTED": "other"}
			source := Source{Host: host, Debug: test.debug}
			if test.remote {
				source.Keyserver = func(context.Context, []string) (map[string]string, error) {
					t.Fatal("unexpected fetch")
					return nil, nil
				}
			}
			values, detail, err := source.Resolve(context.Background(), []string{"API_KEY"})
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil || values["API_KEY"] != "host" || len(values) != 1 {
				t.Fatalf("resolution failed: %v", err)
			}
			if test.debug && !strings.Contains(detail, "debug enclave") {
				t.Fatalf("detail = %q", detail)
			}
			values["API_KEY"] = "changed"
			if host["API_KEY"] != "host" {
				t.Fatal("resolved store aliases host inputs")
			}
		})
	}
}

func TestResolveNormalizesReferencesAndPropagatesFetchFailure(t *testing.T) {
	wantErr := errors.New("fetch failed")
	names := []string{"MODEL_KEY", "API_KEY", "MODEL_KEY"}
	source := Source{Keyserver: func(_ context.Context, got []string) (map[string]string, error) {
		if !slices.Equal(got, []string{"API_KEY", "MODEL_KEY"}) {
			t.Fatalf("requested = %v", got)
		}
		return nil, wantErr
	}}
	if _, _, err := source.Resolve(context.Background(), names); !errors.Is(err, wantErr) {
		t.Fatalf("error = %v", err)
	}
	if !slices.Equal(names, []string{"MODEL_KEY", "API_KEY", "MODEL_KEY"}) {
		t.Fatal("input references changed")
	}
}

func TestResolveRejectsMissingHostSecrets(t *testing.T) {
	if _, _, err := (Source{Host: Store{"API_KEY": "null"}}).Resolve(context.Background(), []string{"API_KEY"}); err == nil {
		t.Fatal("missing host secret accepted")
	}
}
