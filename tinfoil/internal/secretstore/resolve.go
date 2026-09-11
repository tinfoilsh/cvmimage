package secretstore

import (
	"context"
	"fmt"
	"slices"
)

// Source resolves declared names from the host or an attested keyserver.
// Debug guests use host values because keyservers reject their attestation.
type Source struct {
	Host      Store
	Keyserver func(context.Context, []string) (map[string]string, error)
	Debug     bool
}

func (s Source) Resolve(ctx context.Context, names []string) (Store, string, error) {
	names = slices.Clone(names)
	slices.Sort(names)
	names = slices.Compact(names)
	values := s.Host
	detail := "keyserver not configured"
	switch {
	case s.Keyserver == nil:
	case s.Debug:
		detail = "debug enclave: keyserver-url ignored, secrets supplied by host"
	default:
		for _, name := range names {
			if s.Host.GetSecret(name) != "" {
				return nil, "", fmt.Errorf("host supplied secret %q, but keyserver-url is set and declared secrets must come from the keyserver", name)
			}
		}
		values = Store{}
		if len(names) != 0 {
			fetched, err := s.Keyserver(ctx, names)
			if err != nil {
				return nil, "", fmt.Errorf("keyserver secret fetch failed: %w", err)
			}
			if err := validateResponse(names, fetched); err != nil {
				return nil, "", fmt.Errorf("keyserver secret fetch failed: %w", err)
			}
			values = Store(fetched)
		}
		detail = fmt.Sprintf("fetched %d from keyserver", len(names))
	}
	if missing := MissingReferences(names, values); len(missing) != 0 {
		return nil, "", fmt.Errorf("%d declared secret(s) remain unresolved", len(missing))
	}
	selected, err := Select(names, values)
	return selected, detail, err
}

func validateResponse(names []string, secrets map[string]string) error {
	if len(secrets) != len(names) {
		return fmt.Errorf("keyserver returned %d secret(s), expected %d", len(secrets), len(names))
	}
	for _, name := range names {
		if Store(secrets).GetSecret(name) == "" {
			return fmt.Errorf("keyserver did not return declared secret %q", name)
		}
	}
	return nil
}
