package main

import "testing"

func TestPathMatchesPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		// Exact matches
		{"exact match", "/v1/models", "/v1/models", true},
		{"exact no match", "/v1/models", "/v1/users", false},
		{"exact match root", "/", "/", true},
		{"exact trailing slash matters", "/v1/models/", "/v1/models", false},

		// Wildcard suffix
		{"wildcard matches subpath", "/v1/user/*", "/v1/user/123", true},
		{"wildcard matches nested", "/v1/user/*", "/v1/user/123/settings", true},
		{"wildcard matches exact prefix", "/v1/user/*", "/v1/user/", true},
		{"wildcard no match different prefix", "/v1/user/*", "/v1/admin/123", false},
		{"wildcard no match partial prefix", "/v1/user/*", "/v1/username", false},

		// Edge cases
		{"wildcard only matches all", "/*", "/anything/here", true},
		{"wildcard at root", "/*", "/", true},
		{"empty pattern no match", "", "/v1/models", false},
		{"empty path no match", "/v1/models", "", false},
		{"both empty match", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pathMatchesPattern(tt.pattern, tt.path)
			if got != tt.want {
				t.Errorf("pathMatchesPattern(%q, %q) = %v, want %v",
					tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

func TestPathAllowed(t *testing.T) {
	tests := []struct {
		name         string
		allowedPaths []string
		path         string
		want         bool
	}{
		{"empty list allows nothing", []string{}, "/v1/models", false},
		{"single exact match", []string{"/v1/models"}, "/v1/models", true},
		{"single exact no match", []string{"/v1/models"}, "/v1/users", false},
		{"single wildcard match", []string{"/v1/user/*"}, "/v1/user/123", true},
		{"single wildcard no match", []string{"/v1/user/*"}, "/v1/admin/123", false},

		// Multiple patterns
		{
			"multiple patterns first matches",
			[]string{"/v1/models", "/v1/user/*"},
			"/v1/models",
			true,
		},
		{
			"multiple patterns second matches",
			[]string{"/v1/models", "/v1/user/*"},
			"/v1/user/456",
			true,
		},
		{
			"multiple patterns none match",
			[]string{"/v1/models", "/v1/user/*"},
			"/v1/admin",
			false,
		},

		// Real-world patterns
		{
			"openai-style routes",
			[]string{"/v1/chat/completions", "/v1/models", "/v1/embeddings"},
			"/v1/chat/completions",
			true,
		},
		{
			"mixed exact and wildcard",
			[]string{"/health", "/v1/user/*", "/v1/org/*/members"},
			"/v1/user/abc/profile",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pathAllowed(tt.allowedPaths, tt.path)
			if got != tt.want {
				t.Errorf("pathAllowed(%v, %q) = %v, want %v",
					tt.allowedPaths, tt.path, got, tt.want)
			}
		})
	}
}
