package config

import "testing"

func TestGetSecret(t *testing.T) {
	tests := []struct {
		name    string
		config  *ExternalConfig
		key     string
		want    string
	}{
		{"nil receiver", nil, "KEY", ""},
		{"nil secrets map", &ExternalConfig{}, "KEY", ""},
		{"missing key", &ExternalConfig{Secrets: map[string]string{"A": "1"}}, "B", ""},
		{"found key", &ExternalConfig{Secrets: map[string]string{"A": "1"}}, "A", "1"},
		{"null value filtered", &ExternalConfig{Secrets: map[string]string{"A": "null"}}, "A", ""},
		{"empty value returned", &ExternalConfig{Secrets: map[string]string{"A": ""}}, "A", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetSecret(tt.key)
			if got != tt.want {
				t.Errorf("GetSecret(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}
