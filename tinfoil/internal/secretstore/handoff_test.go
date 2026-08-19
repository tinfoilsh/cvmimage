package secretstore

import (
	"os"
	"slices"
	"testing"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/runtimeconfig"
)

func TestReferencesAndWorkloadStore(t *testing.T) {
	config := &runtimeconfig.Config{
		Models: []runtimeconfig.ModelSpec{{KeySecret: "MODEL_KEY"}},
		Containers: []runtimeconfig.Container{
			{Secrets: []string{"API_KEY", "SHARED"}},
			{Secrets: []string{"SHARED"}},
		},
	}
	external := &shimconfig.ExternalConfig{Secrets: map[string]string{
		"API_KEY": "api", "SHARED": "shared",
	}}
	if got := AllReferences(config); !slices.Equal(got, []string{"API_KEY", "MODEL_KEY", "SHARED"}) {
		t.Fatalf("AllReferences() = %v", got)
	}
	if got := MissingReferences(config, external); !slices.Equal(got, []string{"MODEL_KEY"}) {
		t.Fatalf("MissingReferences() = %v", got)
	}
	store, err := WorkloadStore(config, external)
	if err != nil {
		t.Fatal(err)
	}
	if store["API_KEY"] != "api" || store["SHARED"] != "shared" || len(store) != 2 {
		t.Fatalf("WorkloadStore() = %#v", store)
	}
}

func TestHandoffRoundTrip(t *testing.T) {
	file, err := NewHandoffFile()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	digest := ConfigDigest([]byte("config"))
	if err := WriteHandoff(file, digest, Store{"API_KEY": "secret"}); err != nil {
		t.Fatal(err)
	}
	store, err := ReadHandoff(file, digest, []string{"API_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if store["API_KEY"] != "secret" {
		t.Fatalf("ReadHandoff() = %#v", store)
	}
	if _, err := ReadHandoff(file, digest, []string{"API_KEY"}); err != nil {
		t.Fatalf("second ReadHandoff() failed: %v", err)
	}
	if _, err := file.WriteAt([]byte("x"), 0); err == nil {
		t.Fatal("sealed handoff remained writable")
	}
}

func TestReadHandoffRejectsWrongContract(t *testing.T) {
	tests := []struct {
		name     string
		digest   string
		expected []string
	}{
		{name: "digest", digest: ConfigDigest([]byte("other")), expected: []string{"API_KEY"}},
		{name: "missing name", digest: ConfigDigest([]byte("config")), expected: []string{"API_KEY", "OTHER"}},
		{name: "extra name", digest: ConfigDigest([]byte("config")), expected: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, err := NewHandoffFile()
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if err := WriteHandoff(file, ConfigDigest([]byte("config")), Store{"API_KEY": "secret"}); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadHandoff(file, test.digest, test.expected); err == nil {
				t.Fatal("invalid handoff accepted")
			}
		})
	}
}

func TestReadHandoffRejectsUnsealedFile(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "handoff")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := ReadHandoff(file, "digest", nil); err == nil {
		t.Fatal("unsealed handoff accepted")
	}
}
