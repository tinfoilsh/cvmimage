package boot

import (
	"context"
	"os"
	"strings"
	"testing"

	runtimeconfig "github.com/tinfoilsh/tinfoil-config"

	"tinfoil/internal/modelpack"
	"tinfoil/internal/secretstore"
	"tinfoil/internal/volume"
)

func newHandoff(t *testing.T) *os.File {
	t.Helper()
	handoff, err := secretstore.NewHandoffFile()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { handoff.Close() })
	return handoff
}

func TestPrepareSecretHandoff(t *testing.T) {
	workload := Workload{Secrets: []string{"API_KEY"}}
	host := secretstore.Store{"API_KEY": "secret"}
	handoff := newHandoff(t)

	_, detail, err := prepareSecretHandoff(context.Background(), workload, secretstore.Source{Host: host}, handoff, "config-digest")
	if err != nil {
		t.Fatal(err)
	}
	if detail != "handed off 1 workload secret(s); keyserver not configured" {
		t.Fatalf("detail = %q", detail)
	}
	store, err := secretstore.ReadHandoff(handoff, "config-digest", []string{"API_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if store["API_KEY"] != "secret" {
		t.Fatalf("secret handoff = %#v", store)
	}
}

func TestPrepareSecretHandoffReportsHandoffFailure(t *testing.T) {
	_, _, err := prepareSecretHandoff(context.Background(), Workload{}, secretstore.Source{}, nil, "config-digest")
	if err == nil || !strings.Contains(err.Error(), "creating sealed secret handoff") {
		t.Fatalf("error = %v", err)
	}
}

func TestPrepareSecretHandoffKeyserverFetchesEveryDeclaredSecret(t *testing.T) {
	workload := Workload{Secrets: []string{"API_KEY"}, Volumes: volume.Plan{Volumes: []volume.Definition{{Name: "model", Pack: &modelpack.Source{Encrypted: true}, Unlock: runtimeconfig.VolumeUnlock{Secret: "MODEL_KEY"}}}}}
	host := secretstore.Store{}
	handoff := newHandoff(t)

	var requested []string
	fetch := func(_ context.Context, names []string) (map[string]string, error) {
		requested = append(requested, names...)
		return map[string]string{"API_KEY": "secret", "MODEL_KEY": "key"}, nil
	}
	values, detail, err := prepareSecretHandoff(context.Background(), workload, secretstore.Source{Host: host, Keyserver: fetch}, handoff, "config-digest")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(requested, ",") != "API_KEY,MODEL_KEY" {
		t.Fatalf("requested = %v, want every declared secret", requested)
	}
	if detail != "handed off 1 workload secret(s); fetched 2 from keyserver" {
		t.Fatalf("detail = %q", detail)
	}
	if values.storageKeys.GetSecret("MODEL_KEY") != "key" || len(values.storageKeys) != 1 || len(values.workload) != 1 || values.workload.GetSecret("API_KEY") != "secret" || len(host) != 0 {
		t.Fatal("model key must be returned without mutating host inputs")
	}
	store, err := secretstore.ReadHandoff(handoff, "config-digest", []string{"API_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if store["API_KEY"] != "secret" {
		t.Fatalf("secret handoff = %#v", store)
	}
}

func TestStorageKeysHaveSeparateHandoff(t *testing.T) {
	workload := Workload{Secrets: []string{"API_KEY"}, Volumes: volume.Plan{Volumes: []volume.Definition{
		{Name: "model", Pack: &modelpack.Source{Encrypted: true}, Unlock: runtimeconfig.VolumeUnlock{Secret: "PACK_KEY"}},
		{Name: "state", Disk: &volume.DiskSource{}, Unlock: runtimeconfig.VolumeUnlock{Secret: "DISK_KEY"}},
	}}}
	handoff := newHandoff(t)
	values, _, err := prepareSecretHandoff(t.Context(), workload, secretstore.Source{Host: secretstore.Store{"API_KEY": "api", "PACK_KEY": "pack", "DISK_KEY": "disk"}}, handoff, "digest")
	if err != nil {
		t.Fatal(err)
	}
	store, err := secretstore.ReadHandoff(handoff, "digest", []string{"API_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if len(store) != 1 || store["API_KEY"] != "api" || len(values.storageKeys) != 2 || values.storageKeys["DISK_KEY"] != "disk" || values.storageKeys["PACK_KEY"] != "pack" {
		t.Fatal("secret handoffs crossed")
	}
	storageHandoff := newHandoff(t)
	if err := secretstore.WriteHandoff(storageHandoff, "digest", values.storageKeys); err != nil {
		t.Fatal(err)
	}
	storage, err := secretstore.ReadHandoff(storageHandoff, "digest", []string{"DISK_KEY", "PACK_KEY"})
	if err != nil || len(storage) != 2 || storage["PACK_KEY"] != "pack" || storage["DISK_KEY"] != "disk" {
		t.Fatalf("storage handoff: %v", err)
	}
	if _, err := secretstore.ReadHandoff(storageHandoff, "other-digest", []string{"DISK_KEY", "PACK_KEY"}); err == nil {
		t.Fatal("storage handoff accepted another config")
	}
}
