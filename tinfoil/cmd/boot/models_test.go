package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tinfoilsh/modelwrap"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
)

// Reference syntax validation is covered by the modelwrap module tests;
// this only checks the cvmimage mount layout policy built on top of it.
func TestModelPackRefLayout(t *testing.T) {
	ref := strings.Repeat("a", 64) + "_4096_0eefa619-50b7-588f-a072-d405fb439d36"
	got, err := parseModelPackRef(ref)
	if err != nil {
		t.Fatalf("expected valid model pack ref: %v", err)
	}
	if got.RootHash != strings.Repeat("a", 64) || got.HashOffset != "4096" || got.UUID != "0eefa619-50b7-588f-a072-d405fb439d36" {
		t.Fatalf("parsed ref mismatch: %+v", got)
	}
	if got.mapperName() != "mwp-"+strings.Repeat("a", 64) {
		t.Fatalf("mapper name mismatch: %s", got.mapperName())
	}
	if got.mountPoint() != boot.MWPDir+"/mwp-"+strings.Repeat("a", 64) {
		t.Fatalf("mount point mismatch: %s", got.mountPoint())
	}
	if got.legacyMountPoint() != boot.MPKDir+"/mpk-"+strings.Repeat("a", 64) {
		t.Fatalf("legacy mount point mismatch: %s", got.legacyMountPoint())
	}
	if got.ArtifactID() != strings.Repeat("a", 64)+"_0eefa619-50b7-588f-a072-d405fb439d36" {
		t.Fatalf("artifact ID mismatch: %s", got.ArtifactID())
	}
	if _, err := parseModelPackRef("not-a-ref"); err == nil {
		t.Fatal("expected validation error to propagate from modelwrap")
	}
}

func TestModelMountTarget(t *testing.T) {
	ref := &modelPackRef{ArtifactRef: &modelwrap.ArtifactRef{RootHash: strings.Repeat("a", 64)}}
	model := ModelSpec{Name: "private-model"}

	isolatedConfig := &Config{Containers: []Container{{Models: []string{model.Name}}}}
	mountPoint, legacyAlias := modelMountTarget(isolatedConfig, model, ref)
	if mountPoint != boot.PrivateModelsDir+"/"+model.Name || legacyAlias {
		t.Fatalf("isolated target = (%q, %t)", mountPoint, legacyAlias)
	}

	mountPoint, legacyAlias = modelMountTarget(&Config{}, model, ref)
	if mountPoint != ref.mountPoint() || !legacyAlias {
		t.Fatalf("legacy target = (%q, %t)", mountPoint, legacyAlias)
	}
}

func TestVerityTableUsesFixedModelwrapContract(t *testing.T) {
	rootHash := strings.Repeat("a", 64)
	salt := bytes.Repeat([]byte{0x5a}, veritySaltSize)
	length, params, err := verityTable("8:17", rootHash, 8192, salt)
	if err != nil {
		t.Fatalf("verityTable: %v", err)
	}
	if length != 16 {
		t.Fatalf("length sectors = %d, want 16", length)
	}
	want := fmt.Sprintf("1 8:17 8:17 4096 4096 2 3 sha256 %s %s", rootHash, strings.Repeat("5a", veritySaltSize))
	if params != want {
		t.Fatalf("params = %q, want %q", params, want)
	}

	for name, tc := range map[string]struct {
		device string
		offset uint64
		salt   []byte
	}{
		"missing device":   {offset: 4096, salt: salt},
		"unaligned offset": {device: "8:17", offset: 4097, salt: salt},
		"short salt":       {device: "8:17", offset: 4096, salt: salt[:31]},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := verityTable(tc.device, rootHash, tc.offset, tc.salt); err == nil {
				t.Fatal("invalid table accepted")
			}
		})
	}
}

func TestModelSalt(t *testing.T) {
	salt, err := modelSalt(ModelSpec{Name: "m", Repo: "org/model@rev"})
	if err != nil {
		t.Fatalf("modelSalt: %v", err)
	}
	if !bytes.Equal(salt, modelwrap.VeritySalt("org/model@rev")) {
		t.Fatal("salt does not match the modelwrap identity derivation")
	}
	if _, err := modelSalt(ModelSpec{Name: "m"}); err == nil {
		t.Fatal("missing repo accepted")
	}
}

func TestOpenAndMountVerityCleansUpMountFailure(t *testing.T) {
	ops := &fakeModelVolumeOps{mountErr: errors.New("mount failed")}
	err := openAndMountVerityWithOps(ops, "/dev/source", "mwp-test", strings.Repeat("a", 64), "4096", testSalt(), "/mnt/model")
	if err == nil || !strings.Contains(err.Error(), "mount failed") {
		t.Fatalf("error = %v, want mount failure", err)
	}
	wantCalls := []string{"verity:mwp-test", "mount:/dev/mapper/mwp-test", "remove:mwp-test"}
	if fmt.Sprint(ops.calls) != fmt.Sprint(wantCalls) {
		t.Fatalf("calls = %v, want %v", ops.calls, wantCalls)
	}
}

func TestOpenEncryptedAndMountZeroesKeyAndCleansUp(t *testing.T) {
	key := bytes.Repeat([]byte{0xa5}, modelwrap.EMWPKeyBytes)
	ops := &fakeModelVolumeOps{verityErr: errors.New("verity failed")}
	err := openEncryptedAndMount(
		ops,
		"/dev/source",
		"emwp-test-crypt",
		"mwp-test",
		strings.Repeat("a", 64),
		"4096",
		testSalt(),
		"/mnt/model",
		key,
	)
	if err == nil || !strings.Contains(err.Error(), "verity failed") {
		t.Fatalf("error = %v, want verity failure", err)
	}
	if !bytes.Equal(ops.openCryptKey, bytes.Repeat([]byte{0xa5}, modelwrap.EMWPKeyBytes)) {
		t.Fatal("dm-crypt did not receive the derived key")
	}
	if !bytes.Equal(key, make([]byte, modelwrap.EMWPKeyBytes)) {
		t.Fatalf("derived key was not zeroed: %x", key)
	}
	wantCalls := []string{"crypt:emwp-test-crypt", "verity:mwp-test", "remove:emwp-test-crypt"}
	if fmt.Sprint(ops.calls) != fmt.Sprint(wantCalls) {
		t.Fatalf("calls = %v, want %v", ops.calls, wantCalls)
	}
}

func TestOpenEncryptedAndMountCleansBothMappingsAfterMountFailure(t *testing.T) {
	key := bytes.Repeat([]byte{0x3c}, modelwrap.EMWPKeyBytes)
	ops := &fakeModelVolumeOps{mountErr: errors.New("mount failed")}
	err := openEncryptedAndMount(
		ops,
		"/dev/source",
		"emwp-test-crypt",
		"mwp-test",
		strings.Repeat("a", 64),
		"4096",
		testSalt(),
		"/mnt/model",
		key,
	)
	if err == nil || !strings.Contains(err.Error(), "mount failed") {
		t.Fatalf("error = %v, want mount failure", err)
	}
	wantCalls := []string{
		"crypt:emwp-test-crypt",
		"verity:mwp-test",
		"mount:/dev/mapper/mwp-test",
		"remove:mwp-test",
		"remove:emwp-test-crypt",
	}
	if fmt.Sprint(ops.calls) != fmt.Sprint(wantCalls) {
		t.Fatalf("calls = %v, want %v", ops.calls, wantCalls)
	}
	if !bytes.Equal(key, make([]byte, modelwrap.EMWPKeyBytes)) {
		t.Fatalf("derived key was not zeroed: %x", key)
	}
}

func testSalt() []byte {
	return bytes.Repeat([]byte{0x5a}, veritySaltSize)
}

type fakeModelVolumeOps struct {
	calls        []string
	openCryptKey []byte
	cryptErr     error
	verityErr    error
	mountErr     error
	removeErr    error
}

func (ops *fakeModelVolumeOps) openVerity(_ string, name, _, _ string, _ []byte) (string, error) {
	ops.calls = append(ops.calls, "verity:"+name)
	if ops.verityErr != nil {
		return "", ops.verityErr
	}
	return "/dev/mapper/" + name, nil
}

func (ops *fakeModelVolumeOps) openCrypt(_ string, name string, key []byte) (string, error) {
	ops.calls = append(ops.calls, "crypt:"+name)
	ops.openCryptKey = append([]byte(nil), key...)
	if ops.cryptErr != nil {
		return "", ops.cryptErr
	}
	return "/dev/mapper/" + name, nil
}

func (ops *fakeModelVolumeOps) remove(name string) error {
	ops.calls = append(ops.calls, "remove:"+name)
	return ops.removeErr
}

func (ops *fakeModelVolumeOps) mount(sourceDevice, _ string) error {
	ops.calls = append(ops.calls, "mount:"+sourceDevice)
	return ops.mountErr
}

func TestModelPackRefForModel(t *testing.T) {
	ref := strings.Repeat("a", 64) + "_4096_0eefa619-50b7-588f-a072-d405fb439d36"

	for _, tt := range []struct {
		name     string
		model    ModelSpec
		wantKind modelKind
	}{
		{name: "legacy mpk", model: ModelSpec{Name: "legacy", MPK: ref}, wantKind: modelKindPlaintext},
		{name: "mwp", model: ModelSpec{Name: "plain", MWP: ref}, wantKind: modelKindPlaintext},
		{name: "emwp", model: ModelSpec{Name: "encrypted", EMWP: ref}, wantKind: modelKindEncrypted},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, kind, err := modelPackRefForModel(tt.model)
			if err != nil {
				t.Fatalf("expected model ref: %v", err)
			}
			if got.raw != ref {
				t.Fatalf("raw ref mismatch: got %q want %q", got.raw, ref)
			}
			if kind != tt.wantKind {
				t.Fatalf("kind mismatch: got %q want %q", kind, tt.wantKind)
			}
		})
	}

	for _, tt := range []struct {
		name  string
		model ModelSpec
	}{
		{name: "missing model ref", model: ModelSpec{Name: "missing"}},
		{name: "both mpk and mwp", model: ModelSpec{Name: "both", MPK: ref, MWP: ref}},
		{name: "both mwp and emwp", model: ModelSpec{Name: "both", MWP: ref, EMWP: ref}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := modelPackRefForModel(tt.model); err == nil {
				t.Fatal("expected model ref error")
			}
		})
	}
}

func TestEncryptedModelKey(t *testing.T) {
	key := strings.Repeat("k", modelwrap.EMWPMasterKeyBytes)
	spec := &modelPackRef{
		ArtifactRef: &modelwrap.ArtifactRef{
			RootHash:   strings.Repeat("a", 64),
			HashOffset: "4096",
			UUID:       "0eefa619-50b7-588f-a072-d405fb439d36",
		},
	}
	ext := &shimconfig.ExternalConfig{
		Secrets: map[string]string{
			"PRIVATE_MODEL_KEY": base64.StdEncoding.EncodeToString([]byte(key)),
		},
	}
	got, err := encryptedModelKey("PRIVATE_MODEL_KEY", spec, ext)
	if err != nil {
		t.Fatalf("expected derived key: %v", err)
	}
	if len(got) != modelwrap.EMWPKeyBytes {
		t.Fatalf("derived key length: got %d, want %d", len(got), modelwrap.EMWPKeyBytes)
	}
	if bytes.Equal(got, []byte(key)) {
		t.Fatal("derived key should differ from external master key")
	}
	gotAgain, err := encryptedModelKey("PRIVATE_MODEL_KEY", spec, ext)
	if err != nil {
		t.Fatalf("expected repeat derived key: %v", err)
	}
	if !bytes.Equal(got, gotAgain) {
		t.Fatal("derived key should be deterministic for the same artifact")
	}
	otherRef := *spec.ArtifactRef
	otherRef.UUID = "1eefa619-50b7-588f-a072-d405fb439d36"
	otherSpec := &modelPackRef{ArtifactRef: &otherRef}
	otherGot, err := encryptedModelKey("PRIVATE_MODEL_KEY", otherSpec, ext)
	if err != nil {
		t.Fatalf("expected other derived key: %v", err)
	}
	if bytes.Equal(got, otherGot) {
		t.Fatal("derived key should differ across artifacts")
	}

	for _, tc := range []struct {
		name string
		ext  *shimconfig.ExternalConfig
	}{
		{name: "missing external config"},
		{name: "missing secret", ext: &shimconfig.ExternalConfig{Secrets: map[string]string{}}},
		{name: "bad base64", ext: &shimconfig.ExternalConfig{Secrets: map[string]string{"PRIVATE_MODEL_KEY": "!"}}},
		{name: "short key", ext: &shimconfig.ExternalConfig{Secrets: map[string]string{"PRIVATE_MODEL_KEY": base64.StdEncoding.EncodeToString([]byte("short"))}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := encryptedModelKey("PRIVATE_MODEL_KEY", spec, tc.ext); err == nil {
				t.Fatal("expected key decode error")
			}
		})
	}
}
