package modelpack

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	runtimeconfig "github.com/tinfoilsh/tinfoil-config"
)

func TestCompiledPackIdentity(t *testing.T) {
	ref := strings.Repeat("a", 64) + "_4096_0eefa619-50b7-588f-a072-d405fb439d36"
	got, err := Compile(runtimeconfig.ModelSpec{MWP: ref, Repo: "org/model@rev"})
	if err != nil {
		t.Fatalf("expected valid model pack ref: %v", err)
	}
	if got.Ref != ref || got.Repo != "org/model@rev" || got.Encrypted {
		t.Fatalf("pack identity changed: %+v", got)
	}
	if got.MapperName() != "mwp-"+strings.Repeat("a", 64) {
		t.Fatalf("mapper name mismatch: %s", got.MapperName())
	}
	if _, err := Compile(runtimeconfig.ModelSpec{MWP: "not-a-ref", Repo: "org/model@rev"}); err == nil {
		t.Fatal("expected validation error to propagate from modelwrap")
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

func TestCompilePackReferences(t *testing.T) {
	ref := strings.Repeat("a", 64) + "_4096_0eefa619-50b7-588f-a072-d405fb439d36"

	for _, tt := range []struct {
		name      string
		model     runtimeconfig.ModelSpec
		encrypted bool
	}{
		{name: "legacy mpk", model: runtimeconfig.ModelSpec{Name: "legacy", MPK: ref}},
		{name: "mwp", model: runtimeconfig.ModelSpec{Name: "plain", MWP: ref}},
		{name: "emwp", model: runtimeconfig.ModelSpec{Name: "encrypted", EMWP: ref}, encrypted: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt.model.Repo = "org/model@rev"
			got, err := Compile(tt.model)
			if err != nil {
				t.Fatalf("expected model ref: %v", err)
			}
			if got.Ref != ref {
				t.Fatalf("raw ref mismatch: got %q want %q", got.Ref, ref)
			}
			if got.Encrypted != tt.encrypted {
				t.Fatalf("encryption mismatch: got %t want %t", got.Encrypted, tt.encrypted)
			}
		})
	}

	for _, tt := range []struct {
		name  string
		model runtimeconfig.ModelSpec
	}{
		{name: "missing model ref", model: runtimeconfig.ModelSpec{Name: "missing"}},
		{name: "both mpk and mwp", model: runtimeconfig.ModelSpec{Name: "both", MPK: ref, MWP: ref}},
		{name: "both mwp and emwp", model: runtimeconfig.ModelSpec{Name: "both", MWP: ref, EMWP: ref}},
		{name: "missing repo", model: runtimeconfig.ModelSpec{Name: "missing-repo", MWP: ref}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name != "missing repo" {
				tt.model.Repo = "org/model@rev"
			}
			if _, err := Compile(tt.model); err == nil {
				t.Fatal("expected model ref error")
			}
		})
	}
}
