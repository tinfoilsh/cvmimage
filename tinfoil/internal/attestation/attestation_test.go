package attestation

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	envelope "github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

func TestBuildRuntimeVersions(t *testing.T) {
	for _, version := range []string{"v0.15.1-rc.13", "v0.15.1-rc.13+gpu", "v0.15.1-rc.13+mini"} {
		t.Run(version, func(t *testing.T) {
			manifest, err := json.Marshal(map[string]string{"version": version})
			require.NoError(t, err)
			sum := sha256.Sum256(manifest)
			digest := hex.EncodeToString(sum[:])
			data, err := json.Marshal(map[string]any{
				"repo": collateral.RuntimeRepo, "tag": version, "digest": digest,
				"manifest_base64": base64.StdEncoding.EncodeToString(manifest),
				"sigstore_bundle": map[string]any{},
			})
			require.NoError(t, err)
			nonce := make([]byte, envelope.NonceSize)
			encoded, err := envelope.Build(envelope.BuildInput{
				Nonce: nonce, CollateralFormat: collateral.FormatV3,
				Collateral: []collateral.Entry{{
					ID: collateral.RuntimeID, Role: collateral.RoleReferenceValues,
					Format: collateral.RuntimeV1Format, Data: data,
				}},
			}, func([64]byte) (string, []byte, error) {
				return envelope.SEVSNPReportV1Format, []byte("report"), nil
			})
			require.NoError(t, err)
			doc, err := envelope.Parse(encoded, nonce)
			require.NoError(t, err)
			runtime, err := doc.Runtime()
			require.NoError(t, err)
			require.Equal(t, version, runtime.Tag)
			require.Equal(t, digest, runtime.Digest)
			require.Equal(t, manifest, runtime.Manifest)
		})
	}
}

func TestConfigAttachmentFollowsMeasuredDisclosurePolicy(t *testing.T) {
	for _, include := range []string{"", "false", "true"} {
		for _, local := range []bool{false, true} {
			t.Run(fmt.Sprintf("include=%s/local=%t", include, local), func(t *testing.T) {
				config := []byte("cvm-version: v0.15.3-rc.1@sha256:" + strings.Repeat("a", 64) + "\n")
				if include != "" {
					config = append(config, []byte("security:\n  include-config-in-attestation: "+include+"\n")...)
				}
				path := filepath.Join(t.TempDir(), "config.yml")
				require.NoError(t, os.WriteFile(path, config, 0600))
				entries := []collateral.Entry{{ID: collateral.RuntimeID, Role: collateral.RoleReferenceValues, Format: collateral.RuntimeV1Format, Data: json.RawMessage(`{}`)}}
				if !local {
					data, err := json.Marshal(map[string]any{"endorsement_ref": "sha256:" + strings.Repeat("b", 64), "sigstore_bundle": map[string]string{"mediaType": "fixture"}, "issuer_certificate_der": []byte("issuer"), "config_base64": []byte("unsolicited config")})
					require.NoError(t, err)
					entries = append(entries, collateral.Entry{ID: collateral.ConfigID, Role: collateral.RoleReferenceValues, Format: collateral.ConfigEndorsementV2Format, Data: data})
				}
				original := slices.Clone(entries)
				attached, err := withConfigAttachment(entries, path)
				require.NoError(t, err)
				require.Equal(t, original, entries, "attachment must not mutate cached collateral")
				require.Equal(t, entries[0], attached[0], "runtime evidence must be preserved")
				if local && include != "true" {
					require.Len(t, attached, 1)
					return
				}
				set, err := collateral.Decode(attached[1:])
				require.NoError(t, err)
				if include == "true" {
					require.Equal(t, config, set.Config.Config)
				} else {
					require.Empty(t, set.Config.Config)
				}
				if !local {
					require.Equal(t, "sha256:"+strings.Repeat("b", 64), set.Config.Reference)
					require.Equal(t, []byte("issuer"), set.Config.Issuer)
					require.JSONEq(t, `{"mediaType":"fixture"}`, string(set.Config.Bundle))
				}
			})
		}
	}
}

func TestConfigAttachmentPreservesPreflightAndLegacyCollateral(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "missing.yml")
	entries, err := withConfigAttachment(nil, missingPath)
	require.NoError(t, err)
	require.Empty(t, entries)
	for _, format := range []string{collateral.ConfigV1Format, collateral.ConfigEndorsementV1Format} {
		legacy := []collateral.Entry{{ID: collateral.ConfigID, Role: collateral.RoleReferenceValues, Format: format, Data: json.RawMessage(`{"config_base64":"Y29uZmln"}`)}}
		entries, err := withConfigAttachment(legacy, missingPath)
		require.NoError(t, err)
		require.Equal(t, legacy, entries)
	}
}
