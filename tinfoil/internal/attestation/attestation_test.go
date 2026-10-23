package attestation

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
