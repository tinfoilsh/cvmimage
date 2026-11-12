// Package attestation produces the enclave's attestation documents: it
// acquires hardware quotes and assembles the v3 document served at the
// well-known endpoint. Wire shapes (document, sections, collateral entries,
// format URIs) and all verification logic live in tinfoil-go; this package
// owns only the production side.
package attestation

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"time"

	sevabi "github.com/google/go-sev-guest/abi"
	sevclient "github.com/google/go-sev-guest/client"
	tdxclient "github.com/google/go-tdx-guest/client"
	sharedconfig "github.com/tinfoilsh/tinfoil-config"
	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
	envelope "github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"gopkg.in/yaml.v3"

	"tinfoil/internal/boot"
	"tinfoil/internal/kernelcmdline"
)

const (
	PlatformSEVSNP = "sev-snp"
	PlatformTDX    = "tdx"
)

type Identity struct {
	TLSKeyFP [32]byte
	HPKEKey  [32]byte
	Workload []envelope.CryptoMaterialItem
}

func (a Identity) CryptoMaterial() []envelope.CryptoMaterialItem {
	items := []envelope.CryptoMaterialItem{
		{ID: envelope.CryptoMaterialIDTLS, Format: envelope.KeySPKIFPSHA256V1Format, Data: hex.EncodeToString(a.TLSKeyFP[:])},
		{ID: envelope.CryptoMaterialIDHPKE, Format: envelope.KeyX25519HPKEV1Format, Data: hex.EncodeToString(a.HPKEKey[:])},
	}
	return append(items, a.Workload...)
}

// Guest device paths, one per platform.
const (
	SEVGuestDevice = "/dev/sev-guest"
	TDXGuestDevice = "/dev/tdx_guest"
)

// DevicePlatform names the platform from the guest device present, without
// opening it.
func DevicePlatform() (string, error) {
	if _, err := os.Stat(SEVGuestDevice); err == nil {
		return PlatformSEVSNP, nil
	}
	if _, err := os.Stat(TDXGuestDevice); err == nil {
		return PlatformTDX, nil
	}
	return "", fmt.Errorf("no attestation device found (checked %s, %s)", SEVGuestDevice, TDXGuestDevice)
}

// Report fetches the raw hardware attestation report and platform identifier.
func Report(userData [64]byte) (report []byte, platform string, err error) {
	cmdline, err := kernelcmdline.Read()
	if err != nil {
		return nil, "", err
	}
	if cmdline.NonCC {
		return nil, "", fmt.Errorf("hardware attestation is disabled in non-CC mode")
	}
	platform, err = DevicePlatform()
	if err != nil {
		return nil, "", err
	}
	switch platform {
	case PlatformSEVSNP:
		var qp sevclient.LinuxConfigFsQuoteProvider
		report, err = qp.GetRawQuote(userData)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get quote: %w", err)
		}
		if len(report) > sevabi.ReportSize {
			report = report[:sevabi.ReportSize]
		}
		return report, PlatformSEVSNP, nil
	case PlatformTDX:
		var qp tdxclient.QuoteProvider
		qp, err = tdxclient.GetQuoteProvider()
		if err != nil {
			return nil, "", fmt.Errorf("failed to get quote provider: %w", err)
		}
		if err = qp.IsSupported(); err != nil {
			return nil, "", fmt.Errorf("TDX is not supported: %w", err)
		}
		report, err = qp.GetRawQuote(userData)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get quote: %w", err)
		}
		return report, PlatformTDX, nil
	default:
		return nil, "", fmt.Errorf("unsupported platform %q", platform)
	}
}

const (
	quoteRetries    = 3
	quoteRetryDelay = 50 * time.Millisecond
)

// reportWithRetry calls Report with a bounded retry. Quote generation
// serializes on a single in-guest buffer (and, for TDX, a host round trip),
// so concurrent attestation requests can fail transiently with EINTR/EBUSY;
// a short retry absorbs that contention instead of surfacing it to clients.
func reportWithRetry(userData [64]byte) (report []byte, platform string, err error) {
	for attempt := 0; ; attempt++ {
		report, platform, err = Report(userData)
		if err == nil || attempt == quoteRetries {
			return report, platform, err
		}
		time.Sleep(quoteRetryDelay * time.Duration(attempt+1))
	}
}

// evidenceFormat maps a platform label to its CPU evidence format URI.
func evidenceFormat(platform string) (string, error) {
	switch platform {
	case PlatformSEVSNP:
		return envelope.SEVSNPReportV1Format, nil
	case PlatformTDX:
		return envelope.TDXQuoteV1Format, nil
	default:
		return "", fmt.Errorf("unsupported platform %q for v3 evidence", platform)
	}
}

// BuildAttestation assembles a fresh v3 attestation document: it serializes
// the two endorsed sections exactly once, derives REPORT_DATA from their
// hashes and the nonce, obtains a hardware quote over that REPORT_DATA, and
// returns the complete document. The endorsed sections are carried
// base64-encoded so verifiers recover the exact hashed bytes with a plain
// decode.
func BuildAttestation(
	material []envelope.CryptoMaterialItem,
	nonce []byte,
	deviceEvidence []envelope.DeviceEvidenceItem,
	collateral wire.Response,
) (json.RawMessage, error) {
	return buildAttestation(material, nonce, deviceEvidence, collateral, reportWithRetry)
}

type quoteReader func([64]byte) ([]byte, string, error)

func buildAttestation(
	material []envelope.CryptoMaterialItem,
	nonce []byte,
	deviceEvidence []envelope.DeviceEvidenceItem,
	collateral wire.Response,
	readQuote quoteReader,
) (json.RawMessage, error) {
	entries, err := withConfigAttachment(collateral.Collateral, boot.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("preparing config attachment: %w", err)
	}
	return envelope.Build(envelope.BuildInput{
		Nonce: nonce, CryptoMaterial: material, DeviceEvidence: deviceEvidence, Collateral: entries, CollateralFormat: collateral.Format,
	}, func(reportData [64]byte) (string, []byte, error) {
		rawQuote, platform, err := readQuote(reportData)
		if err != nil {
			return "", nil, fmt.Errorf("obtaining hardware quote: %w", err)
		}
		format, err := evidenceFormat(platform)
		return format, rawQuote, err
	})
}

func withConfigAttachment(entries []collateral.Entry, path string) ([]collateral.Entry, error) {
	// Preflight documents must not contain collateral.
	if len(entries) == 0 {
		return entries, nil
	}
	configIndex := -1
	for i, entry := range entries {
		if entry.ID == collateral.ConfigID {
			if entry.Format != collateral.ConfigEndorsementV2Format {
				return entries, nil
			}
			configIndex = i
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config struct {
		Security sharedconfig.SecurityConfig `yaml:"security"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	if !config.Security.IncludeConfigInAttestation {
		data = nil
	}
	fields := make(map[string]json.RawMessage)
	if configIndex >= 0 {
		if err := json.Unmarshal(entries[configIndex].Data, &fields); err != nil {
			return nil, err
		}
		if fields == nil {
			return nil, fmt.Errorf("config endorsement must be an object")
		}
	} else if len(data) == 0 {
		return entries, nil
	}
	delete(fields, "config_base64")
	if len(data) != 0 {
		fields["config_base64"], err = json.Marshal(data)
		if err != nil {
			return nil, err
		}
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	entries = slices.Clone(entries)
	if configIndex >= 0 {
		entries[configIndex].Data = encoded
	} else {
		entries = append(entries, collateral.Entry{ID: collateral.ConfigID, Role: collateral.RoleReferenceValues, Format: collateral.ConfigV1Format, Data: encoded})
	}
	return entries, nil
}
