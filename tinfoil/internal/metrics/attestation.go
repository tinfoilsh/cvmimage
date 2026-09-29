package metrics

import (
	"net/http"
	"strings"
	"sync"

	"github.com/felixge/httpsnoop"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"golang.org/x/mod/semver"

	"tinfoil/internal/legacy"
)

const (
	AttestationEndpointUnversioned = "unversioned"
	AttestationEndpointV3          = "v3"

	attestationRequestsName = "tfshim_attestation_requests_total"
	attestationFormatHeader = "Tinfoil-Pt"
	sdkNameHeader           = "Tinfoil-SDK"
	sdkVersionHeader        = "Tinfoil-SDK-Version"
	maxSDKIdentities        = 128
	maxSDKVersionLength     = 64
	unknownSDKLabel         = "unknown"
	developmentSDKLabel     = "devel"
	overflowSDKLabel        = "other"
	noAttestationVersion    = "none"
	attestationVersionV2    = "v2"
	attestationVersionV3    = "v3"
	attestationServed       = "served"
	attestationClientError  = "client_error"
	attestationServerError  = "server_error"
	attestationOtherResult  = "other"
	sdkGo                   = "tinfoil-go"
	sdkJS                   = "tinfoil-js"
	sdkPython               = "tinfoil-python"
	sdkRust                 = "tinfoil-rs"
	sdkJSVerifier           = "@tinfoilsh/verifier"
)

const (
	clientFamilyGo      = "go"
	clientFamilyPython  = "python"
	clientFamilyNode    = "node"
	clientFamilyBrowser = "browser"
	clientFamilyCurl    = "curl"
	clientFamilyOther   = "other"
	clientFamilyUnknown = "unknown"

	userAgentGoPrefix             = "Go-http-client/"
	userAgentPythonRequestsPrefix = "python-requests/"
	userAgentPythonHTTPXPrefix    = "python-httpx/"
	userAgentNode                 = "node"
	userAgentUndici               = "undici"
	userAgentBrowserPrefix        = "Mozilla/"
	userAgentCurlPrefix           = "curl/"
)

type sdkIdentity struct {
	name, version string
}

type attestationMetrics struct {
	requests   *prometheus.CounterVec
	mu         sync.Mutex
	identities map[sdkIdentity]struct{}
}

var attestationRequests = newAttestationMetrics()

func newAttestationMetrics() *attestationMetrics {
	return &attestationMetrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attestationRequestsName,
			Help: "Attestation HTTP requests by endpoint, served format, self-reported SDK, coarse User-Agent family, and response result; does not indicate client verification success.",
		}, []string{"endpoint", "attestation_version", "sdk", "sdk_version", "client_family", "result"}),
		identities: make(map[sdkIdentity]struct{}),
	}
}

func (m *attestationMetrics) sdkLabels(headers http.Header) sdkIdentity {
	name := headers.Get(sdkNameHeader)
	switch name {
	case sdkGo, sdkJS, sdkPython, sdkRust, sdkJSVerifier:
	default:
		return sdkIdentity{unknownSDKLabel, unknownSDKLabel}
	}
	version := headers.Get(sdkVersionHeader)
	if len(version) > maxSDKVersionLength {
		return sdkIdentity{name, unknownSDKLabel}
	}
	version = strings.TrimPrefix(version, "v")
	if version == developmentSDKLabel || version == unknownSDKLabel {
		return sdkIdentity{name, version}
	}
	if !semver.IsValid("v" + version) {
		return sdkIdentity{name, unknownSDKLabel}
	}
	identity := sdkIdentity{name, version}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.identities[identity]; exists {
		return identity
	}
	// Clients control these headers, including syntactically valid versions.
	if len(m.identities) >= maxSDKIdentities {
		return sdkIdentity{name, overflowSDKLabel}
	}
	m.identities[identity] = struct{}{}
	return identity
}

func ObserveAttestation(endpoint string, next http.Handler) http.Handler {
	return attestationRequests.observe(endpoint, next)
}

// User-Agent families describe HTTP clients, not Tinfoil SDK identities.
func clientFamily(userAgent string) string {
	userAgent = strings.TrimSpace(userAgent)
	switch {
	case userAgent == "":
		return clientFamilyUnknown
	case strings.HasPrefix(userAgent, userAgentGoPrefix):
		return clientFamilyGo
	case strings.HasPrefix(userAgent, userAgentPythonRequestsPrefix), strings.HasPrefix(userAgent, userAgentPythonHTTPXPrefix):
		return clientFamilyPython
	case userAgent == userAgentNode, userAgent == userAgentUndici:
		return clientFamilyNode
	case strings.HasPrefix(userAgent, userAgentBrowserPrefix):
		return clientFamilyBrowser
	case strings.HasPrefix(userAgent, userAgentCurlPrefix):
		return clientFamilyCurl
	default:
		return clientFamilyOther
	}
}

func (m *attestationMetrics) observe(endpoint string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := m.sdkLabels(r.Header)
		family := clientFamily(r.UserAgent())
		response := httpsnoop.CaptureMetrics(next, w, r)
		version, result := noAttestationVersion, attestationOtherResult
		switch {
		case response.Code >= http.StatusOK && response.Code < http.StatusMultipleChoices:
			result = attestationServed
			switch w.Header().Get(attestationFormatHeader) {
			case envelope.AttestationV3Format:
				version = attestationVersionV3
			case string(legacy.SevGuestV2), string(legacy.TdxGuestV2), string(legacy.DummyV2):
				version = attestationVersionV2
			}
		case response.Code >= http.StatusInternalServerError:
			result = attestationServerError
		case response.Code >= http.StatusBadRequest:
			result = attestationClientError
		}
		m.requests.WithLabelValues(endpoint, version, identity.name, identity.version, family, result).Inc()
	})
}
