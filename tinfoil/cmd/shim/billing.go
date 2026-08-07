package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	usagereporting "github.com/tinfoilsh/usage-reporting-go"

	"tinfoil/internal/billing"
	"tinfoil/internal/tokencount"
)

// Billing request/response headers shared with the confidential-model-router.
const (
	// clientRequestedUsageHeader is set by ensureStreamingUsageOptions when the
	// client explicitly asked for usage stats. The response extractor reads it
	// to decide whether to keep or filter usage-only SSE chunks.
	clientRequestedUsageHeader = "X-Tinfoil-Client-Requested-Usage"

	// usageContextMaxSkew bounds how old a signed usage-context header may be
	// before the shim rejects it as stale (and bills normally). Mirrors the
	// router's tool-runtime skew window.
	usageContextMaxSkew = time.Minute
)

// billingSuppressedKey carries the authenticated ingress decision through the
// reverse proxy after the untrusted usage-context headers have been removed.
type billingSuppressedKey struct{}

type billingEventCollector interface {
	AddEvent(billing.Event)
}

func billingSuppressedFromContext(ctx context.Context) bool {
	suppressed, _ := ctx.Value(billingSuppressedKey{}).(bool)
	return suppressed
}

// prepareBillingSuppression validates the router context while its one-minute
// freshness window is still measured at request ingress, then strips both
// headers so they are not exposed to the workload container.
func prepareBillingSuppression(r *http.Request, apiKey, usageContextSecret string) {
	suppressed := alreadyBilledByRouter(r.Header, apiKey, usageContextSecret)
	r.Header.Del(usagereporting.HeaderContext)
	r.Header.Del(usagereporting.HeaderUsageContextSignature)
	*r = *r.WithContext(context.WithValue(r.Context(), billingSuppressedKey{}, suppressed))
}

// ensureStreamingUsageOptions forces upstream streaming requests to include
// usage and continuous usage stats so billing can extract token counts. If the
// client explicitly asked for usage stats, it marks that in a header so the
// response extractor preserves usage-only chunks instead of filtering them.
// Ported from confidential-model-router/main.go.
func ensureStreamingUsageOptions(body map[string]any, headers http.Header) error {
	// Clear any client-supplied value so it cannot spoof the filtering
	// decision in applyBillingToResponse. Only the parsed body options
	// determine whether usage-only chunks are preserved.
	headers.Del(clientRequestedUsageHeader)

	clientRequestedUsage := false

	streamOptions := map[string]any{}
	if raw, present := body["stream_options"]; present {
		var ok bool
		streamOptions, ok = raw.(map[string]any)
		if !ok {
			return fmt.Errorf("'stream_options' must be an object")
		}
	} else {
		streamOptions = map[string]any{}
		body["stream_options"] = streamOptions
	}

	if raw, present := streamOptions["include_usage"]; present {
		includeUsage, ok := raw.(bool)
		if !ok {
			return fmt.Errorf("'stream_options.include_usage' must be a boolean")
		}
		clientRequestedUsage = includeUsage
	}
	if raw, present := streamOptions["continuous_usage_stats"]; present {
		continuousUsage, ok := raw.(bool)
		if !ok {
			return fmt.Errorf("'stream_options.continuous_usage_stats' must be a boolean")
		}
		clientRequestedUsage = clientRequestedUsage || continuousUsage
	}

	streamOptions["include_usage"] = true
	streamOptions["continuous_usage_stats"] = true

	if clientRequestedUsage {
		headers.Set(clientRequestedUsageHeader, "true")
	}
	return nil
}

func hasJSONContentType(header string) bool {
	mediaType, _, err := mime.ParseMediaType(header)
	if err != nil {
		return false
	}
	mediaType = strings.ToLower(mediaType)
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

// prepareBillingRequest inspects every JSON POST body, independent of path, so
// the generic shim supports the same OpenAI-compatible API surface as the
// router. It forces streaming usage options when requested. Billing attribution
// always comes from the shim's measured model-name, never from this untrusted
// request body.
//
// For non-streaming requests, the original body bytes are restored unchanged
// so inference traffic is not modified. For streaming requests, stream_options
// are injected and the body is re-marshalled using json.Number to preserve
// integer precision (e.g. large seed values) that float64 unmarshalling
// would lose. Key order may change (alphabetical) but this does not affect
// the upstream's JSON parsing.
//
// Non-JSON bodies pass through unchanged. Read errors, malformed JSON,
// trailing JSON values, and invalid stream_options are rejected rather than
// forwarding a partial or destructively rewritten request.
func prepareBillingRequest(r *http.Request) (streaming bool, err error) {
	r.Header.Del(clientRequestedUsageHeader)
	if r.Method != http.MethodPost || r.Body == nil || r.Body == http.NoBody || !hasJSONContentType(r.Header.Get("Content-Type")) {
		return false, nil
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		_ = r.Body.Close()
		return false, fmt.Errorf("read request body: %w", err)
	}
	_ = r.Body.Close()

	// Use json.Decoder with UseNumber to preserve integer precision.
	// json.Unmarshal into map[string]any coerces all numbers to float64,
	// which can lose precision for large values (e.g. seed) and alter
	// upstream inference behavior on re-marshal.
	dec := json.NewDecoder(bytes.NewReader(bodyBytes))
	dec.UseNumber()
	var body map[string]any
	if err := dec.Decode(&body); err != nil {
		return false, fmt.Errorf("decode request JSON: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return false, fmt.Errorf("decode request JSON: multiple JSON values")
		}
		return false, fmt.Errorf("decode request JSON: trailing data: %w", err)
	}
	if body == nil {
		return false, fmt.Errorf("decode request JSON: body must be an object")
	}

	if stream, ok := body["stream"].(bool); ok && stream {
		streaming = true
		if err := ensureStreamingUsageOptions(body, r.Header); err != nil {
			return false, err
		}
	}

	// Only re-marshal when the body was mutated (streaming requests may have
	// had stream_options injected). For non-streaming requests, restore the
	// original bytes to avoid changing whitespace and key order.
	if streaming {
		remarshalled, err := json.Marshal(body)
		if err != nil {
			return false, fmt.Errorf("encode request JSON: %w", err)
		}
		r.Body = io.NopCloser(bytes.NewReader(remarshalled))
		r.Header.Set("Content-Length", strconv.Itoa(len(remarshalled)))
		r.ContentLength = int64(len(remarshalled))
	} else {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
		r.ContentLength = int64(len(bodyBytes))
	}
	return streaming, nil
}

// billingCloser wraps a response body and emits a zero-token billing event
// on Close() if the usageHandler was never called. This ensures per-request
// models (e.g. tokenize, whisper) that don't return usage fields still
// generate billing events. Ported from confidential-model-router/manager/proxy.go.
type billingCloser struct {
	io.ReadCloser
	handlerCalled *atomic.Bool
	emitEvent     func()
	once          sync.Once
}

func (b *billingCloser) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() {
		if !b.handlerCalled.Load() {
			b.emitEvent()
		}
	})
	return err
}

// alreadyBilledByRouter reports whether the request carries a validly-signed
// usage-context header from the confidential-model-router declaring that the
// router has already counted this customer request (BillCustomerRequest ==
// false). The shim suppresses its own billing event in that case to prevent
// double-billing on the cloud path (teep → router → shim).
//
// Fail closed toward billing accuracy: a missing context (direct-path client
// with no signing secret) returns false, and an invalid context (bad
// signature, expired IssuedAt, missing half of the header pair, or API key
// mismatch) also returns false with a warning log. The only path that
// suppresses is a validly-signed, in-skew, BillCustomerRequest == false
// context whose APIKeyHash matches the request's bearer token.
func alreadyBilledByRouter(header http.Header, apiKey, usageContextSecret string) bool {
	if usageContextSecret == "" || apiKey == "" {
		return false
	}
	ctx, present, err := usagereporting.FromHeaders(header, usageContextSecret, time.Now(), usageContextMaxSkew)
	switch {
	case !present:
		// Direct-path client (teep): no signed context. Bill normally.
		return false
	case err != nil:
		// Bad signature, expired, or malformed: bill normally and warn.
		log.Printf("warning: invalid usage-context signature from upstream: %v", err)
		return false
	case ctx.BillCustomerRequest:
		// Downstream is explicitly told to bill its own line item
		// (the tool-runtime semantics). Not the router→shim case; bill.
		return false
	}

	// Suppression is only valid for the immediate router -> shim hop. Requiring
	// all three fields prevents a correctly signed but semantically unrelated
	// context (or an empty API-key hash) from becoming a billing wildcard.
	if ctx.ParentService != usagereporting.ServiceRouter || ctx.Depth != 1 || strings.TrimSpace(ctx.APIKeyHash) == "" {
		log.Printf("warning: refusing billing suppression for unexpected usage context (parent_service=%q depth=%d api_key_hash_present=%t)",
			ctx.ParentService, ctx.Depth, strings.TrimSpace(ctx.APIKeyHash) != "")
		return false
	}
	if !usagereporting.VerifyAPIKeyHash(apiKey, ctx.APIKeyHash) {
		log.Printf("warning: refusing billing suppression because usage context does not match request API key")
		return false
	}

	return true
}

// applyBillingToResponse wraps the proxied response body to extract token
// usage and emits a billing event via the collector. It mirrors the
// confidential-model-router proxy's ModifyResponse billing chokepoint:
//
//   - Streaming responses are processed through the SSE token extractor, which
//     invokes the usage handler on the terminal usage chunk and filters
//     usage-only chunks when the client did not request usage. The handler is
//     always invoked (even with zero usage) so a billing event is emitted
//     even if the stream was truncated or the client disconnected early.
//   - Non-streaming JSON 200 responses are teed so usage is extracted on
//     Close() without buffering the whole body up front.
//   - A billingCloser guarantees a zero-token event for usage-less 200 paths.
//   - WebSocket/protocol upgrades emit a zero-token event immediately.
//
// When collector is nil or the request carried no API key, this is a no-op
// (the body still passes through the token extractor unchanged so streaming
// usage-only chunk filtering behaves consistently, but no event is emitted).
func applyBillingToResponse(resp *http.Response, collector billingEventCollector, modelName, enclaveHost string) {
	req := resp.Request

	apiKey := extractBearerToken(req.Header.Get("Authorization"))
	clientRequestedUsage := req.Header.Get(clientRequestedUsageHeader) == "true"
	requestPath := req.URL.Path
	streaming := strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream")

	requestID := resp.Header.Get("X-Request-Id")
	if requestID == "" {
		requestID = resp.Header.Get("X-Request-ID")
	}

	// Suppress this enclave's billing event when the router has already
	// counted the request (cloud path). The response body still passes
	// through the token extractor unchanged so streaming usage-only chunk
	// filtering behaves identically for router-path and direct-path traffic
	// — only the event emission is suppressed, never the body transformation.
	alreadyBilled := billingSuppressedFromContext(req.Context())

	emitZeroTokenEvent := func() {
		if collector == nil || apiKey == "" || alreadyBilled {
			return
		}
		collector.AddEvent(billing.Event{
			Timestamp:   time.Now(),
			UserID:      "authenticated_user",
			APIKey:      apiKey,
			Model:       modelName,
			RequestID:   requestID,
			Enclave:     enclaveHost,
			RequestPath: requestPath,
			Streaming:   streaming,
		})
	}

	// WebSocket/protocol upgrade: the reverse proxy hijacks both connections
	// and copies bidirectionally after this callback returns. We must not
	// touch or wrap the body, but still emit a billing event.
	if resp.StatusCode == http.StatusSwitchingProtocols {
		emitZeroTokenEvent()
		return
	}

	var handlerCalled atomic.Bool

	usageHandler := func(usage *tokencount.Usage) {
		handlerCalled.Store(true)
		if usage == nil {
			return
		}
		if collector == nil || apiKey == "" || alreadyBilled {
			return
		}
		cachedPromptTokens := 0
		if value, ok := usage.CachedPromptTokens(); ok {
			cachedPromptTokens = value
		}
		collector.AddEvent(billing.Event{
			Timestamp:          time.Now(),
			UserID:             "authenticated_user",
			APIKey:             apiKey,
			Model:              modelName,
			PromptTokens:       usage.PromptTokens,
			CachedPromptTokens: cachedPromptTokens,
			CompletionTokens:   usage.CompletionTokens,
			TotalTokens:        usage.TotalTokens,
			RequestID:          requestID,
			Enclave:            enclaveHost,
			RequestPath:        requestPath,
			Streaming:          streaming,
		})
	}

	newBody, err := tokencount.ExtractTokensFromResponseWithHandler(resp, modelName, usageHandler, clientRequestedUsage)
	if err != nil {
		// Don't fail the request; leave the body untouched.
		log.Printf("billing token extraction failed: %v", err)
		return
	}
	resp.Body = newBody

	// For non-streaming successful responses, wrap the body so a billing
	// event is emitted on Close() even when the response has no usage field
	// (e.g. tokenize, metrics). The billingCloser only fires if the
	// usageHandler was never called, preventing double-billing for models
	// that do include usage.
	if !streaming && collector != nil && apiKey != "" && !alreadyBilled && resp.StatusCode == http.StatusOK {
		resp.Body = &billingCloser{
			ReadCloser:    resp.Body,
			handlerCalled: &handlerCalled,
			emitEvent:     emitZeroTokenEvent,
		}
	}

	if streaming {
		resp.Header.Del("Content-Length")
	}
}
