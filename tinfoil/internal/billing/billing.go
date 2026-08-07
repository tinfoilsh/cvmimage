// Package billing records per-request usage events and ships them to the
// control plane via the signed usage-reporting client. It is a port of the
// confidential-model-router's billing collector so that direct (routerless)
// inference paths record usage identically to the relayed path.
package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	usagereporting "github.com/tinfoilsh/usage-reporting-go"
	usageclient "github.com/tinfoilsh/usage-reporting-go/client"
)

// Event represents a billing event with token usage. CachedPromptTokens is the
// subset of PromptTokens that the model served from its prompt cache; the
// uncached portion is derived downstream.
type Event struct {
	Timestamp          time.Time `json:"timestamp"`
	UserID             string    `json:"user_id"`
	Model              string    `json:"model"`
	PromptTokens       int       `json:"prompt_tokens"`
	CachedPromptTokens int       `json:"cached_prompt_tokens"`
	CompletionTokens   int       `json:"completion_tokens"`
	TotalTokens        int       `json:"total_tokens"`
	RequestID          string    `json:"request_id"`
	Enclave            string    `json:"enclave"`
	RequestPath        string    `json:"request_path"`
	Streaming          bool      `json:"streaming"`
	APIKey             string    `json:"api_key"`
}

// Collector ships billing events to the control plane via the usage reporter.
type Collector struct {
	reporter *usageclient.ReporterClient
	stopOnce sync.Once
}

// maskAPIKey masks an API key for safe logging
// Shows first 3 and last 4 characters, masking the rest
func maskAPIKey(apiKey string) string {
	if len(apiKey) <= 10 {
		// Too short to mask safely
		return "***"
	}
	return apiKey[:3] + strings.Repeat("*", len(apiKey)-7) + apiKey[len(apiKey)-4:]
}

// NewCollector creates a billing event collector. Callers that are not
// accounting boundaries must explicitly avoid constructing one; incomplete
// collector configuration is an error rather than an implicit disabled mode.
func NewCollector(controlPlaneURL, reporterID, reporterSecret string) (*Collector, error) {
	return newCollector(controlPlaneURL, reporterID, reporterSecret, nil)
}

func newCollector(controlPlaneURL, reporterID, reporterSecret string, httpClient *http.Client) (*Collector, error) {
	endpoint, err := ingestionEndpoint(controlPlaneURL)
	if err != nil {
		return nil, err
	}
	if reporterID == "" {
		return nil, fmt.Errorf("usage reporter ID is required")
	}
	if reporterID != strings.TrimSpace(reporterID) {
		return nil, fmt.Errorf("usage reporter ID must not have leading or trailing whitespace")
	}
	if reporterSecret == "" {
		return nil, fmt.Errorf("usage reporter secret is required")
	}

	c := &Collector{
		reporter: usageclient.New(usageclient.Config{
			Endpoint:   endpoint,
			ReporterID: reporterID,
			Secret:     reporterSecret,
			HTTPClient: httpClient,
		}),
	}
	if !c.reporter.Enabled() {
		return nil, fmt.Errorf("usage reporter initialization returned a disabled client")
	}
	return c, nil
}

func ingestionEndpoint(controlPlaneURL string) (string, error) {
	u, err := url.Parse(controlPlaneURL)
	if err != nil {
		return "", fmt.Errorf("parse control plane URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("control plane URL must be an absolute https URL without credentials, query, or fragment")
	}
	return strings.TrimRight(controlPlaneURL, "/") + usagereporting.IngestionPath, nil
}

// Enabled reports whether the collector has a configured reporter.
func (c *Collector) Enabled() bool {
	return c != nil && c.reporter != nil && c.reporter.Enabled()
}

// AddEvent forwards a billing event to the usage reporter and writes a masked
// log line for local observability.
func (c *Collector) AddEvent(event Event) {
	if !c.Enabled() {
		panic("billing: AddEvent called on an uninitialized collector")
	}

	// Create a safe version for logging with masked API key
	safeEvent := event
	safeEvent.APIKey = maskAPIKey(event.APIKey)

	eventJSON, err := json.Marshal(safeEvent)
	if err != nil {
		log.WithError(err).Error("Failed to marshal billing event")
		return
	}

	inputTokens := int64(event.PromptTokens)
	outputTokens := int64(event.CompletionTokens)
	if inputTokens == 0 && outputTokens == 0 && event.TotalTokens > 0 {
		inputTokens = int64(event.TotalTokens)
	}

	cachedInputTokens := int64(event.CachedPromptTokens)
	if cachedInputTokens > inputTokens {
		cachedInputTokens = inputTokens
	}

	meters := []usagereporting.Meter{
		{Name: usagereporting.MeterInputTokens, Quantity: inputTokens},
		{Name: usagereporting.MeterOutputTokens, Quantity: outputTokens},
	}
	if cachedInputTokens > 0 {
		meters = append(meters, usagereporting.Meter{
			Name:     usagereporting.MeterCachedInputTokens,
			Quantity: cachedInputTokens,
		})
	}

	c.reporter.AddEvent(usagereporting.Event{
		RequestID:  event.RequestID,
		OccurredAt: event.Timestamp,
		APIKey:     event.APIKey,
		Operation: usagereporting.Operation{
			Service: usagereporting.ServiceRouter,
			Name:    usagereporting.OperationRouterModelRequest,
		},
		CustomerRequests: 1,
		Meters:           meters,
		Attributes: map[string]string{
			"model":     event.Model,
			"route":     event.RequestPath,
			"streaming": fmt.Sprintf("%t", event.Streaming),
			"enclave":   event.Enclave,
		},
	})

	log.WithFields(log.Fields{
		"type": "billing_event",
		"data": string(eventJSON),
	}).Info("Billing event collected")
}

// Stop gracefully shuts down the collector, flushing pending events with a
// bounded timeout so a network stall cannot block shim shutdown indefinitely.
func (c *Collector) Stop() {
	c.stopOnce.Do(func() {
		if c.reporter != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c.reporter.Stop(ctx)
		}
	})
}
