// Package tokencount extracts OpenAI-compatible token usage from inference
// responses (streaming and non-streaming). Streaming responses are processed
// line-by-line without buffering the full body; non-streaming JSON responses
// are teed to the client while being accumulated for usage extraction on
// Close(). It is a port of the confidential-model-router's tokencount package
// so the direct (routerless) path can bill identically.
package tokencount

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
)

// Usage represents token usage information from inference responses.
// Supports both Chat Completions (prompt_tokens/completion_tokens) and
// Responses API (input_tokens/output_tokens) field names.
type Usage struct {
	PromptTokens        int                  `json:"prompt_tokens"`
	CompletionTokens    int                  `json:"completion_tokens"`
	TotalTokens         int                  `json:"total_tokens"`
	InputTokens         int                  `json:"input_tokens"`
	OutputTokens        int                  `json:"output_tokens"`
	PromptTokensDetails *PromptTokensDetails `json:"prompt_tokens_details,omitempty"`
	InputTokensDetails  *PromptTokensDetails `json:"input_tokens_details,omitempty"`
}

type PromptTokensDetails struct {
	CachedTokens int `json:"cached_tokens"`
}

// Normalize maps Responses API fields (input_tokens/output_tokens) into
// Chat Completions fields (prompt_tokens/completion_tokens) so billing
// works uniformly regardless of which API produced the usage data. It also
// derives TotalTokens when the upstream omits it, so non-streaming and
// streaming billing events are consistent.
func (u *Usage) Normalize() {
	if u.PromptTokens == 0 && u.InputTokens > 0 {
		u.PromptTokens = u.InputTokens
	}
	if u.CompletionTokens == 0 && u.OutputTokens > 0 {
		u.CompletionTokens = u.OutputTokens
	}
	if u.PromptTokensDetails == nil && u.InputTokensDetails != nil {
		u.PromptTokensDetails = u.InputTokensDetails
	}
	if u.TotalTokens == 0 {
		u.TotalTokens = u.PromptTokens + u.CompletionTokens
	}
}

func (u *Usage) CachedPromptTokens() (int, bool) {
	if u == nil || u.PromptTokensDetails == nil {
		return 0, false
	}

	cached := min(u.PromptTokens, max(0, u.PromptTokensDetails.CachedTokens))
	return cached, true
}

// OpenAIResponse represents a standard OpenAI-compatible response
type OpenAIResponse struct {
	Usage *Usage `json:"usage,omitempty"`
}

// JSONTokenExtractor accumulates JSON response data and extracts tokens
type JSONTokenExtractor struct {
	buffer bytes.Buffer
	model  string
	usage  *Usage
	mu     sync.Mutex
}

// Write implements io.Writer, accumulating data
func (j *JSONTokenExtractor) Write(p []byte) (n int, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.buffer.Write(p)
}

// ExtractUsage parses the accumulated JSON and extracts token usage
func (j *JSONTokenExtractor) ExtractUsage() {
	j.mu.Lock()
	defer j.mu.Unlock()

	var resp OpenAIResponse
	if err := json.Unmarshal(j.buffer.Bytes(), &resp); err == nil && resp.Usage != nil {
		resp.Usage.Normalize()
		j.usage = resp.Usage
	}
}

// teeReaderCloser wraps a TeeReader and extracts tokens on close
type teeReaderCloser struct {
	io.Reader
	origBody     io.ReadCloser
	extractor    *JSONTokenExtractor
	usageHandler func(*Usage)
}

// Close extracts usage from the data accumulated so far and closes the
// original body. If the caller closes early (e.g. client disconnect), the
// buffered JSON may be incomplete and usage extraction will silently fail,
// leading to under-billing for that request. This matches the
// confidential-model-router's behavior; draining the remaining upstream
// body on early close would waste bandwidth on a disconnected client.
func (t *teeReaderCloser) Close() error {
	// Extract usage from accumulated data
	t.extractor.ExtractUsage()

	// Call usage handler if provided
	if t.usageHandler != nil && t.extractor.usage != nil {
		t.usageHandler(t.extractor.usage)
	}

	// Close original body
	return t.origBody.Close()
}

// ExtractTokensFromResponse extracts token counts from HTTP response.
// The response body is returned as a pass-through reader so the client
// receives bytes without delay; usage is extracted on Close() or, for
// streaming, as the stream is processed. Usage is delivered via the
// usageHandler callback, not a return value.
func ExtractTokensFromResponse(resp *http.Response, model string) (io.ReadCloser, error) {
	return ExtractTokensFromResponseWithHandler(resp, model, nil, false)
}

// ExtractTokensFromResponseWithHandler wraps the response body to extract
// token usage with an optional usage handler. For streaming responses the
// handler is invoked on the terminal usage chunk; for non-streaming JSON
// responses it is invoked on Close(). clientRequestedUsage indicates if the
// client explicitly requested usage stats in their request (controls
// usage-only SSE chunk filtering).
func ExtractTokensFromResponseWithHandler(resp *http.Response, model string, usageHandler func(*Usage), clientRequestedUsage bool) (io.ReadCloser, error) {
	contentType := resp.Header.Get("Content-Type")

	// For streaming responses, use the streaming extractor
	if strings.Contains(contentType, "text/event-stream") {
		pr, pw := io.Pipe()
		extractor := NewStreamingTokenExtractor(resp.Body, pw, model)
		extractor.usageHandler = usageHandler
		extractor.clientRequestedUsage = clientRequestedUsage
		go extractor.processStream()
		return pr, nil
	}

	// For non-JSON or non-200 responses, pass through unchanged
	if resp.StatusCode != http.StatusOK || !strings.Contains(contentType, "application/json") {
		return resp.Body, nil
	}

	// For JSON responses, tee the body to the client while accumulating a copy
	// for usage extraction on Close(). This retains the full response in memory,
	// matching the router extractor's existing behavior.
	extractor := &JSONTokenExtractor{
		model: model,
	}

	// TeeReader copies data to the extractor while passing it through to
	// the client unchanged.
	teeReader := io.TeeReader(resp.Body, extractor)

	// Return a custom closer that logs tokens when closed
	return &teeReaderCloser{
		Reader:       teeReader,
		origBody:     resp.Body,
		extractor:    extractor,
		usageHandler: usageHandler,
	}, nil
}

// maxSSELineBytes bounds a single SSE line; mirrors the tool runtime's
// sseReader limit so large frames survive both parsers.
const maxSSELineBytes = 1 << 22 // 4 MiB

// StreamingTokenExtractor handles token extraction for streaming responses
type StreamingTokenExtractor struct {
	reader               io.ReadCloser
	writer               io.WriteCloser
	model                string
	usage                *Usage
	buffer               bytes.Buffer
	scanner              *bufio.Scanner
	completed            bool
	usageHandler         func(*Usage) // Callback for when usage is extracted
	clientRequestedUsage bool         // Whether client explicitly requested usage stats
}

// NewStreamingTokenExtractor creates a new streaming token extractor that intercepts SSE chunks
func NewStreamingTokenExtractor(reader io.ReadCloser, writer io.WriteCloser, model string) *StreamingTokenExtractor {
	s := &StreamingTokenExtractor{
		reader: reader,
		writer: writer,
		model:  model,
		usage:  &Usage{},
	}
	s.scanner = bufio.NewScanner(reader)
	// Single SSE lines can exceed bufio's 64KiB default (for example a large
	// tool-call argument blob in one chunk), which would abort the stream
	// with ErrTooLong and surface as a silent truncation to the client.
	s.scanner.Buffer(make([]byte, 0, 64*1024), maxSSELineBytes)
	return s
}

// processStream processes the SSE stream, extracting token usage. It reads
// lines from the upstream, writes them to the downstream pipe, and parses
// usage data from SSE chunks. The usage handler is always invoked when the
// stream ends (normally, on client disconnect, or on scanner error) so that
// a billing event is emitted even if no usage data was collected — this
// prevents billing bypass via early disconnect.
func (s *StreamingTokenExtractor) processStream() {
	defer s.writer.Close()
	defer s.reader.Close()

	lastLineWasFiltered := false
	terminalEventPending := false
	terminalResponseEvent := false
	eventHasData := false

	for s.scanner.Scan() {
		line := s.scanner.Text()
		shouldWrite := true
		if strings.HasPrefix(line, "event:") {
			eventType := strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			terminalResponseEvent = isTerminalResponseEvent(eventType)
		}

		// If the previous line was filtered and this is an empty line, skip it
		// to avoid consecutive empty lines in the output
		if lastLineWasFiltered && line == "" {
			lastLineWasFiltered = false
			terminalEventPending = false
			terminalResponseEvent = false
			eventHasData = false
			continue
		}

		lastLineWasFiltered = false

		// Parse SSE data lines
		if strings.HasPrefix(line, "data:") {
			eventHasData = true
			data := strings.TrimPrefix(line, "data:")
			data = strings.TrimPrefix(data, " ")
			if data == "[DONE]" {
				terminalEventPending = true
			} else {
				// Try to parse the chunk
				var chunk map[string]interface{}
				if err := json.Unmarshal([]byte(data), &chunk); err == nil {
					if eventType, ok := chunk["type"].(string); ok && isTerminalResponseEvent(eventType) {
						terminalEventPending = true
					}
					// Check for usage in the chunk (Chat Completions API)
					// or nested under "response" (Responses API streaming)
					usageData, ok := chunk["usage"]
					if !ok || usageData == nil {
						if respObj, rOk := chunk["response"].(map[string]interface{}); rOk {
							usageData, ok = respObj["usage"]
						}
					}
					if ok && usageData != nil {
						usageBytes, _ := json.Marshal(usageData)
						var usage Usage
						if err := json.Unmarshal(usageBytes, &usage); err == nil {
							usage.Normalize()
							// Update usage data (continuous stats may send incremental updates)
							if usage.PromptTokens > 0 {
								s.usage.PromptTokens = usage.PromptTokens
							}
							if usage.CompletionTokens > 0 {
								s.usage.CompletionTokens = usage.CompletionTokens
							}
							if usage.TotalTokens > 0 {
								s.usage.TotalTokens = usage.TotalTokens
							}
							if usage.PromptTokensDetails != nil {
								s.usage.PromptTokensDetails = usage.PromptTokensDetails
							}
						}

						// Check if this is a usage-only chunk that should be filtered
						if !s.clientRequestedUsage {
							// Check if choices array exists and is empty
							if choices, hasChoices := chunk["choices"].([]interface{}); hasChoices && len(choices) == 0 {
								// This is a usage-only chunk with empty choices array
								// Filter it out since client didn't request usage
								shouldWrite = false
								lastLineWasFiltered = true
							}
						}
					}
				}
			}
		}

		// Write the line to output if we should. If the downstream client
		// has closed the connection, stop reading the upstream so the
		// deferred reader.Close() runs promptly.
		if shouldWrite {
			var writeErr error
			if line == "" {
				_, writeErr = s.writer.Write([]byte("\n"))
			} else {
				_, writeErr = s.writer.Write([]byte(line + "\n"))
			}
			if writeErr != nil {
				break
			}
		}

		if line == "" {
			if (terminalEventPending || terminalResponseEvent) && eventHasData {
				break
			}
			terminalEventPending = false
			terminalResponseEvent = false
			eventHasData = false
		}
	}

	// Surface scanner errors (e.g. bufio.ErrTooLong) so they are not
	// silently swallowed. The downstream client already received whatever
	// was written before the error; the pipe closes cleanly via the
	// deferred writer.Close().
	if err := s.scanner.Err(); err != nil {
		log.Printf("tokencount: streaming scanner error (truncated response): %v", err)
	}

	// Always invoke the usage handler so a billing event is emitted even
	// when the stream was truncated or the client disconnected before any
	// usage chunk arrived. Without this, a client could avoid billing by
	// disconnecting early. The handler receives zero values when no usage
	// data was collected, which the billing layer records as a zero-token
	// event (equivalent to the billingCloser fallback for non-streaming).
	if s.usageHandler != nil {
		if s.usage.TotalTokens == 0 {
			s.usage.TotalTokens = s.usage.PromptTokens + s.usage.CompletionTokens
		}
		s.usageHandler(s.usage)
	}

	s.completed = true
}

func isTerminalResponseEvent(eventType string) bool {
	switch eventType {
	case "response.completed", "response.failed", "response.incomplete", "error":
		return true
	default:
		return false
	}
}

// Read implements io.Reader for compatibility
func (s *StreamingTokenExtractor) Read(p []byte) (n int, err error) {
	// This is mainly for compatibility - actual processing happens in processStream
	return s.buffer.Read(p)
}
