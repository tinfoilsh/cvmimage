package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"

	"log"
)

// addPaddingToStreamChunk adds a random padding field to the delta object in a streaming chunk
// without parsing the entire response structure
func addPaddingToStreamChunk(data string) (string, error) {
	var rawJSON map[string]interface{}
	if err := json.Unmarshal([]byte(data), &rawJSON); err != nil {
		return data, err
	}

	// Check if this chunk has choices with delta
	choices, ok := rawJSON["choices"].([]interface{})
	if !ok || len(choices) == 0 {
		return data, nil
	}

	// Get the first choice
	firstChoice, ok := choices[0].(map[string]interface{})
	if !ok {
		return data, nil
	}

	// Get the delta object
	delta, ok := firstChoice["delta"].(map[string]interface{})
	if !ok {
		return data, nil
	}

	// Generate random padding
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	minLength := 4
	maxLength := len(charset)
	r, err := rand.Int(rand.Reader, big.NewInt(int64(maxLength-minLength+1)))
	if err != nil {
		return data, err
	}
	padding := charset[:minLength+int(r.Int64())]

	// Add padding field to delta
	delta["p"] = padding

	// Marshal back to JSON
	modified, err := json.Marshal(rawJSON)
	if err != nil {
		return data, err
	}

	return string(modified), nil
}

// unsafeRequestFields are vLLM-specific request fields that allow callers to
// supply Jinja templates or processor kwargs. Stripping them keeps the
// upstream's template-rendering surface limited to operator-shipped templates.
var unsafeRequestFields = []string{
	"chat_template",
	"chat_template_kwargs",
	"mm_processor_kwargs",
	"guided_decoding_backend",
}

func stripUnsafeRequestFields(body []byte) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	changed := false
	for _, k := range unsafeRequestFields {
		if _, ok := m[k]; ok {
			delete(m, k)
			changed = true
		}
	}
	if !changed {
		return body, nil
	}
	return json.Marshal(m)
}

type chatRequest struct {
	Model    string `json:"model"`
	Stream   bool   `json:"stream"`
	Messages []struct {
		Role    string `json:"role"`
		Content any    `json:"content"` // String or array of content parts
	} `json:"messages"`
}

type streamTransport struct {
	base http.RoundTripper
}

func (t *streamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path != "/v1/chat/completions" {
		return t.base.RoundTrip(req)
	}

	var cr chatRequest

	if req.Body == nil {
		resp := &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(bytes.NewReader([]byte("chat completions request body is empty"))),
		}
		return resp, nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}
	if err := json.Unmarshal(body, &cr); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request body: %w", err)
	}
	body, err = stripUnsafeRequestFields(body)
	if err != nil {
		return nil, fmt.Errorf("failed to sanitise request body: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	// Make the actual request
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if !cr.Stream {
		return resp, nil
	}

	// SSE headers
	resp.Header.Set("Cache-Control", "no-cache")
	resp.Header.Set("Connection", "keep-alive")
	resp.Header.Del("Content-Length")

	// Create a pipe to modify the response stream
	pr, pw := io.Pipe()
	originalBody := resp.Body
	resp.Body = pr

	go func() {
		defer originalBody.Close()
		defer pw.Close()

		scanner := bufio.NewScanner(originalBody)
		scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") && line != "data: [DONE]" {
				data := strings.TrimPrefix(line, "data: ")
				modifiedData, err := addPaddingToStreamChunk(data)
				if err != nil {
					log.Printf("Warning: failed to add padding to chunk: %v", err)
					pw.Write([]byte(line + "\n"))
					continue
				}
				pw.Write([]byte("data: " + modifiedData + "\n"))
			} else {
				pw.Write([]byte(line + "\n"))
			}
		}

	}()

	return resp, nil
}
