package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"mime"
	"net/http"
	"strings"
	"sync"

	"log"
)

const (
	initialSSEBufferSize = 64 * 1024
	maxSSELineBytes      = 4 * 1024 * 1024
)

// isEventStreamContentType reports whether the Content-Type header identifies
// an SSE response, ignoring parameters such as charset.
func isEventStreamContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mediaType == "text/event-stream"
}

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

type streamTransport struct {
	base http.RoundTripper
}

type closeOnceReadCloser struct {
	io.ReadCloser
	once sync.Once
	err  error
}

func (c *closeOnceReadCloser) Close() error {
	c.once.Do(func() {
		c.err = c.ReadCloser.Close()
	})
	return c.err
}

type streamResponseBody struct {
	*io.PipeReader
	upstream io.Closer
}

func (b *streamResponseBody) Close() error {
	return errors.Join(b.PipeReader.Close(), b.upstream.Close())
}

func (t *streamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path != "/v1/chat/completions" {
		return t.base.RoundTrip(req)
	}

	// Make the actual request
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if !isEventStreamContentType(resp.Header.Get("Content-Type")) {
		return resp, nil
	}

	// SSE headers
	resp.Header.Set("Cache-Control", "no-cache")
	resp.Header.Set("Connection", "keep-alive")
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1

	// Create a pipe to modify the response stream
	pr, pw := io.Pipe()
	originalBody := &closeOnceReadCloser{ReadCloser: resp.Body}
	resp.Body = &streamResponseBody{PipeReader: pr, upstream: originalBody}

	go func() {
		defer originalBody.Close()

		scanner := bufio.NewScanner(originalBody)
		scanner.Buffer(make([]byte, 0, initialSSEBufferSize), maxSSELineBytes)
		for scanner.Scan() {
			line := scanner.Text()
			out := line + "\n"
			if strings.HasPrefix(line, "data: ") && line != "data: [DONE]" {
				data := strings.TrimPrefix(line, "data: ")
				modifiedData, err := addPaddingToStreamChunk(data)
				if err != nil {
					log.Printf("Warning: failed to add padding to chunk: %v", err)
				} else {
					out = "data: " + modifiedData + "\n"
				}
			}
			if _, err := io.WriteString(pw, out); err != nil {
				pw.CloseWithError(err)
				return
			}
		}
		if err := scanner.Err(); err != nil {
			pw.CloseWithError(err)
			return
		}
		pw.Close()
	}()

	return resp, nil
}
