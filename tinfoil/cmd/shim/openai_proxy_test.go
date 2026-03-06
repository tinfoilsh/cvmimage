package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAddPaddingToStreamChunk(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldError bool
		validate    func(t *testing.T, output string)
	}{
		{
			name:  "typical streaming chunk with null finish_reason",
			input: `{"id":"chatcmpl-123","object":"chat.completion.chunk","created":1234567890,"model":"deepseek-r1-70b","choices":[{"index":0,"delta":{"role":"assistant","content":"Hello"},"finish_reason":null}]}`,
			validate: func(t *testing.T, output string) {
				var result map[string]interface{}
				if err := json.Unmarshal([]byte(output), &result); err != nil {
					t.Fatalf("Failed to unmarshal output: %v", err)
				}

				// Check that finish_reason is still null
				choices := result["choices"].([]interface{})
				choice := choices[0].(map[string]interface{})
				if choice["finish_reason"] != nil {
					t.Errorf("Expected finish_reason to be null, got %v", choice["finish_reason"])
				}

				// Check that padding was added
				delta := choice["delta"].(map[string]interface{})
				padding, ok := delta["p"].(string)
				if !ok {
					t.Error("Expected padding field 'p' to be added to delta")
				}
				if len(padding) < 4 || len(padding) > 36 {
					t.Errorf("Padding length should be between 4 and 36, got %d", len(padding))
				}

				// Verify padding contains only allowed characters
				allowedChars := "abcdefghijklmnopqrstuvwxyz0123456789"
				for _, char := range padding {
					if !strings.ContainsRune(allowedChars, char) {
						t.Errorf("Invalid character in padding: %c", char)
					}
				}

				// Check that other fields are preserved
				if result["id"] != "chatcmpl-123" {
					t.Error("ID field was not preserved")
				}
				if delta["content"] != "Hello" {
					t.Error("Content field was not preserved")
				}
			},
		},
		{
		name:  "chunk with empty string finish_reason",
		input: `{"id":"chatcmpl-456","choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":""}]}`,
		validate: func(t *testing.T, output string) {
			var result map[string]interface{}
			if err := json.Unmarshal([]byte(output), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			choices := result["choices"].([]interface{})
				choice := choices[0].(map[string]interface{})

				// Empty string should be preserved
				if choice["finish_reason"] != "" {
					t.Errorf("Expected finish_reason to be empty string, got %v", choice["finish_reason"])
				}
			},
		},
		{
		name:  "chunk with stop finish_reason",
		input: `{"id":"chatcmpl-789","choices":[{"index":0,"delta":{"content":""},"finish_reason":"stop"}]}`,
		validate: func(t *testing.T, output string) {
			var result map[string]interface{}
			if err := json.Unmarshal([]byte(output), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			choices := result["choices"].([]interface{})
				choice := choices[0].(map[string]interface{})

				// stop should be preserved
				if choice["finish_reason"] != "stop" {
					t.Errorf("Expected finish_reason to be 'stop', got %v", choice["finish_reason"])
				}
			},
		},
		{
			name:  "chunk without choices",
			input: `{"id":"chatcmpl-end","choices":[]}`,
			validate: func(t *testing.T, output string) {
				// Should return unchanged
				if output != `{"id":"chatcmpl-end","choices":[]}` {
					t.Error("Expected output to be unchanged when no choices")
				}
			},
		},
		{
		name:  "chunk without delta",
		input: `{"id":"chatcmpl-nodelta","choices":[{"index":0,"message":{"content":"test"}}]}`,
		validate: func(t *testing.T, output string) {
			// Should return unchanged when no delta
			var result map[string]interface{}
			if err := json.Unmarshal([]byte(output), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			choices := result["choices"].([]interface{})
				choice := choices[0].(map[string]interface{})

				if _, hasDelta := choice["delta"]; hasDelta {
					t.Error("Should not have delta field")
				}
			},
		},
		{
			name:        "invalid JSON",
			input:       `{"invalid": json}`,
			shouldError: true,
		},
		{
		name:  "complex nested structure preservation",
		input: `{"id":"complex","choices":[{"index":0,"delta":{"role":"assistant","content":"Test","tool_calls":[{"id":"call_123","type":"function","function":{"name":"test","arguments":"{}"}}]},"finish_reason":null,"logprobs":{"content":[{"token":"Test","logprob":-0.5}]}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`,
		validate: func(t *testing.T, output string) {
			var result map[string]interface{}
			if err := json.Unmarshal([]byte(output), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			// Check that complex nested structures are preserved
				choices := result["choices"].([]interface{})
				choice := choices[0].(map[string]interface{})
				delta := choice["delta"].(map[string]interface{})

				// Check tool_calls preservation
				toolCalls, ok := delta["tool_calls"].([]interface{})
				if !ok || len(toolCalls) != 1 {
					t.Error("tool_calls not preserved correctly")
				}

				// Check logprobs preservation
				_, ok = choice["logprobs"].(map[string]interface{})
				if !ok {
					t.Error("logprobs not preserved")
				}

				// Check usage preservation
				usage, ok := result["usage"].(map[string]interface{})
				if !ok || usage["total_tokens"] != float64(15) {
					t.Error("usage not preserved correctly")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := addPaddingToStreamChunk(tt.input)

			if tt.shouldError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if tt.validate != nil {
				tt.validate(t, output)
			}
		})
	}
}
