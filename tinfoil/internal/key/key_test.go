package key

import (
	"errors"
	"net/http"
	"testing"
)

type stubValidator struct {
	result Result
	err    error
	called *int
}

func (s stubValidator) Validate(Request) (Result, error) {
	if s.called != nil {
		*s.called++
	}
	return s.result, s.err
}

func TestChainFallsThroughOnUnsupported(t *testing.T) {
	var firstCalls, secondCalls int
	chain := NewChain(
		stubValidator{err: ErrUnsupportedToken, called: &firstCalls},
		stubValidator{err: nil, called: &secondCalls},
	)
	if _, err := chain.Validate(Request{APIKey: "x"}); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if firstCalls != 1 || secondCalls != 1 {
		t.Fatalf("calls: first=%d second=%d", firstCalls, secondCalls)
	}
}

func TestChainReturnsValidationErrorImmediately(t *testing.T) {
	var secondCalls int
	chain := NewChain(
		stubValidator{err: &ValidationError{StatusCode: http.StatusUnauthorized}},
		stubValidator{err: nil, called: &secondCalls},
	)
	_, err := chain.Validate(Request{APIKey: "x"})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 ValidationError, got %v", err)
	}
	if secondCalls != 0 {
		t.Fatalf("second validator should not be consulted, calls=%d", secondCalls)
	}
}

func TestChainShortCircuitsOnSuccess(t *testing.T) {
	var secondCalls int
	chain := NewChain(
		stubValidator{err: nil},
		stubValidator{err: ErrUnsupportedToken, called: &secondCalls},
	)
	if _, err := chain.Validate(Request{APIKey: "x"}); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if secondCalls != 0 {
		t.Fatalf("second validator should not be consulted, calls=%d", secondCalls)
	}
}

// TestChainPropagatesSubject verifies the Result from the validator that
// handled the request (here the second, after the first falls through) is
// returned to the caller, so the shim can forward the verified subject.
func TestChainPropagatesSubject(t *testing.T) {
	chain := NewChain(
		stubValidator{err: ErrUnsupportedToken},
		stubValidator{result: Result{Subject: "user_42"}, err: nil},
	)
	res, err := chain.Validate(Request{APIKey: "x"})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if res.Subject != "user_42" {
		t.Fatalf("Subject = %q, want user_42", res.Subject)
	}
}
