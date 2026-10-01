package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"tinfoil/internal/trustedtime"
)

func TestTrustedTimeGateClosesAfterSynchronizationLoss(t *testing.T) {
	var clockErr error
	requests := 0
	handler := checkTrustedTime(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusNoContent)
	}), func() (trustedtime.Sample, error) {
		return trustedtime.Sample{}, clockErr
	})
	for _, test := range []struct {
		err      error
		status   int
		requests int
	}{
		{nil, http.StatusNoContent, 1},
		{errors.New("checkpoint expired"), http.StatusServiceUnavailable, 1},
		{errors.New("clock stepped"), http.StatusServiceUnavailable, 1},
	} {
		clockErr = test.err
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
		if response.Code != test.status || requests != test.requests {
			t.Fatalf("status=%d forwarded=%d; want %d, %d", response.Code, requests, test.status, test.requests)
		}
	}
}
