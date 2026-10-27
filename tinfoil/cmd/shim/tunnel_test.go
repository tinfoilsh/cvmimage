package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConnectDisabled(t *testing.T) {
	for name, handler := range map[string]http.Handler{
		"shim":          testFullServer(t, 9999),
		"observability": testObservabilityServer(t),
	} {
		for _, major := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s/http%d", name, major), func(t *testing.T) {
				req := httptest.NewRequest(http.MethodConnect, "https://cvm.example:2300", nil)
				req.ProtoMajor = major
				req.ProtoMinor = 0
				req.Proto = fmt.Sprintf("HTTP/%d.0", major)
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, req)
				if recorder.Code != http.StatusMethodNotAllowed {
					t.Fatalf("CONNECT status = %d, want 405", recorder.Code)
				}
			})
		}
	}
}
