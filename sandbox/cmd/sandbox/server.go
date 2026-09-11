package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"log"
	"net/http"
	"sync"
)

type sandbox struct {
	domain      string
	permit      *ecdsa.PublicKey
	nonce       string
	volume      volume
	fingerprint string

	mu        sync.Mutex
	owner     string
	listening bool
	enrolling sync.Mutex
}

type failure struct {
	Error string `json:"error"`
}

func (s *sandbox) handler() http.Handler {
	mux := http.NewServeMux()
	// Enrollment permits need this boot nonce before a caller can authenticate.
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /enroll", s.enroll)
	return mux
}

func (s *sandbox) health(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	enrolled, listening := s.owner != "", s.listening
	s.mu.Unlock()
	reply(w, http.StatusOK, map[string]any{
		"domain":   s.domain,
		"nonce":    s.nonce,
		"enrolled": enrolled,
		"ssh": map[string]any{
			"port":      sshPort,
			"user":      loginUser,
			"host-key":  s.fingerprint,
			"listening": listening,
		},
	})
}

func reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("response failed: %v", err)
	}
}
