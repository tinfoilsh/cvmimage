package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

const (
	volumeKeyBytes = 64
	maxEnrollBytes = 1 << 12
)

func (s *sandbox) enroll(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		reply(w, http.StatusUnauthorized, failure{"missing permit"})
		return
	}
	if err := s.check(token); err != nil {
		log.Printf("permit refused: %v", err)
		reply(w, http.StatusForbidden, failure{"permit refused"})
		return
	}
	var body struct {
		Key    string `json:"key"`
		Volume string `json:"volume"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxEnrollBytes)).Decode(&body); err != nil {
		reply(w, http.StatusBadRequest, failure{"enrollment is not a JSON object naming a key"})
		return
	}
	volumeKey, err := workspaceKey(body.Volume)
	if err != nil {
		log.Printf("enrollment refused: %v", err)
		reply(w, http.StatusBadRequest, failure{"volume is not base64 for a 64-byte workspace key"})
		return
	}
	defer clear(volumeKey)
	line, err := authorizedKey(body.Key)
	if err != nil {
		log.Printf("enrollment refused: %v", err)
		reply(w, http.StatusBadRequest, failure{"key is not one SSH public key"})
		return
	}
	// Only one request may open the workspace and claim ownership at a time.
	s.enrolling.Lock()
	defer s.enrolling.Unlock()
	if s.ownerKey() != "" {
		log.Printf("enrollment refused: an owner is already enrolled for this boot")
		reply(w, http.StatusConflict, failure{"sandbox is already enrolled"})
		return
	}
	if err := s.open(volumeKey, line); err != nil {
		log.Printf("workspace refused the key: %v", err)
		reply(w, http.StatusForbidden, failure{"workspace key refused"})
		return
	}
	if err := os.Mkdir(home, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		log.Printf("workspace provisioning failed: %v", err)
		reply(w, http.StatusInternalServerError, failure{"workspace could not be provisioned"})
		return
	}
	if err := s.claim(line); err != nil {
		log.Printf("enrollment refused: %v", err)
		reply(w, http.StatusConflict, failure{"sandbox is already enrolled"})
		return
	}

	// Ownership is committed before SSH starts. A start failure does not reopen enrollment.
	if err := s.seal(line); err != nil {
		log.Printf("ssh seal failed: %v", err)
	}
	log.Printf("sandbox %s enrolled an owner for boot %s", s.domain, s.nonce)
	w.WriteHeader(http.StatusNoContent)
}

func workspaceKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, err
	}
	if len(key) != volumeKeyBytes {
		clear(key)
		return nil, fmt.Errorf("workspace key is %d bytes, want %d", len(key), volumeKeyBytes)
	}
	return key, nil
}

func (s *sandbox) claim(owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner != "" {
		return errors.New("an owner is already enrolled for this boot")
	}
	s.owner = owner
	return nil
}

func (s *sandbox) ownerKey() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.owner
}
