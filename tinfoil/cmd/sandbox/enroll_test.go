package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestOwnershipCanOnlyBeClaimedOnce(t *testing.T) {
	box, _ := testSandbox(t)
	start := make(chan struct{})
	winners := make(chan string, 32)
	var group sync.WaitGroup
	for i := range 32 {
		group.Go(func() {
			<-start
			owner := fmt.Sprintf("owner-%d", i)
			if box.claim(owner) == nil {
				winners <- owner
			}
		})
	}
	close(start)
	group.Wait()
	close(winners)
	var claimed []string
	for owner := range winners {
		claimed = append(claimed, owner)
	}
	if len(claimed) != 1 || box.ownerKey() != claimed[0] {
		t.Fatalf("owners = %v, stored = %q", claimed, box.ownerKey())
	}
	if err := box.claim("replacement"); err == nil {
		t.Fatal("replaced the enrolled owner")
	}
}

func TestEnrollmentRefusesSecondOwner(t *testing.T) {
	box, key := testSandbox(t)
	if err := box.claim("original owner"); err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshKey, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{
		"key":    string(ssh.MarshalAuthorizedKey(sshKey)),
		"volume": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, volumeKeyBytes)),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+signPermit(t, key, "ES256", testClaims()))
	response := httptest.NewRecorder()
	box.handler().ServeHTTP(response, request)
	if response.Code != http.StatusConflict || box.ownerKey() != "original owner" {
		t.Fatalf("status = %d, owner = %q", response.Code, box.ownerKey())
	}
	response = httptest.NewRecorder()
	box.handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var health struct {
		Enrolled bool
		SSH      struct{ Listening bool }
	}
	if err := json.Unmarshal(response.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if !health.Enrolled || health.SSH.Listening {
		t.Fatalf("health = %+v", health)
	}
}

type unreadBody struct{ read bool }

func (b *unreadBody) Read([]byte) (int, error) {
	b.read = true
	return 0, errors.New("body must not be read")
}

func TestEnrollmentChecksPermitBeforeReadingBody(t *testing.T) {
	box, _ := testSandbox(t)
	for _, authorization := range []string{"", "Bearer invalid"} {
		body := &unreadBody{}
		request := httptest.NewRequest(http.MethodPost, "/enroll", body)
		request.Header.Set("Authorization", authorization)
		response := httptest.NewRecorder()
		box.handler().ServeHTTP(response, request)
		if body.read || box.ownerKey() != "" {
			t.Fatal("unauthorized enrollment read the body or claimed ownership")
		}
		if response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden {
			t.Fatalf("status = %d", response.Code)
		}
	}
}

func TestInvalidEnrollmentLeavesOwnershipUnclaimed(t *testing.T) {
	box, key := testSandbox(t)
	token := signPermit(t, key, "ES256", testClaims())
	for _, body := range []string{"not json", `{}`, `{"key":"invalid","volume":"invalid"}`} {
		request := httptest.NewRequest(http.MethodPost, "/enroll", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		box.handler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || box.ownerKey() != "" {
			t.Fatalf("status = %d, owner = %q", response.Code, box.ownerKey())
		}
	}
}

func TestEnrollmentRetryAndSSHFailureKeepOwnershipConsistent(t *testing.T) {
	for _, sshFails := range []bool{false, true} {
		box, key := testSandbox(t)
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		sshKey, err := ssh.NewPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		owner := string(ssh.MarshalAuthorizedKey(sshKey))
		body, _ := json.Marshal(map[string]string{"key": owner, "volume": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, volumeKeyBytes))})
		opens, starts := 0, 0
		var spent []byte
		box.openWorkspace = func(volumeKey []byte, line string) error {
			opens++
			if line != owner {
				t.Fatal("owner changed before volume seal")
			}
			if opens == 1 {
				return errors.New("wrong volume key")
			}
			spent = volumeKey
			return nil
		}
		box.startSSH = func(line string) error {
			starts++
			if box.ownerKey() != owner || line != owner {
				t.Fatal("SSH started before owner claim")
			}
			if sshFails {
				return errors.New("sshd failed")
			}
			return nil
		}
		enroll := func() int {
			req := httptest.NewRequest("POST", "/enroll", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+signPermit(t, key, "ES256", testClaims()))
			res := httptest.NewRecorder()
			box.handler().ServeHTTP(res, req)
			return res.Code
		}
		if status := enroll(); status != http.StatusForbidden || box.ownerKey() != "" || starts != 0 {
			t.Fatalf("failed unlock status=%d", status)
		}
		expected := http.StatusNoContent
		if sshFails {
			expected = http.StatusServiceUnavailable
		}
		if status := enroll(); status != expected || box.ownerKey() != owner {
			t.Fatalf("enrollment status=%d", status)
		}
		if !bytes.Equal(spent, make([]byte, volumeKeyBytes)) {
			t.Fatal("workspace key not cleared")
		}
		if status := enroll(); status != http.StatusConflict || opens != 2 || starts != 1 {
			t.Fatalf("replay status=%d opens=%d starts=%d", status, opens, starts)
		}
	}
}

func TestAuthorizedKeyRequiresOneCompletePublicKey(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	line := string(ssh.MarshalAuthorizedKey(key))
	if canonical, err := authorizedKey(strings.TrimSpace(line) + " comment\n"); err != nil || canonical != line {
		t.Fatalf("canonical key: %q %v", canonical, err)
	}
	for _, invalid := range []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5", line + line, "command=\"sh\" " + line} {
		if _, err := authorizedKey(invalid); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
}
