package ecrregistry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testHost = "123456789012.dkr.ecr.us-east-1.amazonaws.com"

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(status int, value string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(value))}
}

func credentialsJSON(t *testing.T, host, password string, expiry time.Time) string {
	t.Helper()
	data, err := json.Marshal(Credentials{Host: host, Username: "AWS", Password: password, ExpiresAt: expiry})
	require.NoError(t, err)
	return string(data)
}

func TestConfigureLoadAndClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", ConfigFileName)
	config, err := Load(path)
	require.NoError(t, err)
	require.Nil(t, config)
	value := fmt.Sprintf(`{"host":%q,"org_id":"org_test","token":"refresh-secret"}`, testHost)
	require.NoError(t, Configure(path, value))
	config, err = Load(path)
	require.NoError(t, err)
	require.Equal(t, &Config{Host: testHost, OrgID: "org_test", Token: "refresh-secret"}, config)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	require.NoError(t, Configure(path, ""))
	config, err = Load(path)
	require.NoError(t, err)
	require.Nil(t, config)
	for _, value := range []string{"{private-key", `{}`, strings.Repeat("x", maxConfigBytes+1), strings.Replace(value, testHost, "evil.example", 1)} {
		require.Error(t, Configure(path, value))
		_, err := os.Stat(path)
		require.ErrorIs(t, err, os.ErrNotExist)
	}
	require.NoError(t, os.WriteFile(path, []byte("{private-key"), 0600))
	_, err = Load(path)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "private-key")
}

func TestRefreshUsesFixedEndpointAndFreshCredentialsEveryTime(t *testing.T) {
	config := &Config{Host: testHost, OrgID: "org_test", Token: "refresh-secret"}
	calls := 0
	transport := transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		require.Equal(t, refreshURL, r.URL.String())
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer refresh-secret", r.Header.Get("Authorization"))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.JSONEq(t, fmt.Sprintf(`{"org_id":"org_test","host":%q}`, testHost), string(body))
		require.NotContains(t, string(body), config.Token)
		return response(http.StatusOK, credentialsJSON(t, testHost, fmt.Sprintf("password-%d", calls), time.Now().Add(12*time.Hour))), nil
	})
	first, err := config.Fetch(context.Background(), transport)
	require.NoError(t, err)
	second, err := config.Fetch(context.Background(), transport)
	require.NoError(t, err)
	require.NotEqual(t, first.Password, second.Password)
	require.Equal(t, 2, calls)
}

func TestRefreshRejectsUnsafeOrExpiredResponses(t *testing.T) {
	config := &Config{Host: testHost, OrgID: "org_test", Token: "refresh-secret"}
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"revoked", http.StatusUnauthorized, "sensitive-server-error"},
		{"forbidden", http.StatusForbidden, "sensitive-server-error"},
		{"invalid JSON", http.StatusOK, "sensitive-server-error"},
		{"wrong host", http.StatusOK, credentialsJSON(t, "evil.example", "secret-password", time.Now().Add(time.Hour))},
		{"expired", http.StatusOK, credentialsJSON(t, testHost, "secret-password", time.Now().Add(-time.Hour))},
		{"nearly expired", http.StatusOK, credentialsJSON(t, testHost, "secret-password", time.Now().Add(time.Minute))},
		{"empty password", http.StatusOK, credentialsJSON(t, testHost, "", time.Now().Add(time.Hour))},
		{"oversized", http.StatusOK, strings.Repeat("x", maxResponseBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			result, err := config.Fetch(context.Background(), transportFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return response(tc.status, tc.body), nil
			}))
			require.Error(t, err)
			require.Nil(t, result)
			require.Equal(t, 1, calls)
			require.NotContains(t, err.Error(), "secret-password")
			require.NotContains(t, err.Error(), "sensitive-server-error")
		})
	}
}

func TestRefreshDoesNotForwardCredentialsOnRedirect(t *testing.T) {
	calls := 0
	config := &Config{Host: testHost, OrgID: "org_test", Token: "refresh-secret"}
	_, err := config.Fetch(context.Background(), transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		require.Equal(t, refreshURL, r.URL.String())
		result := response(http.StatusTemporaryRedirect, "")
		result.Header.Set("Location", "https://evil.example")
		return result, nil
	}))
	require.Error(t, err)
	require.Equal(t, 1, calls)
}

func TestRefreshRetriesTransientFailuresAndHonorsCancellation(t *testing.T) {
	config := &Config{Host: testHost, OrgID: "org_test", Token: "refresh-secret"}
	calls := 0
	auth, err := config.Fetch(context.Background(), transportFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(http.StatusServiceUnavailable, "private failure"), nil
		}
		return response(http.StatusOK, credentialsJSON(t, testHost, "fresh", time.Now().Add(time.Hour))), nil
	}))
	require.NoError(t, err)
	require.Equal(t, "fresh", auth.Password)
	require.Equal(t, 2, calls)
	ctx, cancel := context.WithCancel(context.Background())
	_, err = config.Fetch(ctx, transportFunc(func(*http.Request) (*http.Response, error) {
		cancel()
		return nil, errors.New("refresh-secret must not leak")
	}))
	require.ErrorIs(t, err, context.Canceled)
}
