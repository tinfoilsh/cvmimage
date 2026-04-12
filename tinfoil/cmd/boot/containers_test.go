package main

import (
	"testing"
	"time"

	shimconfig "tinfoil/internal/config"
)

func TestParseGPUs(t *testing.T) {
	tests := []struct {
		name      string
		input     interface{}
		wantNil   bool
		wantCount int
		wantIDs   []string
	}{
		{"nil", nil, true, 0, nil},
		{"false", false, true, 0, nil},
		{"true", true, false, -1, nil},
		{"all", "all", false, -1, nil},
		{"specific ids", "0,1,2", false, 0, []string{"0", "1", "2"}},
		{"int count", 4, false, 4, nil},
		{"float count", float64(8), false, 8, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := parseGPUs(tt.input)
			if tt.wantNil {
				if req != nil {
					t.Fatalf("expected nil, got %+v", req)
				}
				return
			}
			if req == nil {
				t.Fatal("expected non-nil DeviceRequest")
			}
			if req.Count != tt.wantCount {
				t.Errorf("count: got %d, want %d", req.Count, tt.wantCount)
			}
			if tt.wantIDs != nil {
				if len(req.DeviceIDs) != len(tt.wantIDs) {
					t.Fatalf("device IDs: got %v, want %v", req.DeviceIDs, tt.wantIDs)
				}
				for i, id := range req.DeviceIDs {
					if id != tt.wantIDs[i] {
						t.Errorf("device ID[%d]: got %q, want %q", i, id, tt.wantIDs[i])
					}
				}
			}
		})
	}
}

func TestBuildEnv(t *testing.T) {
	ext := &shimconfig.ExternalConfig{
		Env:     map[string]string{"DOMAIN": "test.example.com", "PORT": "8080"},
		Secrets: map[string]string{"API_KEY": "sk-123", "DB_PASS": "secret"},
	}

	env := buildEnv(
		[]interface{}{
			"DOMAIN",
			map[string]interface{}{"STATIC": "value"},
			"MISSING_KEY",
		},
		[]string{"API_KEY", "MISSING_SECRET"},
		ext,
	)

	want := map[string]bool{
		"DOMAIN=test.example.com": true,
		"STATIC=value":            true,
		"API_KEY=sk-123":          true,
	}
	for _, e := range env {
		if !want[e] {
			t.Errorf("unexpected env entry: %s", e)
		}
		delete(want, e)
	}
	for k := range want {
		t.Errorf("missing env entry: %s", k)
	}
}

func TestBuildEnvNilConfig(t *testing.T) {
	ext := &shimconfig.ExternalConfig{}
	env := buildEnv([]interface{}{"FOO"}, []string{"BAR"}, ext)
	if len(env) != 0 {
		t.Errorf("expected empty env with nil maps, got %v", env)
	}
}

func TestValidateContainers(t *testing.T) {
	const goodImage = "ghcr.io/tinfoilsh/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tests := []struct {
		name      string
		c         Container
		debugMode bool
		wantErr   bool
	}{
		{"digest-pinned ok", Container{Name: "ok", Image: goodImage}, false, false},
		{"tag-only image rejected", Container{Name: "bad", Image: "alpine:latest"}, false, true},
		{"short digest rejected", Container{Name: "bad", Image: "alpine@sha256:deadbeef"}, false, true},
		{"missing image rejected", Container{Name: "bad"}, false, true},
		{"pid host rejected", Container{Name: "x", Image: goodImage, PidMode: "host"}, false, true},
		{"pid host allowed in debug", Container{Name: "x", Image: goodImage, PidMode: "host"}, true, false},
		{"ipc host rejected", Container{Name: "x", Image: goodImage, IPC: "host"}, false, true},
		{"sys_admin cap rejected", Container{Name: "x", Image: goodImage, CapAdd: []string{"SYS_ADMIN"}}, false, true},
		{"cap_ prefix rejected", Container{Name: "x", Image: goodImage, CapAdd: []string{"CAP_NET_ADMIN"}}, false, true},
		{"lowercase cap rejected", Container{Name: "x", Image: goodImage, CapAdd: []string{"sys_ptrace"}}, false, true},
		{"benign cap allowed", Container{Name: "x", Image: goodImage, CapAdd: []string{"IPC_LOCK"}}, false, false},
		{"dangerous cap allowed in debug", Container{Name: "x", Image: goodImage, CapAdd: []string{"SYS_ADMIN"}}, true, false},
		{"external env LD_PRELOAD rejected", Container{Name: "x", Image: goodImage, Env: []interface{}{"LD_PRELOAD"}}, false, true},
		{"external env PYTHONPATH rejected", Container{Name: "x", Image: goodImage, Env: []interface{}{"PYTHONPATH"}}, false, true},
		{"external env benign allowed", Container{Name: "x", Image: goodImage, Env: []interface{}{"DOMAIN"}}, false, false},
		{"hardcoded env LD_PRELOAD allowed", Container{Name: "x", Image: goodImage, Env: []interface{}{map[string]interface{}{"LD_PRELOAD": "/x"}}}, false, false},
		{"secret HF_TOKEN rejected", Container{Name: "x", Image: goodImage, Secrets: []string{"HF_TOKEN"}}, false, true},
		{"secret API_KEY allowed", Container{Name: "x", Image: goodImage, Secrets: []string{"API_KEY"}}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateContainers([]Container{tt.c}, tt.debugMode)
			if (err != nil) != tt.wantErr {
				t.Errorf("got err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
	}{
		{"", 0},
		{"30s", 30 * time.Second},
		{"5m", 5 * time.Minute},
		{"invalid", 0},
	}
	for _, tt := range tests {
		got := parseDuration(tt.input)
		if got != tt.want {
			t.Errorf("parseDuration(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
