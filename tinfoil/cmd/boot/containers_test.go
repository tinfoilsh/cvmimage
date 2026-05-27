package main

import (
	"testing"
	"time"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/containernet"
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

func TestNetworkCreateOptionsStaticShimNet(t *testing.T) {
	opts := networkCreateOptions(containernet.ShimNetName)
	if opts.IPAM == nil || len(opts.IPAM.Config) != 1 {
		t.Fatalf("expected static shim-net IPAM config, got %+v", opts.IPAM)
	}
	if got := opts.IPAM.Config[0].Subnet; got != containernet.ShimNetSubnetCIDR {
		t.Errorf("subnet: got %q, want %q", got, containernet.ShimNetSubnetCIDR)
	}
	if got := opts.IPAM.Config[0].Gateway; got != containernet.ShimNetGatewayIP {
		t.Errorf("gateway: got %q, want %q", got, containernet.ShimNetGatewayIP)
	}
}

func TestEndpointSettingsPinsShimUpstreamIP(t *testing.T) {
	ep := endpointSettings(containernet.ShimNetName, 0)
	if ep.IPAMConfig == nil {
		t.Fatal("expected shim-net endpoint IPAM config")
	}
	if got := ep.IPAMConfig.IPv4Address; got != containernet.ShimUpstreamIP {
		t.Errorf("upstream IP: got %q, want %q", got, containernet.ShimUpstreamIP)
	}

	regular := endpointSettings("web", 100)
	if regular.IPAMConfig != nil {
		t.Fatalf("regular networks should not pin IPAM, got %+v", regular.IPAMConfig)
	}
	if regular.GwPriority != 100 {
		t.Errorf("GwPriority: got %d, want 100", regular.GwPriority)
	}
}
