package tinfoilconfig

import (
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDecodeUpstreamPort(t *testing.T) {
	for _, test := range []struct {
		name string
		port int
		want string
	}{
		{name: "negative", port: -1, want: "upstream port must be between"},
		{name: "unset", port: 0, want: "upstream port is not set"},
		{name: "minimum", port: 1},
		{name: "maximum", port: 65535},
		{name: "too large", port: 65536, want: "upstream port must be between"},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := strings.Replace(validConfig, "upstream-port: 8080", fmt.Sprintf("upstream-port: %d", test.port), 1)
			config, err := Decode([]byte(data), Options{})
			if test.want != "" {
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("error = %v, want substring %q", err, test.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if config.ShimCfg.UpstreamPort != test.port {
				t.Fatalf("upstream port = %d, want %d", config.ShimCfg.UpstreamPort, test.port)
			}
		})
	}
}

func TestDecodeAuthenticatedControlPlane(t *testing.T) {
	const customEndpoint = "https://user:password@api.example.com/prefix?tenant=custom"
	for _, test := range []struct {
		name          string
		authenticated bool
		field         string
		wantURL       string
		wantErr       string
	}{
		{name: "authenticated empty", authenticated: true, field: "  control-plane: ''\n", wantErr: "control-plane URL is required when authenticated"},
		{name: "authenticated omitted", authenticated: true, wantURL: "https://api.tinfoil.sh"},
		{name: "authenticated null", authenticated: true, field: "  control-plane: null\n", wantURL: "https://api.tinfoil.sh"},
		{name: "unauthenticated empty", field: "  control-plane: ''\n"},
		{name: "authenticated custom", authenticated: true, field: "  control-plane: '" + customEndpoint + "'\n", wantURL: customEndpoint},
	} {
		t.Run(test.name, func(t *testing.T) {
			shimData := fmt.Sprintf("  upstream-port: 8080\n  authenticated: %t\n", test.authenticated) + test.field
			var node yaml.Node
			if err := yaml.Unmarshal([]byte(shimData), &node); err != nil {
				t.Fatal(err)
			}
			shim, shimErr := DecodeShim(&node)
			data := strings.Replace(validConfig, "  upstream-port: 8080\n", shimData, 1)
			config, configErr := Decode([]byte(data), Options{})
			var workloadShim *ShimConfig
			if config != nil {
				workloadShim = config.ShimCfg
			}
			for _, result := range []struct {
				name   string
				config *ShimConfig
				err    error
			}{
				{name: "shim", config: shim, err: shimErr},
				{name: "workload", config: workloadShim, err: configErr},
			} {
				t.Run(result.name, func(t *testing.T) {
					if test.wantErr != "" {
						if result.err == nil || !strings.Contains(result.err.Error(), test.wantErr) {
							t.Fatalf("error = %v, want substring %q", result.err, test.wantErr)
						}
						return
					}
					if result.err != nil {
						t.Fatal(result.err)
					}
					if result.config.Authenticated != test.authenticated || result.config.ControlPlane != test.wantURL {
						t.Fatalf("authenticated = %v, control-plane = %q; want %v, %q", result.config.Authenticated, result.config.ControlPlane, test.authenticated, test.wantURL)
					}
				})
			}
		})
	}
}
