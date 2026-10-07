package tinfoilconfig

import (
	"fmt"
	"strings"
	"testing"
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
