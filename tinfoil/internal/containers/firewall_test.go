package containers

import (
	"testing"

	shimconfig "tinfoil/internal/config"
)

func TestAttachOrderEgressFirstThenShim(t *testing.T) {
	config := &Config{
		ShimCfg: &shimconfig.Config{UpstreamContainer: "api"},
		Networks: map[string]*NetworkSpec{
			"control": {Egress: "allowlist"},
			"ipc":     {Egress: "closed"},
		},
	}
	first, rest := attachOrder(Container{Name: "api", Networks: []string{"ipc", "control"}}, config)
	if first != "control" || len(rest) == 0 || rest[len(rest)-1] != "shim-net" {
		t.Fatalf("attach order = %q, %v", first, rest)
	}
}
