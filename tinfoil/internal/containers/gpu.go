//go:build tinfoil_gpu

package containers

import (
	"github.com/moby/moby/api/types/container"
	"strings"
)

func configureGPUs(gpus any, host *container.HostConfig) error {
	if req := parseGPUs(gpus); req != nil {
		host.DeviceRequests = []container.DeviceRequest{*req}
	}
	return nil
}

// parseGPUs parses gpus: "all", "0,1,2,3", true, or count
func parseGPUs(gpus interface{}) *container.DeviceRequest {
	if gpus == nil {
		return nil
	}

	req := &container.DeviceRequest{
		Driver:       "nvidia",
		Capabilities: [][]string{{"gpu"}},
	}

	switch v := gpus.(type) {
	case bool:
		if !v {
			return nil
		}
		req.Count = -1
	case string:
		if v == "all" {
			req.Count = -1
		} else {
			req.DeviceIDs = strings.Split(v, ",")
		}
	case int:
		req.Count = v
	case float64:
		req.Count = int(v)
	default:
		return nil
	}
	return req
}
