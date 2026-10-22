//go:build !tinfoil_gpu

package metrics

func gpuMetrics() (string, int, int, int, error) { return "", 0, 0, 0, nil }
