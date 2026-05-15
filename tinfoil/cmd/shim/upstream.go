package main

import (
	"context"
	"fmt"
	"time"

	"github.com/docker/docker/client"

	"tinfoil/internal/containernet"
)

// resolveUpstreamHost returns the named container's IP on the container
// network, retrying briefly so a slow Docker daemon doesn't fail the shim.
func resolveUpstreamHost(ctx context.Context, name string) (string, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return "", fmt.Errorf("creating docker client: %w", err)
	}
	defer cli.Close()

	const (
		retryInterval = 1 * time.Second
		retryTimeout  = 60 * time.Second
	)
	deadlineCtx, cancel := context.WithTimeout(ctx, retryTimeout)
	defer cancel()

	var lastErr error
	for {
		info, err := cli.ContainerInspect(deadlineCtx, name)
		switch {
		case err != nil:
			lastErr = err
		case info.NetworkSettings == nil:
			lastErr = fmt.Errorf("container %q has no network settings yet", name)
		default:
			if ep, ok := info.NetworkSettings.Networks[containernet.NetworkName]; ok && ep != nil && ep.IPAddress != "" {
				return ep.IPAddress, nil
			}
			lastErr = fmt.Errorf("container %q has no IP on %q", name, containernet.NetworkName)
		}

		select {
		case <-deadlineCtx.Done():
			return "", fmt.Errorf("resolving upstream container %q: %w", name, lastErr)
		case <-time.After(retryInterval):
		}
	}
}
