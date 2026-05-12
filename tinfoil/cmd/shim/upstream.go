package main

import (
	"context"
	"fmt"
	"time"

	"github.com/docker/docker/client"
)

// Kept in sync with cmd/boot/containers.go.
const containerNetworkName = "container-net"

// resolveUpstreamHost returns the named container's IP on container-net,
// retrying briefly so a slow Docker daemon doesn't fail the shim.
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
	deadline := time.Now().Add(retryTimeout)
	for {
		info, err := cli.ContainerInspect(ctx, name)
		if err == nil && info.NetworkSettings != nil {
			if ep, ok := info.NetworkSettings.Networks[containerNetworkName]; ok && ep != nil && ep.IPAddress != "" {
				return ep.IPAddress, nil
			}
			err = fmt.Errorf("container %q has no IP on %q", name, containerNetworkName)
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("resolving upstream container %q: %w", name, err)
		}
		time.Sleep(retryInterval)
	}
}
