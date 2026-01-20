package main

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
)

// launchContainers starts all containers from the config
func launchContainers(config *Config) error {
	if len(config.Containers) == 0 {
		slog.Info("no containers to launch")
		return nil
	}

	slog.Info("launching containers", "count", len(config.Containers))
	for _, c := range config.Containers {
		if err := startContainer(c); err != nil {
			return fmt.Errorf("starting container %s: %w", c.Name, err)
		}
	}

	return nil
}

// startContainer starts a Docker container using the Docker SDK
func startContainer(c Container) error {
	if !containerNamePattern.MatchString(c.Name) {
		return fmt.Errorf("invalid container name: %s", c.Name)
	}

	ctx := context.Background()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("creating docker client: %w", err)
	}
	defer cli.Close()

	// Parse extra args
	var extraArgs []string
	switch args := c.Args.(type) {
	case string:
		if args != "" {
			extraArgs = strings.Fields(args)
		}
	case []interface{}:
		for _, a := range args {
			if s, ok := a.(string); ok {
				extraArgs = append(extraArgs, s)
			}
		}
	}

	// Container configuration
	containerConfig := &container.Config{
		Image: c.Image,
	}

	// Host configuration
	hostConfig := &container.HostConfig{
		NetworkMode: "host",
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: "/mnt/ramdisk",
				Target: "/tinfoil",
			},
		},
	}

	// Parse extra args for additional mounts, env vars, etc.
	for i := 0; i < len(extraArgs); i++ {
		arg := extraArgs[i]
		switch {
		case arg == "-v" && i+1 < len(extraArgs):
			// Volume mount: -v source:target
			i++
			volParts := strings.SplitN(extraArgs[i], ":", 2)
			if len(volParts) == 2 {
				source := filepath.Clean(volParts[0])                                     // Clean to prevent path traversal
				if source != ramdiskPath && !strings.HasPrefix(source, ramdiskPath+"/") { // Prevent host escape
					return fmt.Errorf("volume mount source must be under %s: %s", ramdiskPath, source)
				}
				hostConfig.Mounts = append(hostConfig.Mounts, mount.Mount{
					Type:   mount.TypeBind,
					Source: source,
					Target: volParts[1],
				})
			}
		case arg == "-e" && i+1 < len(extraArgs):
			// Environment variable: -e KEY=VALUE
			i++
			containerConfig.Env = append(containerConfig.Env, extraArgs[i])
		case arg == "--gpus":
			// GPU access
			i++
			hostConfig.DeviceRequests = []container.DeviceRequest{
				{
					Count:        -1, // all GPUs
					Capabilities: [][]string{{"gpu"}},
				},
			}
		}
	}

	slog.Info("creating container", "name", c.Name, "image", c.Image)

	// Create container
	resp, err := cli.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, c.Name)
	if err != nil {
		return fmt.Errorf("creating container: %w", err)
	}

	// Start container
	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("starting container: %w", err)
	}

	slog.Info("started container", "name", c.Name, "id", resp.ID[:12])
	return nil
}
