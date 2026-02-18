package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

const (
	containerStopTimeout = 120 * time.Second // 2 minutes for vLLM to cleanup
	ccCleanupWaitTimeout = 60 * time.Second  // Wait for CC secret cleanup
)

// nvidiaModules is the order in which modules should be unloaded
var nvidiaModules = []string{
	"nvidia_uvm",
	"nvidia_drm",
	"nvidia_modeset",
	"nvidia",
}

// nvidiaServices is the order in which services should be stopped
var nvidiaServices = []string{
	"nvidia-cdi-refresh.path",
	"nvidia-cdi-refresh.service",
	"nvidia-fabricmanager.service",
	"nvidia-persistenced.service",
}

// runShutdown performs graceful shutdown of GPU resources
func runShutdown() error {
	log.Println("Starting graceful shutdown...")

	// Detect GPUs to determine if GPU-specific shutdown is needed
	gpuInfo, err := detectGPUs()
	if err != nil {
		log.Printf("Warning: failed to detect GPUs: %v", err)
		gpuInfo = &GPUInfo{} // Assume no GPUs on error
	}

	if !gpuInfo.HasNvidia {
		log.Println("No NVIDIA GPUs detected, skipping GPU shutdown steps")
		log.Println("Syncing filesystems...")
		exec.Command("sync").Run()
		log.Println("Graceful shutdown completed")
		return nil
	}

	log.Printf("NVIDIA GPUs detected: %d devices", gpuInfo.DeviceCount)

	// DIAGNOSTIC MODE: Skip manual stops, let systemd handle it
	// Set to false if systemd doesn't handle services/containers properly
	diagnosticOnly := true

	if !diagnosticOnly {
		// Step 1: Stop all Docker containers gracefully
		if err := stopAllContainers(); err != nil {
			log.Printf("Warning: container shutdown had errors: %v", err)
		}

		// Step 2: Stop NVIDIA services
		if err := stopNvidiaServices(); err != nil {
			log.Printf("Warning: nvidia service shutdown had errors: %v", err)
		}

		// Step 3: Unload NVIDIA kernel modules
		if err := unloadNvidiaModules(); err != nil {
			log.Printf("Warning: nvidia module unload had errors: %v", err)
		}
	} else {
		log.Println("DIAGNOSTIC MODE: Skipping manual service/container stops, letting systemd handle it")
	}

	// Step 4: Wait for and verify CC cleanup (always do this - systemd won't)
	// Use actual GPU count (excluding NVSwitches which are ~4 of the 12 devices)
	expectedGPUs := gpuInfo.DeviceCount
	if gpuInfo.IsMultiGPU {
		expectedGPUs = 8 // 8 GPUs in multi-GPU setup (rest are NVSwitches)
	}
	if err := waitForCCCleanup(expectedGPUs); err != nil {
		log.Printf("Warning: CC cleanup verification had errors: %v", err)
	}

	// Step 5: Final sync
	log.Println("Syncing filesystems...")
	exec.Command("sync").Run()

	log.Println("Graceful GPU shutdown completed")
	return nil
}

// stopAllContainers stops all running Docker containers with a long timeout
func stopAllContainers() error {
	log.Println("Stopping Docker containers...")

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("creating docker client: %w", err)
	}
	defer cli.Close()

	ctx := context.Background()

	// List all running containers
	containers, err := cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return fmt.Errorf("listing containers: %w", err)
	}

	if len(containers) == 0 {
		log.Println("No running containers found")
		return nil
	}

	log.Printf("Found %d running container(s)", len(containers))

	var lastErr error
	for _, c := range containers {
		containerName := c.ID[:12]
		if len(c.Names) > 0 {
			containerName = strings.TrimPrefix(c.Names[0], "/")
		}

		log.Printf("Stopping container %s (%s)...", containerName, c.ID[:12])

		// Try graceful stop with long timeout (for vLLM distributed cleanup)
		timeoutSec := int(containerStopTimeout.Seconds())
		stopCtx, cancel := context.WithTimeout(ctx, containerStopTimeout+10*time.Second)

		err := cli.ContainerStop(stopCtx, c.ID, container.StopOptions{
			Timeout: &timeoutSec,
		})
		cancel()

		if err != nil {
			log.Printf("Graceful stop failed for %s: %v, force killing...", containerName, err)
			// Force kill if graceful stop fails
			killCtx, killCancel := context.WithTimeout(ctx, 10*time.Second)
			if killErr := cli.ContainerKill(killCtx, c.ID, "KILL"); killErr != nil {
				log.Printf("Force kill failed for %s: %v", containerName, killErr)
				lastErr = killErr
			}
			killCancel()
		} else {
			log.Printf("Container %s stopped successfully", containerName)
		}
	}

	// Verify all containers are stopped
	remaining, _ := cli.ContainerList(ctx, container.ListOptions{})
	if len(remaining) > 0 {
		log.Printf("Warning: %d container(s) still running after shutdown", len(remaining))
		// Try one more force kill pass
		for _, c := range remaining {
			cli.ContainerKill(ctx, c.ID, "KILL")
		}
	}

	return lastErr
}

// stopNvidiaServices stops NVIDIA systemd services in the correct order
func stopNvidiaServices() error {
	log.Println("Stopping NVIDIA services...")

	var lastErr error
	for _, service := range nvidiaServices {
		log.Printf("Stopping %s...", service)
		// Use timeout to avoid hanging during system shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, "systemctl", "stop", service)
		if err := cmd.Run(); err != nil {
			// Don't fail on service stop errors - service may not exist, already stopped, or systemd is shutting down
			log.Printf("Note: stopping %s: %v (may already be stopping)", service, err)
		}
		cancel()
	}

	// Brief wait for services to fully stop
	time.Sleep(1 * time.Second)

	return lastErr
}

// unloadNvidiaModules unloads NVIDIA kernel modules in the correct order
func unloadNvidiaModules() error {
	log.Println("Unloading NVIDIA kernel modules...")

	// First check which modules are loaded
	loadedModules, err := getLoadedModules()
	if err != nil {
		return fmt.Errorf("checking loaded modules: %w", err)
	}

	var lastErr error
	for _, module := range nvidiaModules {
		if !loadedModules[module] {
			log.Printf("Module %s not loaded, skipping", module)
			continue
		}

		log.Printf("Unloading %s...", module)
		// Use timeout to avoid hanging during system shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, "rmmod", module)
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			log.Printf("Warning: failed to unload %s: %v (output: %s)", module, err, string(output))
			lastErr = err
			// Continue trying to unload other modules
		} else {
			log.Printf("Module %s unloaded successfully", module)
		}
	}

	return lastErr
}

// getLoadedModules returns a map of currently loaded kernel modules
func getLoadedModules() (map[string]bool, error) {
	file, err := os.Open("/proc/modules")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	modules := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 {
			modules[fields[0]] = true
		}
	}
	return modules, scanner.Err()
}

// waitForCCCleanup waits for CC secret cleanup confirmation in dmesg
func waitForCCCleanup(expectedGPUCount int) error {
	log.Printf("Waiting for CC secret cleanup (expecting %d GPUs)...", expectedGPUCount)

	deadline := time.Now().Add(ccCleanupWaitTimeout)
	cleanupMessage := "kgspCheckGspRmCcCleanup_GH100: CC secret cleanup successful"

	for time.Now().Before(deadline) {
		count, err := countDmesgMatches(cleanupMessage)
		if err != nil {
			log.Printf("Warning: error reading dmesg: %v", err)
		}

		if count >= expectedGPUCount {
			log.Printf("CC secret cleanup confirmed for %d GPUs", count)
			return nil
		}

		log.Printf("CC cleanup progress: %d/%d GPUs", count, expectedGPUCount)
		time.Sleep(2 * time.Second)
	}

	// Check final count
	finalCount, _ := countDmesgMatches(cleanupMessage)
	if finalCount < expectedGPUCount {
		log.Printf("Warning: CC cleanup may not have completed (found %d/%d)", finalCount, expectedGPUCount)
	}

	return nil
}

// countDmesgMatches counts occurrences of a message in dmesg output
func countDmesgMatches(message string) (int, error) {
	cmd := exec.Command("dmesg")
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	count := 0
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, message) {
			count++
		}
	}
	return count, nil
}
