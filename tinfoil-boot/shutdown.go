package main

import (
	"context"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

const (
	containerStopTimeout = 30 * time.Second
	ccCleanupTimeout     = 10 * time.Second
	nvlinkDrainTimeout   = 30 * time.Second
	auxTimeout           = 10 * time.Second
	rmmodTimeout         = 30 * time.Second
	dmesgTimeout         = 5 * time.Second
)

// runShutdown stops Docker containers to release GPU device files.
// This runs as ExecStop of tinfoil-boot.service, which is ordered After=docker.service,
// so on shutdown it runs BEFORE systemd stops docker -- Docker API is still available.
// Everything else (nvidia services, module unload) is handled by systemd and tinfoil-gpu-cleanup.
func runShutdown() error {
	log.Println("Starting graceful shutdown...")
	stopAllContainers()

	gpuInfo, _ := detectGPUs()
	if gpuInfo != nil && gpuInfo.IsMultiGPU {
		// Drain NVLink peer state while Fabric Manager is still running.
		// Cycles peer access enable/disable to quiesce the NVSwitch fabric,
		// avoiding SOE command timeouts (SXid 26004) during host-side VFIO teardown.
		done := make(chan struct{})
		go func() {
			drainNVLinkState()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(nvlinkDrainTimeout):
			log.Printf("Warning: NVLink drain timed out after %v, continuing", nvlinkDrainTimeout)
		}
	}

	log.Println("Shutdown complete, GPU cleanup will follow via tinfoil-gpu-cleanup.service")
	return nil
}

// runGPUCleanup waits for CC secret cleanup confirmation.
// This runs as ExecStart of tinfoil-gpu-cleanup.service, which is activated by
// shutdown.target and ordered After= nvidia/docker services -- so they are already
// stopped by the time we run.
func runGPUCleanup() error {
	log.Println("Starting GPU cleanup verification...")

	gpuInfo, err := detectGPUs()
	if err != nil {
		log.Printf("Warning: GPU detection failed: %v", err)
		gpuInfo = &GPUInfo{}
	}

	if !gpuInfo.HasNvidia {
		log.Println("No NVIDIA GPUs detected, nothing to verify")
		return nil
	}

	expectedGPUs := 1
	if gpuInfo.IsMultiGPU {
		expectedGPUs = 8 // 12 NVIDIA devices = 8 GPUs + 4 NVSwitches, only GPUs do CC cleanup
	}
	log.Printf("Expecting CC cleanup for %d GPUs (%d total NVIDIA devices)", expectedGPUs, gpuInfo.DeviceCount)

	// Unload nvidia modules — triggers CC secret cleanup in GPU firmware.
	unloadNvidiaModules()

	waitForCCCleanup(expectedGPUs)

	log.Println("GPU cleanup complete")
	return nil
}

// stopAllContainers stops every running Docker container.
func stopAllContainers() {
	log.Println("Stopping Docker containers...")

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("Warning: cannot connect to Docker: %v", err)
		return
	}
	defer cli.Close()

	ctx := context.Background()

	containers, err := cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		log.Printf("Warning: cannot list containers: %v", err)
		return
	}

	if len(containers) == 0 {
		log.Println("No running containers")
		return
	}

	log.Printf("Stopping %d container(s)...", len(containers))

	forceKill := func(id string) {
		killCtx, cancel := context.WithTimeout(ctx, auxTimeout)
		defer cancel()
		if err := cli.ContainerKill(killCtx, id, "KILL"); err != nil {
			log.Printf("Warning: force kill %s failed: %v", id[:12], err)
		}
	}

	for _, c := range containers {
		name := c.ID[:12]
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}

		log.Printf("Stopping %s...", name)
		timeout := int(containerStopTimeout.Seconds())
		stopCtx, cancel := context.WithTimeout(ctx, containerStopTimeout+auxTimeout)
		err := cli.ContainerStop(stopCtx, c.ID, container.StopOptions{Timeout: &timeout})
		cancel()

		if err != nil {
			log.Printf("Warning: graceful stop failed for %s, force killing: %v", name, err)
			forceKill(c.ID)
		} else {
			log.Printf("Stopped %s", name)
		}
	}

	listCtx, listCancel := context.WithTimeout(ctx, auxTimeout)
	remaining, _ := cli.ContainerList(listCtx, container.ListOptions{})
	listCancel()
	if len(remaining) > 0 {
		log.Printf("Warning: %d container(s) still running, force killing", len(remaining))
		for _, c := range remaining {
			forceKill(c.ID)
		}
		time.Sleep(2 * time.Second)
	}
}

// nvidiaModules in unload order (dependents before base).
var nvidiaModules = []string{
	"nvidia_uvm",
	"nvidia_drm",
	"nvidia_modeset",
	"nvidia",
}

// unloadNvidiaModules removes NVIDIA kernel modules in dependency order.
// Unloading "nvidia" triggers CC secret cleanup in the GPU firmware.
// Best-effort: if a module fails to unload, we continue.
func unloadNvidiaModules() {
	log.Println("Unloading NVIDIA kernel modules...")

	for _, mod := range nvidiaModules {
		ctx, cancel := context.WithTimeout(context.Background(), rmmodTimeout)
		out, err := exec.CommandContext(ctx, "rmmod", mod).CombinedOutput()
		cancel()

		if err == nil {
			log.Printf("Unloaded %s", mod)
		} else {
			log.Printf("Warning: rmmod %s: %v (%s)", mod, err, strings.TrimSpace(string(out)))
		}
	}
}

// waitForCCCleanup polls dmesg for CC secret cleanup confirmation from all expected GPUs.
func waitForCCCleanup(expectedGPUs int) {
	log.Printf("Waiting for CC secret cleanup (%d GPUs, timeout %v)...", expectedGPUs, ccCleanupTimeout)

	const marker = "kgspCheckGspRmCcCleanup_GH100: CC secret cleanup successful"
	deadline := time.Now().Add(ccCleanupTimeout)

	for time.Now().Before(deadline) {
		count := countDmesgMatches(marker)
		if count >= expectedGPUs {
			log.Printf("CC cleanup complete: %d/%d GPUs", count, expectedGPUs)
			return
		}
		log.Printf("CC cleanup: %d/%d GPUs", count, expectedGPUs)
		time.Sleep(2 * time.Second)
	}

	final := countDmesgMatches(marker)
	if final >= expectedGPUs {
		log.Printf("CC cleanup complete: %d/%d GPUs", final, expectedGPUs)
	} else {
		log.Printf("WARNING: CC cleanup incomplete: %d/%d GPUs (timed out after %v)", final, expectedGPUs, ccCleanupTimeout)
	}
}

// countDmesgMatches counts occurrences of a string in dmesg output.
func countDmesgMatches(message string) int {
	ctx, cancel := context.WithTimeout(context.Background(), dmesgTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "dmesg").Output()
	if err != nil {
		return 0
	}

	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, message) {
			count++
		}
	}
	return count
}
