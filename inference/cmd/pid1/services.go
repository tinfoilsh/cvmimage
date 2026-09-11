package main

import (
	"time"

	"golang.org/x/sys/unix"

	"tinfoil/inference/internal/variant"
	"tinfoil/internal/pid1/hardening"
	"tinfoil/internal/pid1/supervisor"
	"tinfoil/pid1"
)

const (
	containerdReadyLimit = 30 * time.Second
	dockerReadyLimit     = 60 * time.Second
	containerdName       = "containerd"
	dockerName           = "dockerd"
	containersName       = string(variant.ServiceContainers)
	egressName           = string(variant.ServiceEgress)
	containerdSocket     = "/run/containerd/containerd.sock"

	nvidiaDeviceWait  = 15 * time.Second
	nvidiaDevicePoll  = 500 * time.Millisecond
	cdiGenerateLimit  = 30 * time.Second
	persistencedName  = "nvidia-persistenced"
	fabricManagerName = "nvidia-fabricmanager"
	fabricConfigPath  = "/usr/share/nvidia/nvswitch/fabricmanager.cfg"
)

func inferenceServices() (containerd, docker, containers, egress pid1.Service) {
	containerd.Service = supervisor.Service{
		Name: containerdName, Required: true, Restart: true,
		Command: supervisor.Command{Path: "/usr/bin/containerd"},
		Ready:   pid1.EndpointReady("unix", containerdSocket, containerdReadyLimit),
	}
	docker.Service = supervisor.Service{
		Name: dockerName, Required: true, Restart: true,
		Command: supervisor.Command{Path: "/usr/bin/dockerd", Args: []string{"-H", "unix://" + variant.DockerSocket, "--containerd=" + containerdSocket}},
		Ready:   pid1.EndpointReady("unix", variant.DockerSocket, dockerReadyLimit),
	}
	containerPolicy := hardening.RestrictedPolicy([]int{unix.CAP_NET_ADMIN}, []uint32{unix.AF_UNIX, unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK})
	containers = pid1.Service{
		Service: supervisor.Service{
			Name: containersName, Required: true, Restart: true,
			Command: supervisor.Command{Path: variant.ContainersBinary},
			Ready:   pid1.FileReady(variant.ContainersReadyPath),
		},
		Policy: &containerPolicy,
	}
	egressPolicy := hardening.RestrictedPolicy([]int{unix.CAP_NET_ADMIN}, []uint32{unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK})
	egress = pid1.Service{
		Service: supervisor.Service{
			Name: egressName, Restart: true,
			Command: supervisor.Command{Path: variant.EgressBinary},
			PIDFile: variant.EgressPIDPath,
		},
		Policy: &egressPolicy,
	}
	return containerd, docker, containers, egress
}

func nvidiaServices(control nvidiaBootstrapControl) (persistenced, fabric pid1.Service) {
	persistenced.Service = supervisor.Service{
		Name: persistencedName, Restart: true, Forking: true,
		Command: supervisor.Command{Path: "/usr/bin/nvidia-persistenced", Args: []string{"--user", "nvidia-persistenced", "--uvm-persistence-mode", "--verbose"}},
		Ready:   control.WaitForPersistenced,
	}
	fabric.Service = supervisor.Service{
		Name: fabricManagerName, Restart: true,
		Command: fabricManagerCommand(),
		Ready:   control.WaitForFabricManager,
	}
	return persistenced, fabric
}
