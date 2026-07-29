package main

import (
	"tinfoil/internal/containers"
)

func setupFirewall(config *Config) error {
	return containers.SetupInboundFirewall(config.CVMNetwork.InboundPorts)
}

func runNft(script string) error {
	return containers.RunNft(script)
}
