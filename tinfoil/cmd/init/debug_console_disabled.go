//go:build !tinfoil_debug_image

package main

import "tinfoil/internal/pid1/supervisor"

func dispatchDebugConsole([]string) (bool, error) { return false, nil }

func startDebugConsole(*supervisor.Manager) error { return nil }
