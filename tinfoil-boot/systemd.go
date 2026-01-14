package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
)

// startSystemdUnit starts a systemd unit and waits for it to be active
func startSystemdUnit(unit string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return fmt.Errorf("connecting to systemd: %w", err)
	}
	defer conn.Close()

	// Start the unit
	responseChan := make(chan string)
	_, err = conn.StartUnitContext(ctx, unit, "replace", responseChan)
	if err != nil {
		return fmt.Errorf("starting unit %s: %w", unit, err)
	}

	// Wait for the result
	select {
	case result := <-responseChan:
		if result != "done" {
			return fmt.Errorf("unit %s start result: %s", unit, result)
		}
	case <-ctx.Done():
		return fmt.Errorf("timeout waiting for unit %s", unit)
	}

	slog.Info("started systemd unit", "unit", unit)
	return nil
}

// stopSystemdUnit stops a systemd unit
func stopSystemdUnit(unit string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return fmt.Errorf("connecting to systemd: %w", err)
	}
	defer conn.Close()

	responseChan := make(chan string)
	_, err = conn.StopUnitContext(ctx, unit, "replace", responseChan)
	if err != nil {
		return fmt.Errorf("stopping unit %s: %w", unit, err)
	}

	select {
	case result := <-responseChan:
		if result != "done" {
			return fmt.Errorf("unit %s stop result: %s", unit, result)
		}
	case <-ctx.Done():
		return fmt.Errorf("timeout waiting for unit %s to stop", unit)
	}

	slog.Info("stopped systemd unit", "unit", unit)
	return nil
}

// isSystemdUnitActive checks if a systemd unit is active
func isSystemdUnitActive(unit string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	units, err := conn.ListUnitsByNamesContext(ctx, []string{unit})
	if err != nil {
		return false, err
	}

	for _, u := range units {
		if u.Name == unit {
			return u.ActiveState == "active", nil
		}
	}

	return false, nil
}
