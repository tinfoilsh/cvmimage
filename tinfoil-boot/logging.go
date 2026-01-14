package main

import (
	"log/slog"
	"os"
)

func init() {
	// Configure structured JSON logging to stderr
	// Systemd journal will capture this automatically
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)
}
