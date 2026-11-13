package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"tinfoil/internal/boot"
	"tinfoil/internal/timequorum"
)

const noTimeFeedFD = -1

type timeMonitorRunner interface{ Run(context.Context) error }

func watchTimeQuorum(ctx context.Context, monitor timeMonitorRunner, shutdown func() error) {
	if err := monitor.Run(ctx); ctx.Err() == nil {
		if shutdownErr := shutdown(); shutdownErr != nil {
			log.Printf("Time quorum shutdown: %v", shutdownErr)
		}
		log.Fatalf("Authenticated time quorum lost: %v", err)
	}
}

func newTimeMonitor(fd int) (*timequorum.Monitor, *timequorum.ChronyFeed, error) {
	file, err := os.Open(boot.TimeSourcesPath)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	var catalogue struct {
		Relays  []string            `json:"relays"`
		Sources []timequorum.Source `json:"sources"`
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalogue); err != nil {
		return nil, nil, fmt.Errorf("time sources: %w", err)
	}
	sampler, err := timequorum.NewSampler(catalogue.Sources, catalogue.Relays)
	if err != nil {
		return nil, nil, err
	}
	feed, err := timequorum.InheritChronyFeed(fd)
	if err != nil {
		return nil, nil, err
	}
	monitor := timequorum.NewMonitor(sampler, feed, log.Printf)
	state, stateErr := boot.Load()
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		feed.Close()
		return nil, nil, stateErr
	}
	if stateErr == nil {
		for _, stage := range state.Stages {
			if stage.Name == boot.StageTime && stage.Status == boot.StatusOK {
				monitor.Resume()
				break
			}
		}
	}
	return monitor, feed, nil
}

func timeAdmission(monitor *timequorum.Monitor, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/.well-known/tinfoil-boot-stages" && !monitor.Healthy() {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "authenticated time quorum unavailable", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func timeReadyHandler(monitor *timequorum.Monitor) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.RawQuery != "" || r.ContentLength != 0 {
			http.Error(w, "invalid time readiness request", http.StatusBadRequest)
			return
		}
		if err := monitor.Arm(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
