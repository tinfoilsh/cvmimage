// Package trustedtime gates use of UTC on authenticated Chrony measurements.
// The measured kernel requires a protected TSC for CLOCK_MONOTONIC_RAW.
package trustedtime

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

const (
	MaxUncertainty  = time.Second
	BootstrapLimit  = 5 * time.Minute
	SocketPath      = "/run/chrony/chronyd.sock"
	statusPath      = "/run/tinfoil/trusted-time.json"
	chronycPath     = "/usr/bin/chronyc"
	queryLimit      = 2 * time.Second
	pollInterval    = time.Second
	maxStatusAge    = 5 * time.Second
	maxReferenceAge = 5 * time.Minute
	// This matches maxclockerror in the measured Chrony configuration.
	clockErrorPPM    = 100
	partsPerMillion  = 1_000_000
	statusLimit      = 4096
	trackingFields   = 14
	localReferenceID = 0x7f7f0101
)

// Sample describes the current system clock and a conservative UTC error bound.
type Sample struct {
	Time        time.Time
	Uncertainty time.Duration
}

type clocks struct {
	UTC    time.Time
	Raw    time.Duration
	Window time.Duration
}

type checkpoint struct {
	UTC         time.Time     `json:"utc"`
	Raw         time.Duration `json:"raw_ns"`
	Uncertainty time.Duration `json:"uncertainty_ns"`
}

func readClocks() (clocks, error) {
	var before, wall, after unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC_RAW, &before); err != nil {
		return clocks{}, err
	}
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &wall); err != nil {
		return clocks{}, err
	}
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC_RAW, &after); err != nil {
		return clocks{}, err
	}
	window := time.Duration(after.Nano() - before.Nano())
	if window < 0 || window > MaxUncertainty {
		return clocks{}, errors.New("clock sample exceeded its bound")
	}
	return clocks{time.Unix(wall.Sec, wall.Nsec).UTC(), time.Duration(after.Nano()), window}, nil
}

// Read checks freshness using the protected counter, including when the host
// pauses the guest between monitor updates or between these clock reads.
func Read() (Sample, error) {
	file, err := os.Open(statusPath)
	if err != nil {
		return Sample{}, fmt.Errorf("trusted time unavailable: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, statusLimit+1))
	if err != nil || len(data) > statusLimit {
		return Sample{}, errors.New("invalid trusted time status")
	}
	var state checkpoint
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return Sample{}, fmt.Errorf("decode trusted time: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return Sample{}, errors.New("trailing trusted time status")
	}
	now, err := readClocks()
	if err != nil {
		return Sample{}, err
	}
	return state.sample(now)
}

func (state checkpoint) sample(now clocks) (Sample, error) {
	if state.UTC.IsZero() || state.Raw < 0 || state.Raw > now.Raw ||
		state.Uncertainty < 0 || state.Uncertainty > MaxUncertainty {
		return Sample{}, errors.New("invalid trusted time checkpoint")
	}
	elapsed := now.Raw - state.Raw
	if elapsed > maxStatusAge {
		return Sample{}, errors.New("trusted time status expired")
	}
	correction := now.UTC.Sub(state.UTC.Add(elapsed))
	if correction < -MaxUncertainty || correction > MaxUncertainty {
		return Sample{}, errors.New("system clock changed outside its bound")
	}
	if correction < 0 {
		correction = -correction
	}
	// Include actual wall-clock slewing, oscillator drift, and read latency.
	bound := state.Uncertainty + correction + elapsed*clockErrorPPM/partsPerMillion + now.Window
	if bound > MaxUncertainty {
		return Sample{}, errors.New("trusted time uncertainty exceeded its bound")
	}
	return Sample{now.UTC, bound}, nil
}

// Wait holds provisioning until the monitor has established authenticated UTC.
func Wait(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, BootstrapLimit)
	defer cancel()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		if _, err := Read(); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for authenticated UTC: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

// Monitor publishes local clock checkpoints. Once synchronized, any invalid
// observation is fatal; restarting must not reopen Chrony's bootstrap window.
func Monitor(ctx context.Context) error {
	return monitor(ctx, observe, readClocks, publish, invalidate, pollInterval)
}

func monitor(ctx context.Context, observe func(context.Context) (checkpoint, error), now func() (clocks, error), publish func(checkpoint) error, invalidate func() error, interval time.Duration) error {
	if err := invalidate(); err != nil {
		return err
	}
	defer invalidate()
	initial, err := now()
	if err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var previous *checkpoint
	for {
		at, err := now()
		if err != nil {
			return err
		}
		if previous != nil {
			if _, err := previous.sample(at); err != nil {
				return err
			}
		} else if at.Raw < initial.Raw || at.Raw-initial.Raw > BootstrapLimit {
			return errors.New("authenticated UTC bootstrap timed out")
		}
		state, err := observe(ctx)
		if err == nil {
			if err := publish(state); err != nil {
				return err
			}
			previous = &state
		} else if previous != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func observe(ctx context.Context) (checkpoint, error) {
	before, err := readClocks()
	if err != nil {
		return checkpoint{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, queryLimit)
	defer cancel()
	command := exec.CommandContext(ctx, chronycPath, "-u", "root", "-n", "-c", "-h", SocketPath, "tracking")
	command.Env = []string{"LC_ALL=C"}
	data, err := command.Output()
	if err != nil {
		return checkpoint{}, fmt.Errorf("query authenticated time: %w", err)
	}
	after, err := readClocks()
	if err != nil {
		return checkpoint{}, err
	}
	uncertainty, err := trackingBound(data, after.UTC)
	if err != nil {
		return checkpoint{}, err
	}
	elapsed := after.Raw - before.Raw
	if elapsed < 0 || elapsed > MaxUncertainty {
		return checkpoint{}, errors.New("time query exceeded its bound")
	}
	correction := after.UTC.Sub(before.UTC.Add(elapsed))
	if correction < -MaxUncertainty || correction > MaxUncertainty {
		return checkpoint{}, errors.New("system clock changed during time query")
	}
	if correction < 0 {
		correction = -correction
	}
	state := checkpoint{after.UTC, after.Raw, uncertainty + elapsed + correction + after.Window}
	if _, err := state.sample(after); err != nil {
		return checkpoint{}, err
	}
	return state, nil
}

// trackingBound follows chronyc tracking's CSV field order. Only authenticated
// sources are selectable in the measured configuration; no local source exists.
func trackingBound(data []byte, now time.Time) (time.Duration, error) {
	const (
		refIDField = iota
		addressField
		stratumField
		refTimeField
		correctionField
		lastOffsetField
		rmsOffsetField
		frequencyField
		residualFrequencyField
		skewField
		rootDelayField
		rootDispersionField
		intervalField
		leapField
	)
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = trackingFields
	fields, err := reader.Read()
	if err != nil {
		return 0, fmt.Errorf("invalid tracking report: %w", err)
	}
	if _, err := reader.Read(); err != io.EOF {
		return 0, errors.New("multiple tracking reports")
	}
	refID, err := strconv.ParseUint(fields[refIDField], 16, 32)
	if err != nil || refID == 0 || refID == localReferenceID || net.ParseIP(fields[addressField]) == nil || fields[leapField] != "Normal" {
		return 0, errors.New("clock is not synchronized to an external source")
	}
	stratum, err := strconv.Atoi(fields[stratumField])
	const maxStratum = 15
	if err != nil || stratum < 1 || stratum > maxStratum {
		return 0, errors.New("invalid time source stratum")
	}
	var values [trackingFields]float64
	for field := refTimeField; field < leapField; field++ {
		value, err := strconv.ParseFloat(fields[field], 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
			return 0, errors.New("invalid time source measurement")
		}
		values[field] = value
	}
	age := float64(now.Unix()) + float64(now.Nanosecond())/float64(time.Second) - values[refTimeField]
	if values[refTimeField] <= 0 || age < -MaxUncertainty.Seconds() || age > maxReferenceAge.Seconds() ||
		values[rootDelayField] < 0 || values[rootDispersionField] < 0 || values[skewField] < 0 ||
		values[skewField] > clockErrorPPM || math.Abs(values[frequencyField]) > clockErrorPPM {
		return 0, errors.New("time source is stale or outside clock limits")
	}
	seconds := math.Abs(values[correctionField]) + values[rootDispersionField] + values[rootDelayField]/2 + math.Max(age, 0)*clockErrorPPM/partsPerMillion
	if seconds > MaxUncertainty.Seconds() {
		return 0, errors.New("UTC uncertainty exceeded its bound")
	}
	return time.Duration(math.Ceil(seconds * float64(time.Second))), nil
}

func publish(state checkpoint) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(statusPath), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(statusPath), ".trusted-time-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), statusPath)
}

func invalidate() error {
	if err := os.Remove(statusPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
