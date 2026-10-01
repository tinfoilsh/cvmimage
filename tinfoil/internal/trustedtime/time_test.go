package trustedtime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const trackingCSV = "A20FCF31,185.125.190.58,2,1770000000.000000000,-0.012345678,0.000100000,0.000200000,1.500,0.100,0.200,0.040000000,0.005000000,64.0,Normal\n"

func trackingReport(t *testing.T, replacements map[string]string) []byte {
	t.Helper()
	names := strings.Split("reference,address,stratum,reference_time,correction,last_offset,rms_offset,frequency,residual_frequency,skew,root_delay,root_dispersion,interval,leap", ",")
	fields := strings.Split(strings.TrimSpace(trackingCSV), ",")
	for name, replacement := range replacements {
		found := false
		for index, field := range names {
			if field == name {
				fields[index] = replacement
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("unknown tracking field %q", name)
		}
	}
	return []byte(strings.Join(fields, ",") + "\n")
}

func TestTrackingBoundUsesChronyCSVMeasurements(t *testing.T) {
	now := time.Unix(1770000010, 0)
	for _, test := range []struct {
		name         string
		replacements map[string]string
		want         time.Duration
	}{
		{name: "IPv4 and negative correction", want: 38345678 * time.Nanosecond},
		{name: "IPv6 and positive correction", replacements: map[string]string{"address": "2001:db8::123", "correction": "0.012345678"}, want: 38345678 * time.Nanosecond},
		{name: "frequency and skew limits", replacements: map[string]string{"frequency": "-100", "skew": "100"}, want: 38345678 * time.Nanosecond},
		{name: "future reference within uncertainty", replacements: map[string]string{"reference_time": "1770000011"}, want: 37345678 * time.Nanosecond},
		{name: "reference freshness boundary", replacements: map[string]string{"reference_time": "1769999710"}, want: 67345678 * time.Nanosecond},
		{name: "fractional nanosecond rounds up", replacements: map[string]string{"reference_time": "1770000010", "correction": "0.0000000001", "root_delay": "0", "root_dispersion": "0"}, want: time.Nanosecond},
		{name: "exact uncertainty limit", replacements: map[string]string{"reference_time": "1770000010", "correction": "0", "root_delay": "2", "root_dispersion": "0"}, want: MaxUncertainty},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := trackingBound(trackingReport(t, test.replacements), now)
			if err != nil {
				t.Fatal(err)
			}
			if got < test.want || got > test.want+time.Nanosecond {
				t.Fatalf("UTC bound = %s, want %s rounded up by at most 1ns", got, test.want)
			}
		})
	}
}

func TestTrackingBoundRejectsUntrustedReports(t *testing.T) {
	now := time.Unix(1770000010, 0)
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "empty report"},
		{name: "missing field", data: []byte(strings.TrimSuffix(trackingCSV, ",Normal\n") + "\n")},
		{name: "extra field", data: []byte(strings.TrimSpace(trackingCSV) + ",extra\n")},
		{name: "multiple reports", data: []byte(trackingCSV + trackingCSV)},
		{name: "broken CSV quoting", data: []byte("\"" + trackingCSV)},
		{name: "unsynchronized packaged output", data: []byte("00000000,,0,0.000000000,0.000000000,0.000000000,0.000000000,0.000,0.000,0.000,1.000000000,1.000000000,0.0,Not synchronised\n")},
		{name: "no reference", data: trackingReport(t, map[string]string{"reference": "00000000"})},
		{name: "local reference", data: trackingReport(t, map[string]string{"reference": "7F7F0101"})},
		{name: "invalid reference", data: trackingReport(t, map[string]string{"reference": "not-hex"})},
		{name: "overflowing reference", data: trackingReport(t, map[string]string{"reference": "100000000"})},
		{name: "missing address", data: trackingReport(t, map[string]string{"address": ""})},
		{name: "unresolved address", data: trackingReport(t, map[string]string{"address": "ntp-bootstrap.ubuntu.com"})},
		{name: "leap pending", data: trackingReport(t, map[string]string{"leap": "Insert second"})},
		{name: "stratum zero", data: trackingReport(t, map[string]string{"stratum": "0"})},
		{name: "stratum unsynchronized", data: trackingReport(t, map[string]string{"stratum": "16"})},
		{name: "stratum not integer", data: trackingReport(t, map[string]string{"stratum": "2.5"})},
		{name: "missing reference time", data: trackingReport(t, map[string]string{"reference_time": "0"})},
		{name: "stale reference", data: trackingReport(t, map[string]string{"reference_time": "1769999709.999"})},
		{name: "future reference", data: trackingReport(t, map[string]string{"reference_time": "1770000011.001"})},
		{name: "negative delay", data: trackingReport(t, map[string]string{"root_delay": "-0.001"})},
		{name: "negative dispersion", data: trackingReport(t, map[string]string{"root_dispersion": "-0.001"})},
		{name: "negative skew", data: trackingReport(t, map[string]string{"skew": "-1"})},
		{name: "excess skew", data: trackingReport(t, map[string]string{"skew": "100.001"})},
		{name: "excess positive frequency", data: trackingReport(t, map[string]string{"frequency": "100.001"})},
		{name: "excess negative frequency", data: trackingReport(t, map[string]string{"frequency": "-100.001"})},
		{name: "uncertainty from remaining correction", data: trackingReport(t, map[string]string{"correction": "-1"})},
		{name: "uncertainty from root delay", data: trackingReport(t, map[string]string{"root_delay": "2"})},
		{name: "uncertainty from dispersion", data: trackingReport(t, map[string]string{"root_dispersion": "1"})},
		{name: "numeric overflow", data: trackingReport(t, map[string]string{"root_dispersion": "1e999"})},
	} {
		t.Run(test.name, func(t *testing.T) {
			if bound, err := trackingBound(test.data, now); err == nil {
				t.Fatalf("accepted untrusted report with bound %s", bound)
			}
		})
	}
	for _, field := range []string{"reference_time", "correction", "last_offset", "rms_offset", "frequency", "residual_frequency", "skew", "root_delay", "root_dispersion", "interval"} {
		for _, value := range []string{"NaN", "+Inf", "-Inf", "invalid"} {
			t.Run(field+"/"+value, func(t *testing.T) {
				if _, err := trackingBound(trackingReport(t, map[string]string{field: value}), now); err == nil {
					t.Fatalf("accepted %s = %s", field, value)
				}
			})
		}
	}
}

func TestCheckpointUsesProtectedElapsedTime(t *testing.T) {
	utc := time.Unix(1770000010, 0)
	base := checkpoint{UTC: utc, Raw: time.Second, Uncertainty: 100 * time.Millisecond}
	for _, test := range []struct {
		name   string
		state  checkpoint
		now    clocks
		want   time.Duration
		reject bool
	}{
		{name: "drift and sampling latency", state: base, now: clocks{utc.Add(2 * time.Second), 3 * time.Second, time.Millisecond}, want: 101200 * time.Microsecond},
		{name: "positive wall correction", state: base, now: clocks{utc.Add(2100 * time.Millisecond), 3 * time.Second, 0}, want: 200200 * time.Microsecond},
		{name: "negative wall correction", state: base, now: clocks{utc.Add(1900 * time.Millisecond), 3 * time.Second, 0}, want: 200200 * time.Microsecond},
		{name: "freshness boundary", state: base, now: clocks{utc.Add(5 * time.Second), 6 * time.Second, 0}, want: 100500 * time.Microsecond},
		{name: "stale despite unchanged wall", state: base, now: clocks{utc, 6*time.Second + time.Nanosecond, 0}, reject: true},
		{name: "raw counter backwards", state: base, now: clocks{utc, time.Second - time.Nanosecond, 0}, reject: true},
		{name: "wall jumps forward", state: base, now: clocks{utc.Add(4 * time.Second), 3 * time.Second, 0}, reject: true},
		{name: "wall jumps backward", state: base, now: clocks{utc.Add(-time.Second), 3 * time.Second, 0}, reject: true},
		{name: "correction consumes remaining budget", state: base, now: clocks{utc.Add(3 * time.Second), 3 * time.Second, 0}, reject: true},
		{name: "sampling consumes remaining budget", state: base, now: clocks{utc.Add(2 * time.Second), 3 * time.Second, 900 * time.Millisecond}, reject: true},
		{name: "missing UTC", state: checkpoint{Raw: time.Second}, now: clocks{utc, time.Second, 0}, reject: true},
		{name: "negative raw checkpoint", state: checkpoint{UTC: utc, Raw: -time.Nanosecond}, now: clocks{utc, time.Second, 0}, reject: true},
		{name: "negative uncertainty", state: checkpoint{UTC: utc, Raw: time.Second, Uncertainty: -time.Nanosecond}, now: clocks{utc, time.Second, 0}, reject: true},
		{name: "excess checkpoint uncertainty", state: checkpoint{UTC: utc, Raw: time.Second, Uncertainty: MaxUncertainty + time.Nanosecond}, now: clocks{utc, time.Second, 0}, reject: true},
		{name: "exact uncertainty limit", state: checkpoint{UTC: utc, Raw: time.Second, Uncertainty: MaxUncertainty}, now: clocks{utc, time.Second, 0}, want: MaxUncertainty},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.state.sample(test.now)
			if test.reject {
				if err == nil {
					t.Fatalf("accepted invalid checkpoint with sample %+v", got)
				}
				return
			}
			if err != nil || got.Uncertainty != test.want || !got.Time.Equal(test.now.UTC) {
				t.Fatalf("sample = (%+v, %v), want UTC %s with uncertainty %s", got, err, test.now.UTC, test.want)
			}
		})
	}
}

func TestMonitorRetriesBootstrapButNeverReopensIt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	unsynchronized := errors.New("not synchronized")
	connectionLost := errors.New("time connection lost")
	var at clocks
	var observations, publications, invalidations int
	err := monitor(ctx, func(context.Context) (checkpoint, error) {
		observations++
		switch observations {
		case 1, 2:
			return checkpoint{}, unsynchronized
		case 3:
			return checkpoint{at.UTC, at.Raw, time.Millisecond}, nil
		default:
			return checkpoint{}, connectionLost
		}
	}, func() (clocks, error) {
		at.Raw += time.Millisecond
		at.UTC = time.Unix(1770000010, 0).Add(at.Raw)
		return at, nil
	}, func(checkpoint) error {
		publications++
		return nil
	}, func() error {
		invalidations++
		return nil
	}, time.Nanosecond)
	if !errors.Is(err, connectionLost) || observations != 4 || publications != 1 || invalidations != 2 {
		t.Fatalf("monitor = %v, observations=%d publications=%d invalidations=%d", err, observations, publications, invalidations)
	}
}

func TestMonitorRejectsClockDiscontinuityBeforeRefreshing(t *testing.T) {
	for _, test := range []struct {
		name       string
		elapsed    time.Duration
		correction time.Duration
	}{
		{name: "counter regresses", elapsed: -time.Nanosecond},
		{name: "guest paused", elapsed: maxStatusAge + time.Nanosecond},
		{name: "wall jumps", elapsed: time.Millisecond, correction: 2 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			initial := clocks{time.Unix(1770000010, 0), time.Second, 0}
			var reads, observations, publications, invalidations int
			err := monitor(ctx, func(context.Context) (checkpoint, error) {
				observations++
				return checkpoint{initial.UTC, initial.Raw, time.Millisecond}, nil
			}, func() (clocks, error) {
				reads++
				if reads <= 2 {
					return initial, nil
				}
				return clocks{initial.UTC.Add(test.elapsed + test.correction), initial.Raw + test.elapsed, 0}, nil
			}, func(checkpoint) error { publications++; return nil }, func() error { invalidations++; return nil }, time.Nanosecond)
			if err == nil || errors.Is(err, context.DeadlineExceeded) || observations != 1 || publications != 1 || invalidations != 2 {
				t.Fatalf("monitor = %v, observations=%d publications=%d invalidations=%d", err, observations, publications, invalidations)
			}
		})
	}
}

func TestMonitorBoundsBootstrapWithProtectedTime(t *testing.T) {
	for _, elapsed := range []time.Duration{-time.Nanosecond, BootstrapLimit + time.Nanosecond} {
		t.Run(elapsed.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var reads, observations, invalidations int
			err := monitor(ctx, func(context.Context) (checkpoint, error) {
				observations++
				return checkpoint{}, errors.New("not synchronized")
			}, func() (clocks, error) {
				reads++
				raw := time.Second
				if reads > 1 {
					raw += elapsed
				}
				return clocks{time.Unix(1770000010, 0), raw, 0}, nil
			}, func(checkpoint) error { t.Fatal("published during failed bootstrap"); return nil }, func() error { invalidations++; return nil }, time.Nanosecond)
			if err == nil || observations != 0 || invalidations != 2 {
				t.Fatalf("monitor = %v, observations=%d invalidations=%d", err, observations, invalidations)
			}
		})
	}
}

func TestMonitorInvalidatesOnFailure(t *testing.T) {
	injected := errors.New("injected failure")
	for _, stage := range []string{"initial invalidation", "clock read", "publication", "cancellation"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var publications, invalidations int
			initial := clocks{time.Unix(1770000010, 0), time.Second, 0}
			err := monitor(ctx, func(context.Context) (checkpoint, error) {
				return checkpoint{initial.UTC, initial.Raw, time.Millisecond}, nil
			}, func() (clocks, error) {
				if stage == "clock read" {
					return clocks{}, injected
				}
				return initial, nil
			}, func(checkpoint) error {
				publications++
				if stage == "publication" {
					return injected
				}
				cancel()
				return nil
			}, func() error {
				invalidations++
				if stage == "initial invalidation" {
					return injected
				}
				return nil
			}, time.Hour)
			wantErr, wantInvalidations, wantPublications := injected, 2, 0
			switch stage {
			case "initial invalidation":
				wantInvalidations = 1
			case "publication":
				wantPublications = 1
			case "cancellation":
				wantErr, wantPublications = context.Canceled, 1
			}
			if !errors.Is(err, wantErr) || invalidations != wantInvalidations || publications != wantPublications {
				t.Fatalf("monitor = %v, invalidations=%d publications=%d", err, invalidations, publications)
			}
		})
	}
}

func TestMonitorReportsInvalidationFailure(t *testing.T) {
	clockFailure := errors.New("clock read failed")
	cleanupFailure := errors.New("checkpoint removal failed")
	invalidations := 0
	err := monitor(context.Background(), nil, func() (clocks, error) {
		return clocks{}, clockFailure
	}, nil, func() error {
		invalidations++
		if invalidations > 1 {
			return cleanupFailure
		}
		return nil
	}, time.Hour)
	if !errors.Is(err, clockFailure) || !errors.Is(err, cleanupFailure) || invalidations != 2 {
		t.Fatalf("monitor = %v, invalidations=%d", err, invalidations)
	}
}
