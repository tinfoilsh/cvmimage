package metrics

import (
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var containerRestartReasons = []string{
	"oom_killed",
	"nonzero_exit",
	"clean_exit",
	"replacement",
	"unknown",
}

type containerStatusSnapshot struct {
	Containers []containerMetricStatus `json:"containers"`
}

type containerMetricStatus struct {
	Name          string                 `json:"name"`
	Status        string                 `json:"status"`
	RestartCount  int                    `json:"restart_count"`
	RestartCounts map[string]int         `json:"restart_counts"`
	OOMKilled     bool                   `json:"oom_killed"`
	ExitCode      int                    `json:"exit_code"`
	Health        *containerMetricHealth `json:"health"`
}

type containerMetricHealth struct {
	Status        string `json:"status"`
	FailingStreak int    `json:"failing_streak"`
}

type containerPrometheusSnapshot struct {
	metrics    Metrics
	containers []containerMetricStatus
}

type containerPrometheusCollector struct {
	mu sync.RWMutex

	snapshot containerPrometheusSnapshot

	restarting          *prometheus.Desc
	restarts            *prometheus.Desc
	oomKilled           *prometheus.Desc
	lastExitCode        *prometheus.Desc
	state               *prometheus.Desc
	healthStatus        *prometheus.Desc
	healthFailingStreak *prometheus.Desc
}

func newContainerPrometheusCollector() *containerPrometheusCollector {
	containerLabels := append(append([]string{}, baseLabels...), "container")
	return &containerPrometheusCollector{
		restarting: prometheus.NewDesc(
			"tfshim_container_restarting",
			"Whether the container is currently restarting (1 for restarting, 0 otherwise)",
			containerLabels,
			nil,
		),
		restarts: prometheus.NewDesc(
			"tfshim_container_restarts_total",
			"Cumulative container restarts observed during the enclave lifecycle, partitioned by reason",
			append(append([]string{}, containerLabels...), "reason"),
			nil,
		),
		oomKilled: prometheus.NewDesc(
			"tfshim_container_oom_killed",
			"Whether the container's current state reports an OOM kill (1 for OOM killed, 0 otherwise)",
			containerLabels,
			nil,
		),
		lastExitCode: prometheus.NewDesc(
			"tfshim_container_last_exit_code",
			"Last exit code reported by the container runtime",
			containerLabels,
			nil,
		),
		state: prometheus.NewDesc(
			"tfshim_container_state",
			"Current container runtime state",
			append(append([]string{}, containerLabels...), "state"),
			nil,
		),
		healthStatus: prometheus.NewDesc(
			"tfshim_container_health_status",
			"Current container health-check status",
			append(append([]string{}, containerLabels...), "status"),
			nil,
		),
		healthFailingStreak: prometheus.NewDesc(
			"tfshim_container_health_failing_streak",
			"Number of consecutive failed container health checks",
			containerLabels,
			nil,
		),
	}
}

func (c *containerPrometheusCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.restarting
	ch <- c.restarts
	ch <- c.oomKilled
	ch <- c.lastExitCode
	ch <- c.state
	ch <- c.healthStatus
	ch <- c.healthFailingStreak
}

func (c *containerPrometheusCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	snapshot := c.snapshot
	c.mu.RUnlock()

	for _, container := range snapshot.containers {
		labels := containerMetricLabels(&snapshot.metrics, container.Name)
		ch <- prometheus.MustNewConstMetric(c.restarting, prometheus.GaugeValue, boolFloat(container.Status == "restarting"), labels...)
		ch <- prometheus.MustNewConstMetric(c.oomKilled, prometheus.GaugeValue, boolFloat(container.OOMKilled), labels...)
		ch <- prometheus.MustNewConstMetric(c.lastExitCode, prometheus.GaugeValue, float64(container.ExitCode), labels...)

		state := container.Status
		if state == "" {
			state = "unknown"
		}
		ch <- prometheus.MustNewConstMetric(c.state, prometheus.GaugeValue, 1, append(labels, state)...)

		healthStatus := "none"
		failingStreak := 0
		if container.Health != nil {
			healthStatus = container.Health.Status
			if healthStatus == "" {
				healthStatus = "unknown"
			}
			failingStreak = container.Health.FailingStreak
		}
		ch <- prometheus.MustNewConstMetric(c.healthStatus, prometheus.GaugeValue, 1, append(labels, healthStatus)...)
		ch <- prometheus.MustNewConstMetric(c.healthFailingStreak, prometheus.GaugeValue, float64(failingStreak), labels...)

		restartCounts := normalizedRestartCounts(container)
		for _, reason := range containerRestartReasons {
			ch <- prometheus.MustNewConstMetric(c.restarts, prometheus.CounterValue, float64(restartCounts[reason]), append(labels, reason)...)
		}
	}
}

func (c *containerPrometheusCollector) update(metrics *Metrics, containers []containerMetricStatus) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snapshot.metrics = *metrics
	c.snapshot.containers = append([]containerMetricStatus(nil), containers...)
}

func loadContainerMetricStatuses(path string) ([]containerMetricStatus, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var snapshot containerStatusSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, err
	}
	return snapshot.Containers, nil
}

func normalizedRestartCounts(container containerMetricStatus) map[string]int {
	counts := make(map[string]int, len(containerRestartReasons))
	recorded := 0
	for _, reason := range containerRestartReasons {
		if count := container.RestartCounts[reason]; count > 0 {
			counts[reason] = count
			recorded += count
		}
	}
	if recorded < container.RestartCount {
		counts["unknown"] += container.RestartCount - recorded
	}
	return counts
}

func containerMetricLabels(metrics *Metrics, containerName string) []string {
	gpuType := metrics.GPUType
	if gpuType == "" {
		gpuType = "none"
	}
	return []string{
		metrics.ID,
		metrics.Domain,
		metrics.Image,
		metrics.CPUType,
		gpuType,
		containerName,
	}
}

func boolFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}
