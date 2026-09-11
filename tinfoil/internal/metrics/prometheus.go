package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"tinfoil/internal/auth"
	"tinfoil/internal/config"
)

var cpuLabels = []string{"id", "domain", "image", "cpu_type"}
var cpuDescriptors = []*prometheus.Desc{
	prometheus.NewDesc("tfshim_cpu_utilization_percent", "CPU utilization percentage", cpuLabels, nil),
	prometheus.NewDesc("tfshim_cpu_memory_used_gb", "CPU memory used in GB", cpuLabels, nil),
	prometheus.NewDesc("tfshim_cpu_memory_total_gb", "CPU memory total in GB", cpuLabels, nil),
}

type cpuCollector struct{ metadata *config.Metadata }

func (*cpuCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, descriptor := range cpuDescriptors {
		ch <- descriptor
	}
}

func (c *cpuCollector) Collect(ch chan<- prometheus.Metric) {
	snapshot, err := Collect(c.metadata)
	if err != nil {
		ch <- prometheus.NewInvalidMetric(cpuDescriptors[0], err)
		return
	}
	labels := []string{snapshot.ID, snapshot.Domain, snapshot.Image, snapshot.CPUType}
	values := []int{snapshot.CPUUtil, snapshot.CPUMemUtil, snapshot.CPUMemTotal}
	for index, value := range values {
		ch <- prometheus.MustNewConstMetric(cpuDescriptors[index], prometheus.GaugeValue, float64(value), labels...)
	}
}

func HandlePrometheusMetrics(metadata *config.Metadata, apiKey string) http.HandlerFunc {
	return PrometheusHandler(apiKey, &cpuCollector{metadata: metadata})
}

// PrometheusHandler gives each handler its own registry and checks credentials
// before invoking the collector.
func PrometheusHandler(apiKey string, collector prometheus.Collector) http.HandlerFunc {
	registry := prometheus.NewRegistry()
	registry.MustRegister(collector)
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	return func(w http.ResponseWriter, r *http.Request) {
		if !auth.RequireBearer(apiKey, w, r) {
			return
		}
		handler.ServeHTTP(w, r)
	}
}
