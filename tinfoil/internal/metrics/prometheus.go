package metrics

import (
	"errors"
	"log"
	"math"
	"net/http"
	"strconv"

	"tinfoil/internal/auth"
	"tinfoil/internal/config"
)

const (
	prometheusContentType    = "text/plain; version=0.0.4; charset=utf-8; escaping=underscores"
	maxPrometheusOutputBytes = 256 << 10
)

var errPrometheusOutputTooLarge = errors.New("Prometheus output exceeds size limit")

type prometheusValues struct {
	id          string
	domain      string
	image       string
	cpuType     string
	gpuType     string
	cpuUtil     float64
	gpuUtil     float64
	cpuMemUsed  float64
	gpuMemUsed  float64
	cpuMemTotal float64
	gpuMemTotal float64
}

type prometheusMetric struct {
	name  string
	help  string
	value float64
}

type boundedTextBuffer struct {
	data []byte
}

func (buffer *boundedTextBuffer) appendString(value string) error {
	if len(value) > maxPrometheusOutputBytes-len(buffer.data) {
		return errPrometheusOutputTooLarge
	}
	buffer.data = append(buffer.data, value...)
	return nil
}

func prometheusValuesFromMetrics(metrics *Metrics) prometheusValues {
	gpuType := metrics.GPUType
	gpuUtil := float64(metrics.GPUUtil)
	gpuMemUsed := float64(metrics.GPUMemUtil)
	gpuMemTotal := float64(metrics.GPUMemTotal)
	if gpuType == "" {
		gpuType = "none"
		gpuUtil = 0
		gpuMemUsed = 0
		gpuMemTotal = 0
	}
	return prometheusValues{
		id:          metrics.ID,
		domain:      metrics.Domain,
		image:       metrics.Image,
		cpuType:     metrics.CPUType,
		gpuType:     gpuType,
		cpuUtil:     float64(metrics.CPUUtil),
		gpuUtil:     gpuUtil,
		cpuMemUsed:  float64(metrics.CPUMemUtil),
		gpuMemUsed:  gpuMemUsed,
		cpuMemTotal: float64(metrics.CPUMemTotal),
		gpuMemTotal: gpuMemTotal,
	}
}

func appendPrometheusLabelValue(buffer *boundedTextBuffer, value string) error {
	start := 0
	for index := 0; index < len(value); index++ {
		var escaped string
		switch value[index] {
		case '\\':
			escaped = `\\`
		case '"':
			escaped = `\"`
		case '\n':
			escaped = `\n`
		default:
			continue
		}
		if err := buffer.appendString(value[start:index]); err != nil {
			return err
		}
		if err := buffer.appendString(escaped); err != nil {
			return err
		}
		start = index + 1
	}
	return buffer.appendString(value[start:])
}

func appendPrometheusMetric(buffer *boundedTextBuffer, metric prometheusMetric, values prometheusValues) error {
	if math.IsNaN(metric.value) || math.IsInf(metric.value, 0) {
		return errors.New("Prometheus metric value is not finite")
	}
	for _, value := range []string{"# HELP ", metric.name, " ", metric.help, "\n# TYPE ", metric.name, " gauge\n", metric.name, `{cpu_type="`} {
		if err := buffer.appendString(value); err != nil {
			return err
		}
	}
	labels := [...]struct {
		separator string
		value     string
	}{
		{value: values.cpuType},
		{separator: `",domain="`, value: values.domain},
		{separator: `",gpu_type="`, value: values.gpuType},
		{separator: `",id="`, value: values.id},
		{separator: `",image="`, value: values.image},
	}
	for _, label := range labels {
		if err := buffer.appendString(label.separator); err != nil {
			return err
		}
		if err := appendPrometheusLabelValue(buffer, label.value); err != nil {
			return err
		}
	}
	if err := buffer.appendString(`"} `); err != nil {
		return err
	}
	if err := buffer.appendString(strconv.FormatFloat(metric.value, 'g', -1, 64)); err != nil {
		return err
	}
	return buffer.appendString("\n")
}

func renderPrometheusMetrics(values prometheusValues) ([]byte, error) {
	metrics := [...]prometheusMetric{
		{name: "tfshim_cpu_memory_total_gb", help: "CPU memory total in GB", value: values.cpuMemTotal},
		{name: "tfshim_cpu_memory_used_gb", help: "CPU memory used in GB", value: values.cpuMemUsed},
		{name: "tfshim_cpu_utilization_percent", help: "CPU utilization percentage", value: values.cpuUtil},
		{name: "tfshim_gpu_memory_total_gb", help: "GPU memory total in GB", value: values.gpuMemTotal},
		{name: "tfshim_gpu_memory_used_gb", help: "GPU memory used in GB", value: values.gpuMemUsed},
		{name: "tfshim_gpu_utilization_percent", help: "GPU utilization percentage", value: values.gpuUtil},
	}
	buffer := boundedTextBuffer{data: make([]byte, 0, 2048)}
	for _, metric := range metrics {
		if err := appendPrometheusMetric(&buffer, metric, values); err != nil {
			return nil, err
		}
	}
	return buffer.data, nil
}

func handlePrometheusMetrics(metadata *config.Metadata, metricsAPIKey string, collect func(*config.Metadata) (*Metrics, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !auth.RequireBearer(metricsAPIKey, w, r) {
			return
		}

		metrics, err := collect(metadata)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		output, err := renderPrometheusMetrics(prometheusValuesFromMetrics(metrics))
		if err != nil {
			log.Printf("Prometheus metrics encoding failed: %v", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", prometheusContentType)
		_, _ = w.Write(output)
	}
}

// HandlePrometheusMetrics handles the /metrics endpoint for Prometheus scraping.
func HandlePrometheusMetrics(metadata *config.Metadata, metricsAPIKey string) http.HandlerFunc {
	return handlePrometheusMetrics(metadata, metricsAPIKey, collectMetrics)
}
