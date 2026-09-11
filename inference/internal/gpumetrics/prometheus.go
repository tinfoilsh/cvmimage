package gpumetrics

import "github.com/prometheus/client_golang/prometheus"

var labels = []string{"id", "domain", "image", "cpu_type", "gpu_type"}
var descriptors = []*prometheus.Desc{
	prometheus.NewDesc("tfshim_cpu_utilization_percent", "CPU utilization percentage", labels, nil),
	prometheus.NewDesc("tfshim_gpu_utilization_percent", "GPU utilization percentage", labels, nil),
	prometheus.NewDesc("tfshim_cpu_memory_used_gb", "CPU memory used in GB", labels, nil),
	prometheus.NewDesc("tfshim_gpu_memory_used_gb", "GPU memory used in GB", labels, nil),
	prometheus.NewDesc("tfshim_cpu_memory_total_gb", "CPU memory total in GB", labels, nil),
	prometheus.NewDesc("tfshim_gpu_memory_total_gb", "GPU memory total in GB", labels, nil),
}

type collector struct{ snapshot func() (*Metrics, error) }

func (*collector) Describe(ch chan<- *prometheus.Desc) {
	for _, descriptor := range descriptors {
		ch <- descriptor
	}
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	snapshot, err := c.snapshot()
	if err != nil {
		ch <- prometheus.NewInvalidMetric(descriptors[0], err)
		return
	}
	gpuType := snapshot.GPUType
	values := []int{snapshot.CPUUtil, snapshot.GPUUtil, snapshot.CPUMemUtil, snapshot.GPUMemUtil, snapshot.CPUMemTotal, snapshot.GPUMemTotal}
	if gpuType == "" {
		gpuType = "none"
		values[1], values[3], values[5] = 0, 0, 0
	}
	labelValues := []string{snapshot.ID, snapshot.Domain, snapshot.Image, snapshot.CPUType, gpuType}
	for index, value := range values {
		ch <- prometheus.MustNewConstMetric(descriptors[index], prometheus.GaugeValue, float64(value), labelValues...)
	}
}
