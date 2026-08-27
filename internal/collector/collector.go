package collector

import (
	"net"

	ctbackend "ebpf-traffic-exporter/internal/conntrack"
	"ebpf-traffic-exporter/internal/utils"

	"github.com/prometheus/client_golang/prometheus"
)

// TrafficCollector exports the latest in-memory IP aggregate. It never dumps
// conntrack from the Prometheus scrape path.
type TrafficCollector struct {
	source interface {
		Snapshot() map[ctbackend.TrafficKey]uint64
	}
	desc *prometheus.Desc
}

func NewTrafficCollector(source interface {
	Snapshot() map[ctbackend.TrafficKey]uint64
}) *TrafficCollector {
	return &TrafficCollector{
		source: source,
		desc: prometheus.NewDesc(
			"network_traffic_bytes_total",
			"Total bytes of network traffic observed since exporter startup",
			[]string{"src_ip", "dst_ip", "direction", "ip_type"},
			nil,
		),
	}
}

func (c *TrafficCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *TrafficCollector) Collect(ch chan<- prometheus.Metric) {
	for key, bytes := range c.source.Snapshot() {
		dst := ctbackend.Uint32ToIPv4(key.Dst)
		ipType := "public"
		if utils.IsPrivateIP(net.ParseIP(dst)) {
			ipType = "private"
		}
		ch <- prometheus.MustNewConstMetric(
			c.desc, prometheus.CounterValue, float64(bytes),
			ctbackend.Uint32ToIPv4(key.Src), dst, key.Direction.String(), ipType,
		)
	}
}
