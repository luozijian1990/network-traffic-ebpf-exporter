package collector

import (
	"log"
	"net"

	"ebpf-traffic-exporter/internal/ebpf"
	"ebpf-traffic-exporter/internal/utils"

	"github.com/prometheus/client_golang/prometheus"
)

// TrafficCollector implements prometheus.Collector
type TrafficCollector struct {
	objects *ebpf.BpfObjects
	desc    *prometheus.Desc
}

func NewTrafficCollector(objs *ebpf.BpfObjects) *TrafficCollector {
	return &TrafficCollector{
		objects: objs,
		desc: prometheus.NewDesc(
			"network_traffic_bytes_total",
			"Total bytes of network traffic",
			[]string{"src_ip", "dst_ip", "direction", "ip_type"},
			nil,
		),
	}
}

func (c *TrafficCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c *TrafficCollector) Collect(ch chan<- prometheus.Metric) {
	var key ebpf.BpfKeyT
	var val ebpf.BpfValueT
	iter := c.objects.TrafficStats.Iterate()
	for iter.Next(&key, &val) {
		src := utils.IntToIP(key.SrcIp)
		dst := utils.IntToIP(key.DstIp)
		
		direction := "inbound"
		if key.Direction == 1 {
			direction = "outbound"
		}

		ipType := "public"
		if utils.IsPrivateIP(net.ParseIP(dst)) {
			ipType = "private"
		}

		ch <- prometheus.MustNewConstMetric(
			c.desc,
			prometheus.CounterValue,
			float64(val.Bytes),
			src, dst, direction, ipType,
		)
	}
	if err := iter.Err(); err != nil {
		log.Printf("Map iteration error: %v", err)
	}
}
