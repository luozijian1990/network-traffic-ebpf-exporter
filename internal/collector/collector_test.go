package collector

import (
	"net"
	"strings"
	"testing"

	ctbackend "ebpf-traffic-exporter/internal/conntrack"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type snapshotSource map[ctbackend.TrafficKey]uint64

func (s snapshotSource) Snapshot() map[ctbackend.TrafficKey]uint64 { return s }

func TestTrafficCollectorKeepsMainMetricSchema(t *testing.T) {
	src, _ := ctbackend.IPv4ToUint32(net.ParseIP("10.0.0.1"))
	dst, _ := ctbackend.IPv4ToUint32(net.ParseIP("8.8.8.8"))
	collector := NewTrafficCollector(snapshotSource{
		{Src: src, Dst: dst, Direction: ctbackend.Outbound}: 123,
	})
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(collector)
	want := `
# HELP network_traffic_bytes_total Total bytes of network traffic observed since exporter startup
# TYPE network_traffic_bytes_total counter
network_traffic_bytes_total{direction="outbound",dst_ip="8.8.8.8",ip_type="public",src_ip="10.0.0.1"} 123
`
	if err := testutil.GatherAndCompare(registry, strings.NewReader(want), "network_traffic_bytes_total"); err != nil {
		t.Fatal(err)
	}
}
