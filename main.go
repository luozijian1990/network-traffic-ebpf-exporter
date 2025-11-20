package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb bpf bpf/traffic.c -- -I.

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	ifaceName = flag.String("iface", "eth0", "Network interface to attach to")
	addr      = flag.String("addr", ":9091", "Address to listen on for metrics")
)

// TrafficCollector implements prometheus.Collector
type TrafficCollector struct {
	objects *bpfObjects
	desc    *prometheus.Desc
}

func NewTrafficCollector(objs *bpfObjects) *TrafficCollector {
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
	var key bpfKeyT
	var val bpfValueT
	iter := c.objects.TrafficStats.Iterate()
	for iter.Next(&key, &val) {
		src := intToIP(key.SrcIp)
		dst := intToIP(key.DstIp)
		
		direction := "inbound"
		if key.Direction == 1 {
			direction = "outbound"
		}

		ipType := "public"
		if isPrivateIP(net.ParseIP(dst)) {
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

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	privateIPBlocks := []*net.IPNet{
		parseCIDR("10.0.0.0/8"),
		parseCIDR("172.16.0.0/12"),
		parseCIDR("192.168.0.0/16"),
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func parseCIDR(s string) *net.IPNet {
	_, block, _ := net.ParseCIDR(s)
	return block
}

func intToIP(ip uint32) string {
	result := make(net.IP, 4)
	result[0] = byte(ip)
	result[1] = byte(ip >> 8)
	result[2] = byte(ip >> 16)
	result[3] = byte(ip >> 24)
	return result.String()
}

func attachTC(ifaceName string, objs *bpfObjects) (func(), error) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %v", ifaceName, err)
	}
	log.Printf("Found interface %s (index: %d)", ifaceName, link.Attrs().Index)

	// Create clsact qdisc
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if !os.IsExist(err) {
			return nil, fmt.Errorf("add clsact qdisc: %v", err)
		}
		log.Printf("clsact qdisc already exists on %s", ifaceName)
	} else {
		log.Printf("Added clsact qdisc to %s", ifaceName)
	}

	// Attach Ingress
	ingressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           objs.TcIngress.FD(),
		Name:         "tc_ingress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(ingressFilter); err != nil {
		return nil, fmt.Errorf("add ingress filter: %v", err)
	}
	log.Printf("Attached TC Ingress filter")

	// Attach Egress
	egressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           objs.TcEgress.FD(),
		Name:         "tc_egress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(egressFilter); err != nil {
		return nil, fmt.Errorf("add egress filter: %v", err)
	}
	log.Printf("Attached TC Egress filter")

	cleanup := func() {
		log.Println("Cleaning up TC filters...")
		netlink.FilterDel(ingressFilter)
		netlink.FilterDel(egressFilter)
		log.Println("TC filters removed")
	}
	return cleanup, nil
}

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	log.Println("Loading eBPF objects...")
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	cleanup, err := attachTC(*ifaceName, &objs)
	if err != nil {
		log.Fatalf("attaching TC: %v", err)
	}
	defer cleanup()

	log.Printf("Attached eBPF program to %s successfully", *ifaceName)

	// Register collector
	collector := NewTrafficCollector(&objs)
	prometheus.MustRegister(collector)

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Printf("Serving metrics on %s", *addr)
		log.Fatal(http.ListenAndServe(*addr, nil))
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	sig := <-stop
	log.Printf("Received signal: %v. Exiting...", sig)
}
