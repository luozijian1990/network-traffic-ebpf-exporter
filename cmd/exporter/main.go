package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"ebpf-traffic-exporter/internal/collector"
	"ebpf-traffic-exporter/internal/ebpf"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	ifaceName = flag.String("iface", "eth0", "Network interface to attach to")
	addr      = flag.String("addr", ":9091", "Address to listen on for metrics")
)

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log.Println("Loading eBPF objects...")
	objs, err := ebpf.LoadObjects()
	if err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	cleanup, err := ebpf.AttachTC(*ifaceName, objs)
	if err != nil {
		log.Fatalf("attaching TC: %v", err)
	}
	defer cleanup()

	log.Printf("Attached eBPF program to %s successfully", *ifaceName)

	// Register collector
	coll := collector.NewTrafficCollector(objs)
	prometheus.MustRegister(coll)

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
