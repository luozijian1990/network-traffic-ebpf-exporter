package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() (result error) {
	// Reserve the HTTP address before changing any TC state.
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *addr, err)
	}
	defer listener.Close()

	log.Println("Loading eBPF objects...")
	objs, err := ebpf.LoadObjects()
	if err != nil {
		return fmt.Errorf("loading objects: %w", err)
	}
	defer objs.Close()

	cleanup, err := ebpf.AttachTC(*ifaceName, objs)
	if err != nil {
		return fmt.Errorf("attaching TC: %w", err)
	}
	defer func() { result = errors.Join(result, cleanup()) }()

	log.Printf("Attached eBPF program to %s successfully", *ifaceName)

	// Register collector
	coll := collector.NewTrafficCollector(objs)
	registry := prometheus.NewRegistry()
	registry.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}), coll)
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	serveErrors := make(chan error, 1)

	go func() {
		log.Printf("Serving metrics on %s", *addr)
		serveErrors <- server.Serve(listener)
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	select {
	case sig := <-stop:
		log.Printf("Received signal: %v. Exiting...", sig)
	case err := <-serveErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(ctx)
}
