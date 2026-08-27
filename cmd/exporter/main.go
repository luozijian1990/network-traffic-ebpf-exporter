package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ebpf-traffic-exporter/internal/collector"
	ctbackend "ebpf-traffic-exporter/internal/conntrack"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	ifaceName    = flag.String("iface", "eth0", "Interface whose IPv4 addresses define the local endpoint")
	addr         = flag.String("addr", ":9091", "Address to listen on for metrics")
	dumpInterval = flag.Duration("dump-interval", 30*time.Second, "Interval between IPv4 conntrack table dumps")
	maxEntries   = flag.Int("max-entries", 10240, "Maximum number of IP-level aggregate keys")
)

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if *dumpInterval <= 0 {
		return fmt.Errorf("--dump-interval must be greater than zero")
	}
	if *maxEntries <= 0 {
		return fmt.Errorf("--max-entries must be greater than zero")
	}
	if err := ctbackend.CheckAccounting(ctbackend.AccountingPath); err != nil {
		return err
	}
	if err := ctbackend.CheckEvents(ctbackend.EventsPath); err != nil {
		return err
	}
	localIPs, err := ctbackend.InterfaceIPv4s(*ifaceName)
	if err != nil {
		return err
	}
	engine := ctbackend.NewEngine(localIPs, *maxEntries)
	manager, err := ctbackend.NewManager(engine, *dumpInterval, prometheus.DefaultRegisterer)
	if err != nil {
		return err
	}
	defer manager.Close()
	prometheus.MustRegister(collector.NewTrafficCollector(engine))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go manager.Run(ctx)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !manager.Healthy(time.Now()) {
			http.Error(w, "conntrack collector is stale", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	server := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	serveErrors := make(chan error, 1)
	go func() {
		log.Printf("serving metrics on %s for interface %s (%d local IPv4 addresses)", *addr, *ifaceName, len(localIPs))
		serveErrors <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-serveErrors:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
