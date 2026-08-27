package conntrack

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	nfconntrack "github.com/florianl/go-conntrack"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	AccountingPath = "/proc/sys/net/netfilter/nf_conntrack_acct"
	EventsPath     = "/proc/sys/net/netfilter/nf_conntrack_events"
)

const eventReadBufferBytes = 4 << 20

type netfilterConn interface {
	Dump(nfconntrack.Table, nfconntrack.Family) ([]nfconntrack.Con, error)
	Close() error
}

type Manager struct {
	engine           *Engine
	nfct             netfilterConn
	interval         time.Duration
	failureThreshold int
	lastSuccessNanos atomic.Int64
	consecutive      atomic.Int64
	eventConnected   atomic.Bool
	metrics          *selfMetrics
	eventCtx         context.Context
	eventCancel      context.CancelFunc
	eventWG          sync.WaitGroup
	closeOnce        sync.Once
	closeErr         error
}

type selfMetrics struct {
	dumpDuration        prometheus.Histogram
	dumpEntries         prometheus.Gauge
	dumpErrors          prometheus.Counter
	consecutiveFailures prometheus.Gauge
	reconnects          prometheus.Counter
	lastSuccess         prometheus.Gauge
	previousEntries     prometheus.Gauge
	aggregateEntries    prometheus.Gauge
	droppedKeys         prometheus.Counter
	skipped             *prometheus.CounterVec
	counterResets       prometheus.Counter
	destroyEvents       prometheus.Counter
	destroyBytes        prometheus.Counter
	eventErrors         prometheus.Counter
	eventReconnects     prometheus.Counter
	eventConnected      prometheus.Gauge
}

func NewManager(engine *Engine, interval time.Duration, registerer prometheus.Registerer) (*Manager, error) {
	nfct, err := openNetfilter()
	if err != nil {
		return nil, permissionHint("opening conntrack netlink socket", err)
	}
	eventCtx, eventCancel := context.WithCancel(context.Background())
	m := &Manager{
		engine: engine, nfct: nfct, interval: interval, failureThreshold: 3,
		metrics: newSelfMetrics(registerer), eventCtx: eventCtx, eventCancel: eventCancel,
	}
	eventSocket, eventErrors, err := m.openAndRegisterEvents()
	if err != nil {
		eventCancel()
		_ = nfct.Close()
		return nil, permissionHint("subscribing to conntrack DESTROY events", err)
	}
	m.eventConnected.Store(true)
	m.metrics.eventConnected.Set(1)
	m.eventWG.Add(1)
	go m.superviseEvents(eventSocket, eventErrors)
	return m, nil
}

func openNetfilter() (netfilterConn, error) {
	return nfconntrack.Open(&nfconntrack.Config{DisableNSLockThread: true})
}

func newSelfMetrics(registerer prometheus.Registerer) *selfMetrics {
	m := &selfMetrics{
		dumpDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "network_conntrack_dump_duration_seconds", Help: "Duration of conntrack table dump attempts.",
		}),
		dumpEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "network_conntrack_dump_entries", Help: "Number of entries returned by the latest successful dump.",
		}),
		dumpErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "network_conntrack_dump_errors_total", Help: "Total number of failed conntrack dumps.",
		}),
		consecutiveFailures: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "network_conntrack_consecutive_failures", Help: "Current number of consecutive conntrack dump failures.",
		}),
		reconnects: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "network_conntrack_reconnects_total", Help: "Total number of successful conntrack netlink reconnects.",
		}),
		lastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "network_conntrack_last_success_timestamp_seconds", Help: "Unix timestamp of the latest successful conntrack dump.",
		}),
		previousEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "network_conntrack_previous_entries", Help: "Number of connection baselines retained after the latest dump.",
		}),
		aggregateEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "network_conntrack_agg_entries", Help: "Number of IP-level aggregate keys currently retained.",
		}),
		droppedKeys: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "network_conntrack_dropped_keys_total", Help: "Total new aggregate keys dropped because max-entries was reached.",
		}),
		skipped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "network_conntrack_skipped_connections_total", Help: "Total conntrack tuples or entries skipped, by bounded reason.",
		}, []string{"reason"}),
		counterResets: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "network_conntrack_counter_resets_total", Help: "Total origin or reply counters observed below their previous value.",
		}),
		destroyEvents: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "network_conntrack_destroy_events_total", Help: "Total conntrack DESTROY events received.",
		}),
		destroyBytes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "network_conntrack_destroy_bytes_total", Help: "Total bytes added from conntrack DESTROY events.",
		}),
		eventErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "network_conntrack_event_errors_total", Help: "Total conntrack event listener failures.",
		}),
		eventReconnects: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "network_conntrack_event_reconnects_total", Help: "Total successful conntrack event listener reconnects.",
		}),
		eventConnected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "network_conntrack_event_connected", Help: "Whether the conntrack DESTROY event listener is connected.",
		}),
	}
	registerer.MustRegister(
		m.dumpDuration, m.dumpEntries, m.dumpErrors, m.consecutiveFailures,
		m.reconnects, m.lastSuccess, m.previousEntries, m.aggregateEntries,
		m.droppedKeys, m.skipped, m.counterResets, m.destroyEvents,
		m.destroyBytes, m.eventErrors, m.eventReconnects, m.eventConnected,
	)
	return m
}

func (m *Manager) Run(ctx context.Context) {
	if err := m.dumpOnce(); err != nil {
		log.Printf("%v", permissionHint("initial conntrack dump", err))
	}
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.dumpOnce(); err != nil {
				log.Printf("conntrack dump failed: %v", err)
				if int(m.consecutive.Load()) >= m.failureThreshold {
					m.reconnect(ctx)
				}
			}
		}
	}
}

func (m *Manager) Close() error {
	m.closeOnce.Do(func() {
		m.eventCancel()
		m.eventWG.Wait()
		if m.nfct != nil {
			m.closeErr = m.nfct.Close()
		}
	})
	return m.closeErr
}

func (m *Manager) dumpOnce() error {
	started := time.Now()
	connections, err := m.nfct.Dump(nfconntrack.Conntrack, nfconntrack.IPv4)
	m.metrics.dumpDuration.Observe(time.Since(started).Seconds())
	if err != nil {
		m.recordFailure()
		return err
	}
	m.recordSuccess(connections)
	return nil
}

func (m *Manager) recordFailure() {
	m.metrics.dumpErrors.Inc()
	failures := m.consecutive.Add(1)
	m.metrics.consecutiveFailures.Set(float64(failures))
}

func (m *Manager) recordSuccess(connections []nfconntrack.Con) {
	stats := m.engine.Process(connections)
	m.recordProcessStats(stats)
	m.metrics.dumpEntries.Set(float64(len(connections)))
	now := time.Now()
	m.lastSuccessNanos.Store(now.UnixNano())
	m.metrics.lastSuccess.Set(float64(now.Unix()))
	m.consecutive.Store(0)
	m.metrics.consecutiveFailures.Set(0)
}

func (m *Manager) recordProcessStats(stats ProcessStats) {
	for reason, count := range stats.Skipped {
		m.metrics.skipped.WithLabelValues(reason).Add(float64(count))
	}
	m.metrics.droppedKeys.Add(float64(stats.DroppedKeys))
	m.metrics.counterResets.Add(float64(stats.CounterResets))
	m.metrics.previousEntries.Set(float64(stats.PreviousEntries))
	m.metrics.aggregateEntries.Set(float64(stats.AggregateEntries))
}

func (m *Manager) recordDestroy(connection nfconntrack.Con) int {
	m.metrics.destroyEvents.Inc()
	stats := m.engine.ProcessDestroy(connection)
	m.recordProcessStats(stats)
	m.metrics.destroyBytes.Add(float64(stats.AddedBytes))
	return 0
}

func (m *Manager) openAndRegisterEvents() (*nfconntrack.Nfct, <-chan error, error) {
	nfct, err := nfconntrack.Open(&nfconntrack.Config{DisableNSLockThread: true})
	if err != nil {
		return nil, nil, err
	}
	if err := nfct.Con.SetReadBuffer(eventReadBufferBytes); err != nil {
		_ = nfct.Con.Close()
		return nil, nil, fmt.Errorf("set conntrack event receive buffer: %w", err)
	}
	errors := nfct.AttachErrChan()
	if err := nfct.Register(m.eventCtx, nfconntrack.Conntrack, nfconntrack.NetlinkCtDestroy, m.recordDestroy); err != nil {
		// Register can fail before its shutdown goroutine starts, so close the
		// underlying socket directly instead of calling Nfct.Close.
		_ = nfct.Con.Close()
		return nil, nil, err
	}
	return nfct, errors, nil
}

func (m *Manager) superviseEvents(current *nfconntrack.Nfct, errors <-chan error) {
	defer m.eventWG.Done()
	for {
		select {
		case <-m.eventCtx.Done():
			m.setEventConnected(false)
			if err := current.Close(); err != nil {
				log.Printf("closing conntrack event socket failed: %v", err)
			}
			return
		case err, ok := <-errors:
			m.setEventConnected(false)
			m.metrics.eventErrors.Inc()
			if ok && err != nil {
				log.Printf("conntrack event listener failed: %v", err)
			} else {
				log.Printf("conntrack event listener stopped unexpectedly")
			}
			if err := current.Close(); err != nil {
				log.Printf("closing failed conntrack event socket: %v", err)
			}
		}

		for attempt := 0; ; attempt++ {
			if !waitForRetry(m.eventCtx, attempt) {
				return
			}
			next, nextErrors, err := m.openAndRegisterEvents()
			if err != nil {
				m.metrics.eventErrors.Inc()
				log.Printf("reopening conntrack event socket failed: %v", err)
				continue
			}
			current, errors = next, nextErrors
			m.setEventConnected(true)
			m.metrics.eventReconnects.Inc()
			log.Printf("conntrack DESTROY event listener reconnected")
			break
		}
	}
}

func (m *Manager) setEventConnected(connected bool) {
	m.eventConnected.Store(connected)
	if connected {
		m.metrics.eventConnected.Set(1)
		return
	}
	m.metrics.eventConnected.Set(0)
}

func waitForRetry(ctx context.Context, attempt int) bool {
	backoff := time.Second * time.Duration(1<<min(attempt, 5))
	if backoff > 30*time.Second {
		backoff = 30 * time.Second
	}
	timer := time.NewTimer(backoff)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (m *Manager) reconnect(ctx context.Context) {
	if m.nfct != nil {
		if err := m.nfct.Close(); err != nil {
			log.Printf("closing failed conntrack socket: %v", err)
		}
	}
	m.nfct = nil
	for attempt := 0; ; attempt++ {
		backoff := time.Second * time.Duration(1<<min(attempt, 5))
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		nfct, err := openNetfilter()
		if err != nil {
			log.Printf("reopening conntrack netlink socket failed: %v", err)
			continue
		}
		m.nfct = nfct
		m.engine.RequireBaseline()
		started := time.Now()
		connections, err := m.nfct.Dump(nfconntrack.Conntrack, nfconntrack.IPv4)
		m.metrics.dumpDuration.Observe(time.Since(started).Seconds())
		if err != nil {
			m.recordFailure()
			log.Printf("conntrack recovery baseline failed: %v", err)
			_ = m.nfct.Close()
			m.nfct = nil
			continue
		}
		m.recordSuccess(connections)
		m.metrics.reconnects.Inc()
		log.Printf("conntrack netlink socket reconnected; recovery dump stored as baseline")
		return
	}
}

func (m *Manager) Healthy(now time.Time) bool {
	if !m.eventConnected.Load() {
		return false
	}
	nanos := m.lastSuccessNanos.Load()
	if nanos == 0 {
		return false
	}
	staleAfter := maxDuration(3*m.interval, 2*time.Minute)
	return now.Sub(time.Unix(0, nanos)) <= staleAfter
}

func CheckAccounting(path string) error {
	return checkConntrackSetting(path, "nf_conntrack_acct")
}

func CheckEvents(path string) error {
	return checkConntrackSetting(path, "nf_conntrack_events")
}

func checkConntrackSetting(path, name string) error {
	remediation := fmt.Sprintf("sysctl -w net.netfilter.%s=1", name)
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s from %s: %w; enable it with: %s", name, path, err, remediation)
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(content)), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid %s value in %s: %w; enable it with: %s", name, path, err, remediation)
	}
	if value == 0 {
		return fmt.Errorf("%s is disabled; enable it with: %s", name, remediation)
	}
	return nil
}

func permissionHint(operation string, err error) error {
	return fmt.Errorf("%s: %w (conntrack Netlink access requires root or CAP_NET_ADMIN; for example: setcap cap_net_admin=+ep ./conntrack-traffic-exporter)", operation, err)
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
