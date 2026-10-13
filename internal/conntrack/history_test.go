package conntrack

import (
	"fmt"
	nfconntrack "github.com/florianl/go-conntrack"
	"testing"
)

func TestDelayedDestroyKeepsBaselineAcrossManyDumps(t *testing.T) {
	e := NewEngine(map[uint32]struct{}{mustIP(t, "10.0.0.1"): {}}, 10240)
	e.Process(nil)
	e.Process([]nfconntrack.Con{connection(t, 42, 100, 200, "10.0.0.1", "8.8.8.8")})
	for i := 0; i < 20; i++ {
		e.Process(nil)
	}
	e.ProcessDestroy(connection(t, 42, 1000, 2000, "10.0.0.1", "8.8.8.8"))
	assertTraffic(t, e, "10.0.0.1", "8.8.8.8", Outbound, 1000)
	assertTraffic(t, e, "8.8.8.8", "10.0.0.1", Inbound, 2000)
}

func TestConnectionTableOptionalIDIsUnambiguous(t *testing.T) {
	table := newConnectionTable[int]()
	key := connKey{Src: 1, Dst: 2, ID: 7}
	table.set(key, 10)
	missing := key
	missing.ID = 0
	if matched, value, ok := table.find(missing); !ok || matched != key || value != 10 {
		t.Fatal("missing ID did not match unique tuple")
	}
	other := key
	other.ID = 8
	table.set(other, 20)
	if _, _, ok := table.find(missing); ok {
		t.Fatal("ambiguous tuple matched")
	}
	unknown := key
	unknown.ID = 9
	if _, _, ok := table.find(unknown); ok {
		t.Fatal("different known IDs matched")
	}
	table.set(missing, 30)
	if matched, value, ok := table.find(unknown); !ok || matched != missing || value != 30 {
		t.Fatal("known ID did not match missing-ID baseline")
	}
	table.remove(missing)
	table.remove(other)
	if table.count != 1 {
		t.Fatal("index count not updated")
	}
}

func TestLostEventsBoundRetiredHistoryWithoutRecounting(t *testing.T) {
	e := NewEngine(map[uint32]struct{}{mustIP(t, "10.0.0.1"): {}}, 10240)
	e.Process(nil)
	e.Process([]nfconntrack.Con{connection(t, 42, 100, 200, "10.0.0.1", "8.8.8.8")})
	for i := 0; i <= maxRetiredBaselines; i++ {
		e.retired.set(connKey{ID: uint32(i + 100)}, retainedCounters{})
	}
	stats := e.Process(nil)
	if e.initialized || e.retired.count != 0 || stats.Skipped["history_capacity_rebaseline"] != 1 {
		t.Fatal("history overflow did not request a visible fresh baseline")
	}
	e.ProcessDestroy(connection(t, 42, 1000, 2000, "10.0.0.1", "8.8.8.8"))
	assertTraffic(t, e, "10.0.0.1", "8.8.8.8", Outbound, 100)
	e.Process(nil)
	if !e.initialized {
		t.Fatal("fresh baseline not established")
	}
}

func BenchmarkHistoryMiss(b *testing.B) {
	for _, n := range []int{1000, 5000, 10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			table := newConnectionTable[int]()
			for i := 0; i < n; i++ {
				table.set(connKey{ID: uint32(i + 1)}, 1)
			}
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				for i := 0; i < n; i++ {
					table.find(connKey{ID: uint32(i + n + 1)})
				}
			}
		})
	}
}
