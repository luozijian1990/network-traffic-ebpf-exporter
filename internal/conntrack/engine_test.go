package conntrack

import (
	"net"
	"testing"

	nfconntrack "github.com/florianl/go-conntrack"
)

func TestClassify(t *testing.T) {
	local := mustIP(t, "10.0.0.1")
	otherLocal := mustIP(t, "10.0.0.2")
	remote := mustIP(t, "8.8.8.8")
	remote2 := mustIP(t, "1.1.1.1")
	localIPs := map[uint32]struct{}{local: {}, otherLocal: {}}
	tests := []struct {
		name   string
		src    uint32
		dst    uint32
		dir    Direction
		reason string
	}{
		{"local to remote", local, remote, Outbound, ""},
		{"remote to local", remote, local, Inbound, ""},
		{"remote to remote", remote, remote2, Inbound, "non_local"},
		{"local to local", local, otherLocal, Inbound, "local_local"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir, reason := classify(test.src, test.dst, localIPs)
			if dir != test.dir || reason != test.reason {
				t.Fatalf("classify() = (%v, %q), want (%v, %q)", dir, reason, test.dir, test.reason)
			}
		})
	}
}

func TestInitialDumpIsBaselineAndSecondDumpUsesDelta(t *testing.T) {
	localIPs := map[uint32]struct{}{mustIP(t, "10.0.0.1"): {}}
	engine := NewEngine(localIPs, 10240)
	engine.Process([]nfconntrack.Con{connection(t, 7, 1000, 2000, "10.0.0.1", "8.8.8.8")})
	if got := len(engine.Snapshot()); got != 0 {
		t.Fatalf("initial baseline exported %d aggregate keys, want 0", got)
	}
	stats := engine.Process([]nfconntrack.Con{connection(t, 7, 1500, 2400, "10.0.0.1", "8.8.8.8")})
	assertTraffic(t, engine, "10.0.0.1", "8.8.8.8", Outbound, 500)
	assertTraffic(t, engine, "8.8.8.8", "10.0.0.1", Inbound, 400)
	if stats.CounterResets != 0 {
		t.Fatalf("counter resets = %d, want 0", stats.CounterResets)
	}
}

func TestNewConnectionUsesCurrentCounter(t *testing.T) {
	engine := NewEngine(map[uint32]struct{}{mustIP(t, "10.0.0.1"): {}}, 10240)
	engine.Process(nil)
	engine.Process([]nfconntrack.Con{connection(t, 8, 500, 200, "10.0.0.1", "8.8.8.8")})
	assertTraffic(t, engine, "10.0.0.1", "8.8.8.8", Outbound, 500)
	assertTraffic(t, engine, "8.8.8.8", "10.0.0.1", Inbound, 200)
}

func TestCounterResetUsesCurrentWithoutUnderflow(t *testing.T) {
	engine := NewEngine(map[uint32]struct{}{mustIP(t, "10.0.0.1"): {}}, 10240)
	engine.Process([]nfconntrack.Con{connection(t, 9, 1000, 1000, "10.0.0.1", "8.8.8.8")})
	stats := engine.Process([]nfconntrack.Con{connection(t, 9, 200, 300, "10.0.0.1", "8.8.8.8")})
	assertTraffic(t, engine, "10.0.0.1", "8.8.8.8", Outbound, 200)
	assertTraffic(t, engine, "8.8.8.8", "10.0.0.1", Inbound, 300)
	if stats.CounterResets != 2 {
		t.Fatalf("counter resets = %d, want 2", stats.CounterResets)
	}
}

func TestDisappearedConnectionIsEvicted(t *testing.T) {
	engine := NewEngine(map[uint32]struct{}{mustIP(t, "10.0.0.1"): {}}, 10240)
	engine.Process([]nfconntrack.Con{connection(t, 10, 100, 100, "10.0.0.1", "8.8.8.8")})
	if len(engine.previous) != 1 {
		t.Fatalf("previous entries = %d, want 1", len(engine.previous))
	}
	engine.Process(nil)
	if len(engine.previous) != 0 {
		t.Fatalf("previous entries = %d after disappearance, want 0", len(engine.previous))
	}
}

func TestDestroyEventCompletesObservedDownload(t *testing.T) {
	const fileBytes uint64 = 1709820816
	const bytesVisibleAtDump uint64 = 1086486
	engine := NewEngine(map[uint32]struct{}{mustIP(t, "172.16.11.105"): {}}, 10240)
	engine.Process(nil)
	engine.Process([]nfconntrack.Con{
		connection(t, 12, 0, bytesVisibleAtDump, "172.16.11.105", "172.16.11.158"),
	})

	engine.ProcessDestroy(connection(t, 12, 0, fileBytes, "172.16.11.105", "172.16.11.158"))

	assertTraffic(t, engine, "172.16.11.158", "172.16.11.105", Inbound, fileBytes)
}

func TestDestroyEventAccountsConnectionBetweenDumps(t *testing.T) {
	engine := NewEngine(map[uint32]struct{}{mustIP(t, "10.0.0.1"): {}}, 10240)
	engine.Process(nil)

	engine.ProcessDestroy(connection(t, 13, 1000, 2000, "10.0.0.1", "8.8.8.8"))

	assertTraffic(t, engine, "10.0.0.1", "8.8.8.8", Outbound, 1000)
	assertTraffic(t, engine, "8.8.8.8", "10.0.0.1", Inbound, 2000)
}

func TestDestroyEventUsesRetiredBaselineAfterDumpDisappearance(t *testing.T) {
	engine := NewEngine(map[uint32]struct{}{mustIP(t, "10.0.0.1"): {}}, 10240)
	engine.Process(nil)
	engine.Process([]nfconntrack.Con{connection(t, 14, 100, 200, "10.0.0.1", "8.8.8.8")})
	engine.Process(nil)

	engine.ProcessDestroy(connection(t, 14, 1000, 2000, "10.0.0.1", "8.8.8.8"))

	assertTraffic(t, engine, "10.0.0.1", "8.8.8.8", Outbound, 1000)
	assertTraffic(t, engine, "8.8.8.8", "10.0.0.1", Inbound, 2000)
}

func TestDestroyEventDeduplicatesStaleDumpAndDuplicateEvent(t *testing.T) {
	engine := NewEngine(map[uint32]struct{}{mustIP(t, "10.0.0.1"): {}}, 10240)
	engine.Process(nil)
	stale := connection(t, 15, 100, 200, "10.0.0.1", "8.8.8.8")
	final := connection(t, 15, 1000, 2000, "10.0.0.1", "8.8.8.8")
	engine.Process([]nfconntrack.Con{stale})
	engine.ProcessDestroy(final)

	engine.Process([]nfconntrack.Con{stale})
	engine.ProcessDestroy(final)

	assertTraffic(t, engine, "10.0.0.1", "8.8.8.8", Outbound, 1000)
	assertTraffic(t, engine, "8.8.8.8", "10.0.0.1", Inbound, 2000)
}

func TestDestroyEventMatchesDumpWhenOptionalIDIsMissing(t *testing.T) {
	engine := NewEngine(map[uint32]struct{}{mustIP(t, "10.0.0.1"): {}}, 10240)
	engine.Process(nil)
	engine.Process([]nfconntrack.Con{connection(t, 16, 100, 200, "10.0.0.1", "8.8.8.8")})
	final := connection(t, 16, 1000, 2000, "10.0.0.1", "8.8.8.8")
	final.ID = nil

	engine.ProcessDestroy(final)

	assertTraffic(t, engine, "10.0.0.1", "8.8.8.8", Outbound, 1000)
	assertTraffic(t, engine, "8.8.8.8", "10.0.0.1", Inbound, 2000)
}

func TestDNATReplyIsMappedBackToExternalHost(t *testing.T) {
	const requestBytes uint64 = 1130338
	const responseBytes uint64 = 1613492684
	engine := NewEngine(map[uint32]struct{}{mustIP(t, "172.16.11.105"): {}}, 10240)
	engine.Process(nil)
	connection := connection(t, 17, requestBytes, responseBytes, "172.16.11.158", "172.16.11.105")
	containerIP := net.ParseIP("172.17.0.3")
	connection.Reply.Src = &containerIP

	stats := engine.Process([]nfconntrack.Con{connection})

	assertTraffic(t, engine, "172.16.11.158", "172.16.11.105", Inbound, requestBytes)
	assertTraffic(t, engine, "172.16.11.105", "172.16.11.158", Outbound, responseBytes)
	if stats.Skipped["non_local"] != 0 {
		t.Fatalf("DNAT reply counted as non-local: %#v", stats.Skipped)
	}
}

func TestSNATOriginIsMappedBackToExternalHost(t *testing.T) {
	engine := NewEngine(map[uint32]struct{}{mustIP(t, "172.16.11.105"): {}}, 10240)
	engine.Process(nil)
	connection := connection(t, 18, 2000, 100, "172.17.0.3", "172.16.11.158")
	externalIP := net.ParseIP("172.16.11.105")
	connection.Reply.Dst = &externalIP

	stats := engine.Process([]nfconntrack.Con{connection})

	assertTraffic(t, engine, "172.16.11.105", "172.16.11.158", Outbound, 2000)
	assertTraffic(t, engine, "172.16.11.158", "172.16.11.105", Inbound, 100)
	if stats.Skipped["non_local"] != 0 {
		t.Fatalf("SNAT origin counted as non-local: %#v", stats.Skipped)
	}
}

func TestMaxEntriesUpdatesExistingAndDropsNew(t *testing.T) {
	engine := NewEngine(nil, 1)
	stats := ProcessStats{Skipped: make(map[string]uint64)}
	a := parsedTuple{src: mustIP(t, "10.0.0.1"), dst: mustIP(t, "8.8.8.8")}
	b := parsedTuple{src: mustIP(t, "10.0.0.1"), dst: mustIP(t, "1.1.1.1")}
	engine.addTraffic(a, Outbound, 100, &stats)
	engine.addTraffic(a, Outbound, 50, &stats)
	engine.addTraffic(b, Outbound, 200, &stats)
	if len(engine.aggregate) != 1 || engine.aggregate[TrafficKey{Src: a.src, Dst: a.dst, Direction: Outbound}] != 150 {
		t.Fatalf("existing aggregate was not retained and updated: %#v", engine.aggregate)
	}
	if stats.DroppedKeys != 1 {
		t.Fatalf("dropped keys = %d, want 1", stats.DroppedKeys)
	}
}

func TestNilAndMalformedConnectionsAreSkippedWithoutPanic(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	remote := net.ParseIP("8.8.8.8")
	proto := uint8(6)
	bytes := uint64(1)
	validTuple := &nfconntrack.IPTuple{Src: &ip, Dst: &remote, Proto: &nfconntrack.ProtoTuple{Number: &proto}}
	tests := []struct {
		name   string
		con    nfconntrack.Con
		reason string
	}{
		{"nil origin", nfconntrack.Con{}, "missing_origin"},
		{"nil reply", nfconntrack.Con{Origin: validTuple}, "missing_reply"},
		{"nil IP", nfconntrack.Con{Origin: &nfconntrack.IPTuple{}, Reply: validTuple}, "missing_ip"},
		{"nil proto", nfconntrack.Con{Origin: &nfconntrack.IPTuple{Src: &ip, Dst: &remote}, Reply: validTuple}, "missing_proto"},
		{"nil counter", nfconntrack.Con{Origin: validTuple, Reply: validTuple}, "missing_counter"},
		{"nil bytes", nfconntrack.Con{Origin: validTuple, Reply: validTuple, CounterOrigin: &nfconntrack.Counter{}, CounterReply: &nfconntrack.Counter{Bytes: &bytes}}, "missing_counter"},
	}
	engine := NewEngine(map[uint32]struct{}{mustIP(t, "10.0.0.1"): {}}, 10)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stats := engine.Process([]nfconntrack.Con{test.con})
			if stats.Skipped[test.reason] != 1 {
				t.Fatalf("skipped[%q] = %d, want 1", test.reason, stats.Skipped[test.reason])
			}
		})
	}
}

func TestIPv6IsSkipped(t *testing.T) {
	src := net.ParseIP("2001:db8::1")
	dst := net.ParseIP("2001:db8::2")
	proto := uint8(6)
	bytes := uint64(1)
	tuple := &nfconntrack.IPTuple{Src: &src, Dst: &dst, Proto: &nfconntrack.ProtoTuple{Number: &proto}}
	engine := NewEngine(nil, 10)
	stats := engine.Process([]nfconntrack.Con{{
		Origin: tuple, Reply: tuple,
		CounterOrigin: &nfconntrack.Counter{Bytes: &bytes}, CounterReply: &nfconntrack.Counter{Bytes: &bytes},
	}})
	if stats.Skipped["unsupported_ipv6"] != 1 || len(engine.Snapshot()) != 0 {
		t.Fatalf("IPv6 entry was not skipped: stats=%#v aggregate=%#v", stats, engine.Snapshot())
	}
}

func TestReconnectBaselineKeepsAggregate(t *testing.T) {
	engine := NewEngine(map[uint32]struct{}{mustIP(t, "10.0.0.1"): {}}, 10)
	engine.Process(nil)
	engine.Process([]nfconntrack.Con{connection(t, 11, 100, 50, "10.0.0.1", "8.8.8.8")})
	engine.RequireBaseline()
	engine.Process([]nfconntrack.Con{connection(t, 11, 10000, 5000, "10.0.0.1", "8.8.8.8")})
	assertTraffic(t, engine, "10.0.0.1", "8.8.8.8", Outbound, 100)
	engine.Process([]nfconntrack.Con{connection(t, 11, 10100, 5050, "10.0.0.1", "8.8.8.8")})
	assertTraffic(t, engine, "10.0.0.1", "8.8.8.8", Outbound, 200)
}

func connection(t *testing.T, id uint32, originBytes, replyBytes uint64, srcText, dstText string) nfconntrack.Con {
	t.Helper()
	src := net.ParseIP(srcText)
	dst := net.ParseIP(dstText)
	proto := uint8(6)
	srcPort := uint16(12345)
	dstPort := uint16(443)
	originProto := &nfconntrack.ProtoTuple{Number: &proto, SrcPort: &srcPort, DstPort: &dstPort}
	replyProto := &nfconntrack.ProtoTuple{Number: &proto, SrcPort: &dstPort, DstPort: &srcPort}
	return nfconntrack.Con{
		ID:            &id,
		Origin:        &nfconntrack.IPTuple{Src: &src, Dst: &dst, Proto: originProto},
		Reply:         &nfconntrack.IPTuple{Src: &dst, Dst: &src, Proto: replyProto},
		CounterOrigin: &nfconntrack.Counter{Bytes: &originBytes},
		CounterReply:  &nfconntrack.Counter{Bytes: &replyBytes},
	}
}

func mustIP(t *testing.T, text string) uint32 {
	t.Helper()
	value, ok := IPv4ToUint32(net.ParseIP(text))
	if !ok {
		t.Fatalf("invalid test IPv4 %q", text)
	}
	return value
}

func assertTraffic(t *testing.T, engine *Engine, src, dst string, direction Direction, want uint64) {
	t.Helper()
	key := TrafficKey{Src: mustIP(t, src), Dst: mustIP(t, dst), Direction: direction}
	if got := engine.Snapshot()[key]; got != want {
		t.Fatalf("traffic %#v = %d, want %d", key, got, want)
	}
}
