package conntrack

import (
	"encoding/binary"
	"net"
	"sync"

	nfconntrack "github.com/florianl/go-conntrack"
)

type Direction uint8

const (
	Inbound Direction = iota
	Outbound
)

func (d Direction) String() string {
	if d == Outbound {
		return "outbound"
	}
	return "inbound"
}

type TrafficKey struct {
	Src       uint32
	Dst       uint32
	Direction Direction
}

type connKey struct {
	Src, Dst uint32
	ID       uint32
	Zone     uint16
	SrcPort  uint16
	DstPort  uint16
	ICMPID   uint16
	ICMPType uint8
	ICMPCode uint8
	Proto    uint8
}

type connCounters struct {
	Origin uint64
	Reply  uint64
}

type retainedCounters struct {
	counters connCounters
	expires  uint64
}

type parsedTuple struct {
	src uint32
	dst uint32
}

type ProcessStats struct {
	Skipped          map[string]uint64
	DroppedKeys      uint64
	CounterResets    uint64
	AddedBytes       uint64
	PreviousEntries  int
	AggregateEntries int
}

type Engine struct {
	mu          sync.RWMutex
	localIPs    map[uint32]struct{}
	previous    *connectionTable[connCounters]
	retired     *connectionTable[retainedCounters]
	destroyed   *connectionTable[retainedCounters]
	aggregate   map[TrafficKey]uint64
	maxEntries  int
	generation  uint64
	initialized bool
}

func NewEngine(localIPs map[uint32]struct{}, maxEntries int) *Engine {
	copyIPs := make(map[uint32]struct{}, len(localIPs))
	for ip := range localIPs {
		copyIPs[ip] = struct{}{}
	}
	return &Engine{
		localIPs: copyIPs, previous: newConnectionTable[connCounters](),
		retired: newConnectionTable[retainedCounters](), destroyed: newConnectionTable[retainedCounters](),
		aggregate: make(map[TrafficKey]uint64), maxEntries: maxEntries,
	}
}

func (e *Engine) RequireBaseline() {
	e.mu.Lock()
	e.previous = newConnectionTable[connCounters]()
	e.retired = newConnectionTable[retainedCounters]()
	e.destroyed = newConnectionTable[retainedCounters]()
	e.initialized = false
	e.mu.Unlock()
}

func (e *Engine) Process(connections []nfconntrack.Con) ProcessStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.generation++
	stats := ProcessStats{Skipped: make(map[string]uint64)}
	nextPrevious := newConnectionTable[connCounters]()
	for i := range connections {
		key, origin, reply, counters, reason := parseConnection(&connections[i])
		if reason != "" {
			stats.Skipped[reason]++
			continue
		}
		origin, originDirection, originReason, reply, replyDirection, replyReason :=
			classifyConnection(origin, reply, e.localIPs)
		if originReason != "" {
			stats.Skipped[originReason]++
		}
		if replyReason != "" {
			stats.Skipped[replyReason]++
		}
		if originReason != "" && replyReason != "" {
			continue
		}
		if destroyedKey, destroyed, exists := e.destroyed.find(key); exists {
			if countersAtOrBelow(counters, destroyed.counters) {
				continue
			}
			e.destroyed.remove(destroyedKey)
		}
		nextPrevious.set(key, counters)
		if !e.initialized {
			continue
		}
		previousKey, previous, existed := e.previous.find(key)
		var retiredKey connKey
		if !existed {
			if matchedKey, retained, ok := e.retired.find(key); ok {
				retiredKey, previous, existed = matchedKey, retained.counters, true
			}
		}
		originDelta, originReset := counterDelta(counters.Origin, previous.Origin, existed)
		replyDelta, replyReset := counterDelta(counters.Reply, previous.Reply, existed)
		if originReset {
			stats.CounterResets++
		}
		if replyReset {
			stats.CounterResets++
		}
		if originReason == "" {
			e.addTraffic(origin, originDirection, originDelta, &stats)
		}
		if replyReason == "" {
			e.addTraffic(reply, replyDirection, replyDelta, &stats)
		}
		if previousKey != (connKey{}) {
			e.previous.remove(previousKey)
		}
		if retiredKey != (connKey{}) {
			e.retired.remove(retiredKey)
		}
	}
	e.previous.each(func(key connKey, counters connCounters) {
		if _, stillPresent := nextPrevious.exact(key); stillPresent {
			return
		}
		if _, wasDestroyed := e.destroyed.exact(key); wasDestroyed {
			return
		}
		e.retired.set(key, retainedCounters{counters: counters})
	})
	e.previous = nextPrevious
	e.initialized = true
	e.expireRetained()
	if !e.initialized {
		stats.Skipped["history_capacity_rebaseline"]++
	}
	stats.PreviousEntries = e.previous.count + e.retired.count
	stats.AggregateEntries = len(e.aggregate)
	return stats
}

// ProcessDestroy applies the final lifetime counters carried by a conntrack
// DESTROY event. Retired baselines and tombstones close the races with dumps.
func (e *Engine) ProcessDestroy(connection nfconntrack.Con) ProcessStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	stats := ProcessStats{Skipped: make(map[string]uint64)}
	key, origin, reply, counters, reason := parseConnection(&connection)
	if reason != "" {
		stats.Skipped[reason]++
		return e.finishStats(stats)
	}
	if !e.initialized {
		stats.Skipped["uninitialized_event"]++
		return e.finishStats(stats)
	}
	origin, originDirection, originReason, reply, replyDirection, replyReason :=
		classifyConnection(origin, reply, e.localIPs)
	if originReason != "" {
		stats.Skipped[originReason]++
	}
	if replyReason != "" {
		stats.Skipped[replyReason]++
	}
	if originReason != "" && replyReason != "" {
		return e.finishStats(stats)
	}
	if destroyedKey, destroyed, exists := e.destroyed.find(key); exists {
		if counters == destroyed.counters {
			stats.Skipped["duplicate_destroy"]++
			return e.finishStats(stats)
		}
		e.destroyed.remove(destroyedKey)
	}
	previousKey, previous, existed := e.previous.find(key)
	var retiredKey connKey
	if !existed {
		if matchedKey, retained, ok := e.retired.find(key); ok {
			retiredKey, previous, existed = matchedKey, retained.counters, true
		}
	}
	originDelta, originReset := counterDelta(counters.Origin, previous.Origin, existed)
	replyDelta, replyReset := counterDelta(counters.Reply, previous.Reply, existed)
	if originReset {
		stats.CounterResets++
	}
	if replyReset {
		stats.CounterResets++
	}
	if originReason == "" {
		e.addTraffic(origin, originDirection, originDelta, &stats)
	}
	if replyReason == "" {
		e.addTraffic(reply, replyDirection, replyDelta, &stats)
	}
	if previousKey != (connKey{}) {
		e.previous.remove(previousKey)
	}
	if retiredKey != (connKey{}) {
		e.retired.remove(retiredKey)
	}
	e.previous.remove(key)
	e.retired.remove(key)
	e.destroyed.set(key, retainedCounters{counters: counters, expires: e.generation + 2})
	return e.finishStats(stats)
}

func (e *Engine) finishStats(stats ProcessStats) ProcessStats {
	stats.PreviousEntries = e.previous.count + e.retired.count
	stats.AggregateEntries = len(e.aggregate)
	return stats
}

func (e *Engine) expireRetained() {
	e.destroyed.each(func(key connKey, retained retainedCounters) {
		if retained.expires <= e.generation {
			e.destroyed.remove(key)
		}
	})
	if e.retired.count > maxRetiredBaselines {
		// Preserve exported totals but avoid double-counting evicted lifetimes.
		e.previous = newConnectionTable[connCounters]()
		e.retired = newConnectionTable[retainedCounters]()
		e.destroyed = newConnectionTable[retainedCounters]()
		e.initialized = false
	}
}

func (e *Engine) addTraffic(tuple parsedTuple, direction Direction, delta uint64, stats *ProcessStats) {
	if delta == 0 {
		return
	}
	key := TrafficKey{Src: tuple.src, Dst: tuple.dst, Direction: direction}
	if _, exists := e.aggregate[key]; !exists && len(e.aggregate) >= e.maxEntries {
		stats.DroppedKeys++
		return
	}
	e.aggregate[key] += delta
	stats.AddedBytes += delta
}

func (e *Engine) Snapshot() map[TrafficKey]uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make(map[TrafficKey]uint64, len(e.aggregate))
	for key, value := range e.aggregate {
		result[key] = value
	}
	return result
}

func counterDelta(current, previous uint64, existed bool) (uint64, bool) {
	if !existed {
		return current, false
	}
	if current < previous {
		return current, true
	}
	return current - previous, false
}

func countersAtOrBelow(current, final connCounters) bool {
	return current.Origin <= final.Origin && current.Reply <= final.Reply
}

func classify(src, dst uint32, localIPs map[uint32]struct{}) (Direction, string) {
	_, srcLocal := localIPs[src]
	_, dstLocal := localIPs[dst]
	switch {
	case srcLocal && !dstLocal:
		return Outbound, ""
	case !srcLocal && dstLocal:
		return Inbound, ""
	case srcLocal && dstLocal:
		return Inbound, "local_local"
	default:
		return Inbound, "non_local"
	}
}

func classifyConnection(origin, reply parsedTuple, localIPs map[uint32]struct{}) (
	parsedTuple, Direction, string, parsedTuple, Direction, string,
) {
	originDirection, originReason := classify(origin.src, origin.dst, localIPs)
	replyDirection, replyReason := classify(reply.src, reply.dst, localIPs)

	// DNAT: remote -> external local, then container -> remote. Restore the
	// reply tuple as external local -> remote for host-interface accounting.
	if originReason == "" && replyReason == "non_local" && origin.src == reply.dst {
		mapped := parsedTuple{src: origin.dst, dst: origin.src}
		if direction, reason := classify(mapped.src, mapped.dst, localIPs); reason == "" {
			reply, replyDirection, replyReason = mapped, direction, ""
		}
	}

	// SNAT: container -> remote, then remote -> external local. Restore the
	// origin tuple as external local -> remote.
	if originReason == "non_local" && replyReason == "" && origin.dst == reply.src {
		mapped := parsedTuple{src: reply.dst, dst: reply.src}
		if direction, reason := classify(mapped.src, mapped.dst, localIPs); reason == "" {
			origin, originDirection, originReason = mapped, direction, ""
		}
	}

	return origin, originDirection, originReason, reply, replyDirection, replyReason
}

func parseConnection(con *nfconntrack.Con) (connKey, parsedTuple, parsedTuple, connCounters, string) {
	var zeroKey connKey
	var zeroTuple parsedTuple
	var zeroCounters connCounters
	if con.Origin == nil {
		return zeroKey, zeroTuple, zeroTuple, zeroCounters, "missing_origin"
	}
	if con.Reply == nil {
		return zeroKey, zeroTuple, zeroTuple, zeroCounters, "missing_reply"
	}
	origin, proto, reason := parseTuple(con.Origin)
	if reason != "" {
		return zeroKey, zeroTuple, zeroTuple, zeroCounters, reason
	}
	reply, replyProto, reason := parseTuple(con.Reply)
	if reason != "" {
		return zeroKey, zeroTuple, zeroTuple, zeroCounters, reason
	}
	if *replyProto.Number != *proto.Number {
		return zeroKey, zeroTuple, zeroTuple, zeroCounters, "invalid_tuple"
	}
	if con.CounterOrigin == nil || con.CounterReply == nil ||
		con.CounterOrigin.Bytes == nil || con.CounterReply.Bytes == nil {
		return zeroKey, zeroTuple, zeroTuple, zeroCounters, "missing_counter"
	}
	key := connKey{Src: origin.src, Dst: origin.dst, Proto: *proto.Number}
	if con.ID != nil {
		key.ID = *con.ID
	}
	if con.Zone != nil {
		key.Zone = *con.Zone
	} else if con.Origin.Zone != nil {
		key.Zone = *con.Origin.Zone
	}
	if proto.SrcPort != nil {
		key.SrcPort = *proto.SrcPort
	}
	if proto.DstPort != nil {
		key.DstPort = *proto.DstPort
	}
	if proto.IcmpID != nil {
		key.ICMPID = *proto.IcmpID
	}
	if proto.IcmpType != nil {
		key.ICMPType = *proto.IcmpType
	}
	if proto.IcmpCode != nil {
		key.ICMPCode = *proto.IcmpCode
	}
	return key, origin, reply, connCounters{
		Origin: *con.CounterOrigin.Bytes, Reply: *con.CounterReply.Bytes,
	}, ""
}

func parseTuple(tuple *nfconntrack.IPTuple) (parsedTuple, *nfconntrack.ProtoTuple, string) {
	var zero parsedTuple
	if tuple.Src == nil || tuple.Dst == nil {
		return zero, nil, "missing_ip"
	}
	src4 := (*tuple.Src).To4()
	dst4 := (*tuple.Dst).To4()
	if src4 == nil || dst4 == nil {
		return zero, nil, "unsupported_ipv6"
	}
	if tuple.Proto == nil || tuple.Proto.Number == nil {
		return zero, nil, "missing_proto"
	}
	return parsedTuple{src: binary.BigEndian.Uint32(src4), dst: binary.BigEndian.Uint32(dst4)}, tuple.Proto, ""
}

func IPv4ToUint32(ip net.IP) (uint32, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(ip4), true
}

func Uint32ToIPv4(ip uint32) string {
	bytes := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(bytes, ip)
	return bytes.String()
}
