package transport

import (
	"math"
	"sync"
	"time"
)

// TrafficClass is one of the three classes TeamSpeak counts traffic in.
type TrafficClass int

// The traffic classes, in the order the server lists them.
const (
	// TrafficSpeech is voice and whisper packets.
	TrafficSpeech TrafficClass = iota
	// TrafficKeepalive is ping and pong packets.
	TrafficKeepalive
	// TrafficControl is every other packet: commands, acknowledgements and the
	// handshake.
	TrafficControl
)

// trafficClasses is how many classes there are.
const trafficClasses = 3

// ClassOf returns the class a packet of type t is counted in.
func ClassOf(t PacketType) TrafficClass {
	switch t { //nolint:exhaustive // every other type is control traffic
	case PacketTypeVoice, PacketTypeVoiceWhisper:
		return TrafficSpeech
	case PacketTypePing, PacketTypePong:
		return TrafficKeepalive
	default:
		return TrafficControl
	}
}

// TrafficFigures is what one direction of one class has carried.
type TrafficFigures struct {
	// Packets is the number of datagrams, resent ones included.
	Packets uint64
	// Bytes is the size of those datagrams, headers included.
	Bytes uint64
	// BytesLastSecond is the bytes of the last whole second.
	BytesLastSecond uint64
	// BytesPerSecondLastMinute is the bytes per second averaged over the last
	// minute.
	BytesPerSecondLastMinute uint64
}

// Traffic is a connection's traffic, per class.
type Traffic struct {
	Sent     [trafficClasses]TrafficFigures
	Received [trafficClasses]TrafficFigures
}

const windowSeconds = 60

// counter is one direction of one class: totals and a ring of one-second byte
// buckets.
type counter struct {
	buckets [windowSeconds]uint64
	packets uint64
	bytes   uint64
	// second is the whole second the newest bucket stands for.
	second int64
}

func (c *counter) advance(second int64) {
	if second <= c.second {
		return
	}
	for i := int64(1); i <= min(second-c.second, windowSeconds); i++ {
		c.buckets[(c.second+i)%windowSeconds] = 0
	}
	c.second = second
}

func (c *counter) add(bytes int, now time.Time) {
	c.advance(now.Unix())
	c.packets++
	n := uint64(max(bytes, 0))
	c.bytes += n
	c.buckets[c.second%windowSeconds] += n
}

func (c *counter) figures(now time.Time) TrafficFigures {
	c.advance(now.Unix())
	// The second in progress is incomplete, so "the last second" is the one
	// before it, and the minute is the 60 before it.
	var minute uint64
	for i := int64(1); i <= windowSeconds; i++ {
		minute += c.buckets[(c.second-i+2*windowSeconds)%windowSeconds]
	}

	return TrafficFigures{
		Packets:                  c.packets,
		Bytes:                    c.bytes,
		BytesLastSecond:          c.buckets[(c.second-1+windowSeconds)%windowSeconds],
		BytesPerSecondLastMinute: minute / windowSeconds,
	}
}

// trafficMeter counts the datagrams a connection sends and receives. Time is
// passed in so a test can drive it.
type trafficMeter struct {
	sent     [trafficClasses]counter
	received [trafficClasses]counter
	mu       sync.Mutex
}

func (m *trafficMeter) recordSent(t PacketType, bytes int, now time.Time) {
	m.mu.Lock()
	m.sent[ClassOf(t)].add(bytes, now)
	m.mu.Unlock()
}

func (m *trafficMeter) recordReceived(t PacketType, bytes int, now time.Time) {
	m.mu.Lock()
	m.received[ClassOf(t)].add(bytes, now)
	m.mu.Unlock()
}

func (m *trafficMeter) snapshot(now time.Time) Traffic {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out Traffic
	for i := range trafficClasses {
		out.Sent[i] = m.sent[i].figures(now)
		out.Received[i] = m.received[i].figures(now)
	}

	return out
}

// connStats is what a connection measures of itself: the datagrams it carries
// and the keepalive round trip.
type connStats struct {
	// pings is when each keepalive ping still waiting for its pong was sent,
	// by packet id. Guarded by mu.
	pings   map[uint16]time.Time
	rtt     roundTrip
	traffic trafficMeter
	mu      sync.Mutex
}

func newConnStats() *connStats {
	return &connStats{pings: make(map[uint16]time.Time)}
}

// pingsAwaiting bounds the pings remembered while they wait for a pong, so
// ones the server never answers do not pile up.
const pingsAwaiting = 16

func (s *connStats) pingSent(id uint16, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pings) >= pingsAwaiting {
		clear(s.pings)
	}
	s.pings[id] = at
}

// pongReceived completes the round trip of the ping a pong acknowledges.
func (s *connStats) pongReceived(id uint16, at time.Time) {
	s.mu.Lock()
	sent, ok := s.pings[id]
	delete(s.pings, id)
	s.mu.Unlock()
	if ok {
		s.rtt.add(at.Sub(sent))
	}
}

// roundTripSamples is how many recent samples the estimate covers.
const roundTripSamples = 10

// roundTrip estimates the keepalive round-trip time: the mean and the
// standard deviation over the last roundTripSamples samples.
type roundTrip struct {
	samples []time.Duration
	mu      sync.Mutex
}

func (r *roundTrip) add(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.samples = append(r.samples, d)
	if len(r.samples) > roundTripSamples {
		r.samples = r.samples[1:]
	}
}

// RoundTripEstimate is the keepalive round-trip time: the mean of the recent
// samples and their standard deviation.
type RoundTripEstimate struct {
	Mean      time.Duration
	Deviation time.Duration
}

func (r *roundTrip) get() (RoundTripEstimate, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(r.samples)
	if n == 0 {
		return RoundTripEstimate{}, false
	}
	var sum float64
	for _, s := range r.samples {
		sum += float64(s)
	}
	avg := sum / float64(n)
	var variance float64
	for _, s := range r.samples {
		variance += (float64(s) - avg) * (float64(s) - avg)
	}

	return RoundTripEstimate{Mean: time.Duration(avg), Deviation: time.Duration(math.Sqrt(variance / float64(n)))}, true
}
