package client

import (
	"testing"
	"time"
)

func TestBackoffPolicy_DoublesUpToTheCeiling(t *testing.T) {
	p := BackoffPolicy{InitialDelay: time.Second, MaxDelay: 5 * time.Second, Factor: 2, Jitter: -1}

	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second}
	for i, w := range want {
		if got := p.Delay(i + 1); got != w {
			t.Errorf("Delay(%d) = %v, want %v", i+1, got, w)
		}
	}
}

// A zero field used to mean the default everywhere except Jitter, where it
// meant none, so a zero policy retried a fleet in lockstep.
func TestBackoffPolicy_ZeroValueIsTheDefault(t *testing.T) {
	got := BackoffPolicy{}.withDefaults()
	if got != DefaultBackoffPolicy() {
		t.Errorf("zero policy = %+v, want the default %+v", got, DefaultBackoffPolicy())
	}
}

func TestBackoffPolicy_JitterStaysUnderTheCeiling(t *testing.T) {
	p := BackoffPolicy{InitialDelay: time.Second, MaxDelay: 4 * time.Second, Factor: 2, Jitter: 0.5}.withDefaults()

	if got := p.delay(10, func() float64 { return 1 }); got != 4*time.Second {
		t.Errorf("highest jitter at the ceiling = %v, want the ceiling", got)
	}
	if got := p.delay(1, func() float64 { return 0 }); got != 500*time.Millisecond {
		t.Errorf("lowest jitter on the first delay = %v, want 500ms", got)
	}
}
