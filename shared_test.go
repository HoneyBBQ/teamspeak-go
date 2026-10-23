package teamspeak

import (
	"errors"
	"math"
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

// The three states are the voice client's and the ServerQuery client's alike,
// so they are named once.
func TestStatus_String(t *testing.T) {
	for _, tc := range []struct {
		want   string
		status Status
	}{
		{"disconnected", StatusDisconnected},
		{"connecting", StatusConnecting},
		{"connected", StatusConnected},
		{"status 7", Status(7)},
	} {
		if got := tc.status.String(); got != tc.want {
			t.Errorf("Status(%d).String() = %q, want %q", int(tc.status), got, tc.want)
		}
	}
}

// Which major version is which family is one decision, taken here so the two
// clients cannot disagree about the same server. A major this module does not
// name is unknown rather than guessed.
func TestServerFamilyForVersion(t *testing.T) {
	for _, tc := range []struct {
		want    ServerFamily
		version string
	}{
		{ServerFamilyTS3, "3.13.8 [Build: 1779874471]"},
		{ServerFamilyTS3, "3.0.0"},
		{ServerFamilyTS6, "6.0.0-beta13.1"},
		{ServerFamilyTS6, "7.1.0"},
		{ServerFamilyUnknown, "5.0.0"},
		{ServerFamilyUnknown, ""},
		{ServerFamilyUnknown, "not a version"},
	} {
		if got := ServerFamilyForVersion(tc.version); got != tc.want {
			t.Errorf("ServerFamilyForVersion(%q) = %q, want %q", tc.version, got, tc.want)
		}
	}
}

func TestBackoffPolicy_Validate(t *testing.T) {
	nan := math.NaN()
	refused := map[string]BackoffPolicy{
		"negative initial":              {InitialDelay: -time.Second},
		"negative max":                  {MaxDelay: -time.Second},
		"max below initial":             {InitialDelay: time.Second, MaxDelay: time.Millisecond},
		"max below the default initial": {MaxDelay: time.Millisecond},
		"NaN factor":                    {Factor: nan},
		"infinite factor":               {Factor: math.Inf(1)},
		"factor that shrinks":           {Factor: 0.5},
		"negative factor":               {Factor: -2},
		"NaN jitter":                    {Jitter: nan},
		"jitter above 1":                {Jitter: 1.5},
		"negative attempts":             {MaxAttempts: -1},
		"infinite negative jitter":      {Jitter: math.Inf(-1)},
	}
	for name, p := range refused {
		err := p.Validate()
		if !errors.Is(err, ErrInvalidBackoff) {
			t.Errorf("%s: Validate(%+v) = %v, want ErrInvalidBackoff", name, p, err)
		}
	}
	accepted := map[string]BackoffPolicy{
		"zero value":            {},
		"edges":                 {InitialDelay: 1, MaxDelay: 1, Factor: 1, Jitter: 1, MaxAttempts: 0},
		"jitter off":            {Jitter: -1},
		"default":               DefaultBackoffPolicy(),
		"initial above default": {InitialDelay: 2 * time.Minute},
	}
	for name, p := range accepted {
		err := p.Validate()
		if err != nil {
			t.Errorf("%s: Validate refused %+v: %v", name, p, err)
		}
	}
}

func FuzzBackoffPolicy_Validate(f *testing.F) {
	f.Add(int64(time.Second), int64(time.Minute), 2.0, 0.2, 3)
	f.Add(int64(0), int64(0), 0.0, 0.0, 0)
	f.Add(int64(1), int64(1), math.NaN(), -1.0, 1)
	f.Fuzz(func(t *testing.T, initial, maxDelay int64, factor, jitter float64, attempts int) {
		p := BackoffPolicy{
			InitialDelay: time.Duration(initial), MaxDelay: time.Duration(maxDelay),
			Factor: factor, Jitter: jitter, MaxAttempts: attempts,
		}
		if p.Validate() != nil {
			return
		}
		// A policy that passes gives delays within its ceiling, however odd.
		ceiling := p.withDefaults().MaxDelay
		for attempt := 1; attempt <= 5; attempt++ {
			if d := p.Delay(attempt); d < 0 || d > ceiling {
				t.Fatalf("Delay(%d) = %v, outside 0..%v for %+v", attempt, d, ceiling, p)
			}
		}
	})
}
