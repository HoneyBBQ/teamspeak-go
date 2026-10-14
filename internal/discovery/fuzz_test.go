package discovery

import (
	"net"
	"strings"
	"testing"
)

// FuzzSplitHostPortOrDefault checks that no address a user types panics the
// splitter or the domain list a TSDNS lookup is built from, that a host and
// port joined by net.JoinHostPort split back as they were, and that the domain
// list is at most three suffixes of the host, longest first.
func FuzzSplitHostPortOrDefault(f *testing.F) {
	f.Add("", "", "")
	f.Add("example.com", "example.com", "9987")
	f.Add("[::1]:9988", "::1", "9988")
	f.Add("[::1]", "a", "1")
	f.Add("::1", "x.y.z.example.com", "65535")
	f.Add("a:", "a.", "0")
	f.Add("[", "..", "99999999999")

	f.Fuzz(func(t *testing.T, addr, host, port string) {
		_, _ = SplitHostPortOrDefault(addr, "9987")

		if host != "" && port != "" && !strings.ContainsAny(host+port, ":[]%") {
			gotHost, gotPort := SplitHostPortOrDefault(net.JoinHostPort(host, port), "9987")
			if gotHost != host || gotPort != port {
				t.Fatalf("SplitHostPortOrDefault(%q) = %q, %q, want %q, %q",
					net.JoinHostPort(host, port), gotHost, gotPort, host, port)
			}
		}

		domains := getDomainList(addr)
		if len(domains) > 3 {
			t.Fatalf("getDomainList(%q) = %q, more than three", addr, domains)
		}
		for i, domain := range domains {
			if !strings.HasSuffix(addr, domain) || (i > 0 && len(domain) >= len(domains[i-1])) {
				t.Fatalf("getDomainList(%q) = %q, want suffixes, longest first", addr, domains)
			}
		}
	})
}
