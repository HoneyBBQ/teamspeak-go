package serverquery

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// webTLS answers WebQuery over HTTPS with a certificate no system trust store
// knows. Its Client trusts it.
func webTLS(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"body":[{"version":"3.13.8","build":"1","platform":"Linux"}],` +
			`"status":{"code":0,"message":"ok"}}`))
	}))
	t.Cleanup(srv.Close)

	return srv
}

// An https:// base URL needs nothing from this package: a caller whose client
// trusts the server's certificate connects.
func TestWeb_OverHTTPSWithATrustingClient(t *testing.T) {
	srv := webTLS(t)
	c, err := New(WebWith(srv.URL, "key", WebOptions{Client: srv.Client()}), WithServer(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = c.Connect(t.Context())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = c.Disconnect(t.Context()) }()
	v, err := c.GetVersion(t.Context())
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	if v.Version != "3.13.8" {
		t.Errorf("version = %q, want 3.13.8", v.Version)
	}
}

// The default client verifies the certificate and fails closed.
func TestWeb_OverHTTPSRefusesAnUntrustedCertificate(t *testing.T) {
	srv := webTLS(t)
	c, err := New(Web(srv.URL, "key"), WithServer(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = c.Connect(t.Context())
	if err == nil {
		_ = c.Disconnect(t.Context())
		t.Fatal("Connect succeeded against a certificate nothing trusts")
	}
}
