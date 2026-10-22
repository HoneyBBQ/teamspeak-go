//go:build integration

package serverquery_test

// WebQuery over HTTPS against a live server. The rest of the live suite reaches
// WebQuery over plain HTTP; these tests put the TLS handshake of a real server
// under it, with a certificate from a CA made for the run.
//
// They are opt-in, and run when all three are set:
//
//	TEAMSPEAK_QUERY_HTTPS_URL      the https:// base URL, such as https://127.0.0.1:10443
//	TEAMSPEAK_QUERY_HTTPS_CA       the path of the PEM file of the CA that signed its certificate
//	TEAMSPEAK_QUERY_HTTPS_API_KEY  an api key of that server (TEAMSPEAK_QUERY_API_KEY when unset)
//
// scripts/webquery-tls.sh makes the certificates, and the CI job shows how a
// TeamSpeak 6 server serves them itself and how a TeamSpeak 3 server, which has
// no HTTPS of its own, is fronted by a TLS terminator. The tests need nothing
// from the fixture's channels or groups, so a bare server will do.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

const (
	envHTTPSURL    = "TEAMSPEAK_QUERY_HTTPS_URL"
	envHTTPSCA     = "TEAMSPEAK_QUERY_HTTPS_CA"
	envHTTPSAPIKey = "TEAMSPEAK_QUERY_HTTPS_API_KEY"
)

// httpsVars are what an HTTPS test needs: the URL, the CA file's contents and
// the api key.
func httpsVars(t *testing.T) (string, []byte, string) {
	t.Helper()
	base := os.Getenv(envHTTPSURL)
	caFile := os.Getenv(envHTTPSCA)
	apiKey := os.Getenv(envHTTPSAPIKey)
	if apiKey == "" {
		apiKey = os.Getenv(envAPIKey)
	}
	if base == "" || caFile == "" || apiKey == "" {
		t.Skipf("%s, %s and %s not set — skipping the WebQuery HTTPS test", envHTTPSURL, envHTTPSCA, envHTTPSAPIKey)
	}
	pem, err := os.ReadFile(caFile) //nolint:gosec // the path is the test environment's own
	if err != nil {
		t.Fatalf("reading %s: %v", envHTTPSCA, err)
	}

	return base, pem, apiKey
}

// trusting is an http.Client that trusts only the CA in pem, the public way to
// trust a private CA.
func trusting(t *testing.T, pem []byte) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("the CA file holds no certificate")
	}

	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
}

func httpsClient(t *testing.T, apiKey string) (*serverquery.Client, []byte) {
	t.Helper()
	base, pem, _ := httpsVars(t)
	waitForOtherSuites()
	c, err := serverquery.New(
		serverquery.WebWith(base, apiKey, serverquery.WebOptions{Client: trusting(t, pem)}),
		serverquery.WithServer(1),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return c, pem
}

// The commands every transport serves, over HTTPS through a client that trusts
// the run's CA.
func TestQueryHTTPS_Commands(t *testing.T) {
	_, _, apiKey := httpsVars(t)
	c, _ := httpsClient(t, apiKey)
	open(t, c)
	assertCoreCommands(t, c, serverFamily())

	base, _, _ := httpsVars(t)
	if stats := c.Stats(); stats.Transport != "web" || stats.Address != base {
		t.Errorf("Stats = %+v, want the web transport at %s", stats, base)
	}
}

// A refusal from the server over HTTPS is the same typed error as over HTTP.
func TestQueryHTTPS_ServerErrorMapsToItsCode(t *testing.T) {
	_, _, apiKey := httpsVars(t)
	c, _ := httpsClient(t, apiKey)
	open(t, c)

	_, err := c.GetChannelInfo(adminCtx(t), 999_999)
	if !errors.Is(err, errcode.ChannelInvalidID) {
		t.Errorf("GetChannelInfo of a channel that does not exist = %v, want code %d", err, errcode.ChannelInvalidID)
	}
}

// A wrong api key is answered with an HTTP 401 and the server's own code, and
// both are matched.
func TestQueryHTTPS_HTTPErrorOfAWrongKey(t *testing.T) {
	c, _ := httpsClient(t, "not-a-key")

	err := c.Connect(adminCtx(t))
	if err == nil {
		_ = c.Disconnect(context.Background())
		t.Fatal("a wrong api key connected")
	}
	httpErr, ok := errors.AsType[*serverquery.WebQueryHTTPError](err)
	if !ok {
		t.Fatalf("Connect = %v, want a *WebQueryHTTPError", err)
	}
	if httpErr.Status != http.StatusUnauthorized || !httpErr.HasCode() || httpErr.Code != errcode.APIKeyInvalid {
		t.Errorf("error = %+v, want HTTP 401 and code %d", httpErr, errcode.APIKeyInvalid)
	}
	if !errors.Is(err, errcode.APIKeyInvalid) {
		t.Errorf("Connect = %v, want the code still matched", err)
	}
}

// Without the CA the default client refuses the certificate. There is no
// fallback to skipping the check.
func TestQueryHTTPS_RefusesACertificateNothingTrusts(t *testing.T) {
	base, _, apiKey := httpsVars(t)
	waitForOtherSuites()

	c, err := serverquery.New(serverquery.Web(base, apiKey), serverquery.WithServer(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = c.Connect(adminCtx(t))
	if err == nil {
		_ = c.Disconnect(context.Background())
		t.Fatal("Connect succeeded against a certificate the system does not trust")
	}
	if _, ok := errors.AsType[*tls.CertificateVerificationError](err); !ok {
		t.Errorf("Connect = %v, want a certificate verification error", err)
	}
	if _, ok := errors.AsType[*serverquery.WebQueryHTTPError](err); ok {
		t.Errorf("Connect = %v, want a failure before any HTTP answer", err)
	}
}
