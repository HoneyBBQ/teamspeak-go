// Package discovery turns the address a user types into the host:port of a
// TeamSpeak voice server, the way the official client does: a MyTeamSpeak
// nickname, a _ts3._udp SRV record, a TSDNS lookup, or plain DNS.
package discovery

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	errEmptyAddress      = errors.New("empty address")
	errNicknameScheme    = errors.New("nickname service is not an http or https URL")
	errNicknameNotFound  = errors.New("nickname not found")
	errEmptyResponseBody = errors.New("empty response")
	errResponseTooLarge  = errors.New("lookup answer larger than 8 KiB")
)

// Endpoints and lifetimes the resolver uses.
const (
	// TSDNSDefaultPort is the TCP port a TSDNS server listens on when no SRV
	// record names another.
	TSDNSDefaultPort = "41144"
	// NicknameLookup is the MyTeamSpeak endpoint that maps a nickname to a
	// server address.
	NicknameLookup = "https://named.myteamspeak.com/lookup"
	// CacheTTL is how long a resolved address is reused before resolving again.
	CacheTTL = 10 * time.Minute
)

// The values of ResolvedAddr.Source the resolver sets.
const (
	// SourceSRV is a _ts3._udp SRV record.
	SourceSRV = "SRV"
	// SourceTSDNSSRV is a TSDNS server found through a _tsdns._tcp SRV record.
	SourceTSDNSSRV = "TSDNS-SRV"
	// SourceTSDNSDirect is a TSDNS server on the host's domain at port 41144.
	SourceTSDNSDirect = "TSDNS-Direct"
	// SourceDirect is the address as given.
	SourceDirect = "Direct"
)

// ResolvedAddr is one resolved host:port and how it was obtained.
type ResolvedAddr struct {
	Expiry time.Time
	Addr   string
	Source string
}

// Resolver resolves TeamSpeak-style addresses (nickname, SRV, TSDNS) with TTL cache.
type Resolver struct {
	log   *slog.Logger
	cache map[string][]ResolvedAddr
	// lookupSRV is net.DefaultResolver.LookupSRV; tests replace it.
	lookupSRV func(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	// lookupTSDNS is LookupTSDNS; tests replace it to reach a local server.
	lookupTSDNS func(ctx context.Context, server, host string) ([]string, error)
	// nicknameService is the lookup endpoint; empty is NicknameLookup.
	nicknameService string
	mu              sync.RWMutex
	// lookupNicknames sends a dot-less name to named.myteamspeak.com. Off
	// unless asked for: it tells a third party which server the user wants.
	lookupNicknames bool
}

// NewResolver returns a Resolver using log for debug tracing (nil →
// slog.Default). lookupNicknames sends a dot-less name to MyTeamSpeak's
// nickname service first; without it such a name is resolved like any host.
// nicknameService is that service's endpoint, empty for NicknameLookup.
func NewResolver(log *slog.Logger, lookupNicknames bool, nicknameService string) *Resolver {
	if log == nil {
		log = slog.Default()
	}

	return &Resolver{
		log:             log,
		cache:           make(map[string][]ResolvedAddr),
		lookupNicknames: lookupNicknames,
		nicknameService: nicknameService,
		lookupSRV:       net.DefaultResolver.LookupSRV,
		lookupTSDNS:     LookupTSDNS,
	}
}

// Resolve tries, in order: a MyTeamSpeak nickname when enabled, _ts3._udp SRV,
// TSDNS via SRV and :41144, then plain DNS.
func (r *Resolver) Resolve(ctx context.Context, inputAddr string) ([]ResolvedAddr, error) {
	if inputAddr == "" {
		return nil, errEmptyAddress
	}

	if cached, ok := r.getValidCache(inputAddr); ok {
		return cached, nil
	}

	host, port := splitHostPortOrDefault(inputAddr)

	if ip := net.ParseIP(host); ip != nil {
		return []ResolvedAddr{{Addr: net.JoinHostPort(host, port), Source: SourceDirect}}, nil
	}

	if r.lookupNicknames && !strings.Contains(host, ".") && host != "localhost" {
		if nickAddr, ok := r.resolveNicknameAddr(ctx, host); ok {
			return r.Resolve(ctx, nickAddr)
		}
	}

	if results, ok := r.resolveSRV(ctx, host); ok {
		return r.setCache(inputAddr, results), nil
	}

	domainList := getDomainList(host)

	if entries, ok := r.resolveTSDNSSRV(ctx, domainList, host); ok {
		return r.setCache(inputAddr, tsdnsAddrs(entries, port, SourceTSDNSSRV)), nil
	}

	if entries, ok := r.resolveTSDNSDirect(ctx, domainList, host); ok {
		return r.setCache(inputAddr, tsdnsAddrs(entries, port, SourceTSDNSDirect)), nil
	}

	r.log.Debug("falling back to direct dns", slog.String("host", host), slog.String("port", port))
	results := []ResolvedAddr{{
		Addr:   net.JoinHostPort(host, port),
		Source: SourceDirect,
	}}

	return r.setCache(inputAddr, results), nil
}

func (r *Resolver) getValidCache(inputAddr string) ([]ResolvedAddr, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cached, ok := r.cache[inputAddr]
	if !ok || len(cached) == 0 || time.Now().After(cached[0].Expiry) {
		return nil, false
	}
	r.log.Debug("cache hit", slog.String("addr", inputAddr), slog.String("source", cached[0].Source))

	return cached, true
}

// SplitHostPortOrDefault splits a TeamSpeak address into host and port,
// falling back to defaultPort when the address has none. Unlike
// net.SplitHostPort it accepts a bracketed IPv6 literal without a port
// ("[::1]") and a bare IPv6 literal ("::1"), returning the host unbracketed.
func SplitHostPortOrDefault(inputAddr, defaultPort string) (string, string) {
	host, port, err := net.SplitHostPort(inputAddr)
	if err == nil {
		return host, port
	}
	if inner, ok := strings.CutPrefix(inputAddr, "["); ok {
		if inner, ok = strings.CutSuffix(inner, "]"); ok {
			return inner, defaultPort
		}
	}

	return inputAddr, defaultPort
}

func splitHostPortOrDefault(inputAddr string) (string, string) {
	return SplitHostPortOrDefault(inputAddr, "9987")
}

func (r *Resolver) resolveNicknameAddr(ctx context.Context, host string) (string, bool) {
	r.log.Debug("trying nickname resolution", slog.String("nickname", host))
	endpoint := r.nicknameService
	if endpoint == "" {
		endpoint = NicknameLookup
	}
	nickAddr, err := lookupNickname(ctx, endpoint, host)
	if err != nil || nickAddr == "" {
		r.log.Debug("nickname resolution failed", slog.String("nickname", host), slog.Any("error", err))

		return "", false
	}
	r.log.Debug("nickname resolved", slog.String("nickname", host), slog.String("result", nickAddr))

	return nickAddr, true
}

func (r *Resolver) resolveSRV(ctx context.Context, host string) ([]ResolvedAddr, bool) {
	r.log.Debug("trying dns srv", slog.String("host", host))
	_, srvs, err := r.lookupSRV(ctx, "ts3", "udp", host)
	if err != nil || len(srvs) == 0 {
		r.log.Debug("dns srv failed", slog.String("host", host), slog.Any("error", err))

		return nil, false
	}

	results := srvAddrs(srvs)
	r.log.Debug("dns srv succeeded", slog.String("host", host), slog.String("result", results[0].Addr))

	return results, true
}

// srvAddrs turns SRV answers into addresses, keeping their order.
//
// RFC 2782 wants the lowest priority tried first and, within a priority, a
// weighted random choice. net.Resolver.LookupSRV already returns the records
// sorted by priority and randomised by weight within each priority, so the
// order is the one to try and is deliberately not changed here.
func srvAddrs(srvs []*net.SRV) []ResolvedAddr {
	results := make([]ResolvedAddr, 0, len(srvs))
	for _, srv := range srvs {
		target := strings.TrimSuffix(srv.Target, ".")
		results = append(results, ResolvedAddr{
			Addr:   net.JoinHostPort(target, strconv.FormatUint(uint64(srv.Port), 10)),
			Source: SourceSRV,
		})
	}

	return results
}

func (r *Resolver) resolveTSDNSSRV(ctx context.Context, domains []string, queryHost string) ([]string, bool) {
	for _, domain := range domains {
		r.log.Debug("trying tsdns srv", slog.String("domain", domain))
		_, srvs, err := r.lookupSRV(ctx, "tsdns", "tcp", domain)
		if err != nil || len(srvs) == 0 {
			r.log.Debug("tsdns srv failed", slog.String("domain", domain))

			continue
		}
		for _, srv := range srvs {
			target := strings.TrimSuffix(srv.Target, ".")
			entries, queryErr := r.lookupTSDNS(
				ctx, net.JoinHostPort(target, strconv.FormatUint(uint64(srv.Port), 10)), queryHost,
			)
			if queryErr == nil && len(entries) > 0 {
				r.log.Debug("tsdns srv succeeded", slog.String("domain", domain), slog.Any("result", entries))

				return entries, true
			}
		}
	}

	return nil, false
}

func (r *Resolver) resolveTSDNSDirect(ctx context.Context, domains []string, queryHost string) ([]string, bool) {
	for _, domain := range domains {
		r.log.Debug("trying tsdns direct", slog.String("domain", domain))
		entries, err := r.lookupTSDNS(ctx, net.JoinHostPort(domain, TSDNSDefaultPort), queryHost)
		if err == nil && len(entries) > 0 {
			r.log.Debug("tsdns direct succeeded", slog.String("domain", domain), slog.Any("result", entries))

			return entries, true
		}
		r.log.Debug("tsdns direct failed", slog.String("domain", domain))
	}

	return nil, false
}

// tsdnsDefaultVoicePort is the port TeamSpeak assumes for a TSDNS entry that
// names none.
const tsdnsDefaultVoicePort = "9987"

// tsdnsPortPlaceholder is the TSDNS port that stands for any port the user
// gave.
const tsdnsPortPlaceholder = "$PORT"

// tsdnsAddrs turns a TSDNS answer into addresses, keeping its order. An entry
// without a port means 9987, and the port $PORT means port, the one in the
// address being resolved.
func tsdnsAddrs(entries []string, port, source string) []ResolvedAddr {
	results := make([]ResolvedAddr, 0, len(entries))
	for _, entry := range entries {
		host, entryPort := SplitHostPortOrDefault(entry, tsdnsDefaultVoicePort)
		if entryPort == tsdnsPortPlaceholder {
			entryPort = port
		}
		results = append(results, ResolvedAddr{Addr: net.JoinHostPort(host, entryPort), Source: source})
	}

	return results
}

func (r *Resolver) setCache(key string, results []ResolvedAddr) []ResolvedAddr {
	expiry := time.Now().Add(CacheTTL)
	for i := range results {
		results[i].Expiry = expiry
	}
	r.mu.Lock()
	r.cache[key] = results
	r.mu.Unlock()

	return results
}

// getDomainList returns host suffixes ordered longest-first (for TSDNS), capped at three.
func getDomainList(host string) []string {
	parts := strings.Split(host, ".")
	list := make([]string, 0, len(parts)-1)
	for i := range len(parts) - 1 {
		list = append(list, strings.Join(parts[i:], "."))
	}
	if len(list) > 3 {
		return list[:3]
	}

	return list
}

// maxResponseSize bounds what is read of a TSDNS or nickname lookup answer,
// which is one address: a server that sends more cannot make the client
// hold it.
const maxResponseSize = 8 << 10

// lookupNickname asks the nickname service at endpoint for nickname.
func lookupNickname(ctx context.Context, endpoint, nickname string) (string, error) {
	lookupURL, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	if lookupURL.Scheme != "http" && lookupURL.Scheme != "https" {
		return "", errNicknameScheme
	}
	query := lookupURL.Query()
	query.Set("name", nickname)
	lookupURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, lookupURL.String(), nil)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", errNicknameNotFound
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxResponseSize {
		return "", errResponseTooLarge
	}

	lines := strings.Split(string(body), "\n")
	if len(lines) > 0 && lines[0] != "" {
		return strings.TrimSpace(lines[0]), nil
	}

	return "", errEmptyResponseBody
}

// tsdnsTimeouts bound a lookup: dial is the connection attempt, total the whole
// exchange. They are variables for tests.
var (
	tsdnsDialTimeout  = 2 * time.Second
	tsdnsTotalTimeout = 3 * time.Second
)

// LookupTSDNS asks the TSDNS server at server, host or host:port with the port
// defaulting to 41144, for host's address.
//
// The answer is the server's entries, in order, as it sent them. An entry may
// have no port, which TeamSpeak takes as 9987, or the literal port $PORT, which
// means the port the user gave (9987 by default); Resolver applies both.
//
// A nil slice with a nil error means the server has no record for host: it
// answered 404 or errors, or nothing. The answer ends at the first newline or
// when the server closes the connection. A connection failure, a timeout, a
// cancelled ctx, or an answer of 8 KiB or more without an end is an error.
func LookupTSDNS(ctx context.Context, server, host string) ([]string, error) {
	serverHost, serverPort := SplitHostPortOrDefault(server, TSDNSDefaultPort)

	d := net.Dialer{Timeout: tsdnsDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(serverHost, serverPort))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Closing the connection is what stops a read when ctx ends.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	_ = conn.SetDeadline(time.Now().Add(tsdnsTotalTimeout))

	_, err = io.WriteString(conn, host+"\n")
	if err != nil {
		return nil, ctxOr(ctx, err)
	}

	answer, err := readAnswer(conn)
	if err != nil {
		return nil, ctxOr(ctx, err)
	}

	answer = strings.TrimSpace(answer)
	if answer == "" || answer == "404" || answer == "errors" {
		return nil, nil
	}

	return strings.Fields(answer), nil
}

// ctxOr prefers ctx's error when ctx ended, since that is what closed the
// connection.
func ctxOr(ctx context.Context, err error) error {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		return ctxErr
	}

	return err
}

// readAnswer reads up to the first newline or the end of the connection.
func readAnswer(r io.Reader) (string, error) {
	buf := make([]byte, 0, 256)
	chunk := make([]byte, 512)
	for {
		n, err := r.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			return string(buf[:i]), nil
		}
		if len(buf) >= maxResponseSize {
			return "", errResponseTooLarge
		}
		if errors.Is(err, io.EOF) {
			return string(buf), nil
		}
		if err != nil {
			return "", err
		}
	}
}
