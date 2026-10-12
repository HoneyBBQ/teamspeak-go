// Package discovery turns the address a user types into the host:port of a
// TeamSpeak voice server, the way the official client does: a MyTeamSpeak
// nickname, a _ts3._udp SRV record, a TSDNS lookup, or plain DNS.
package discovery

import (
	"bufio"
	"context"
	"errors"
	"fmt"
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
	errNicknameNotFound  = errors.New("nickname not found")
	errEmptyResponseBody = errors.New("empty response")
	errTSDNSNotFound     = errors.New("not found")
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
	mu    sync.RWMutex
	// lookupNicknames sends a dot-less name to named.myteamspeak.com. Off
	// unless asked for: it tells a third party which server the user wants.
	lookupNicknames bool
}

// NewResolver returns a Resolver using log for debug tracing (nil →
// slog.Default). lookupNicknames sends a dot-less name to MyTeamSpeak's
// nickname service first; without it such a name is resolved like any host.
func NewResolver(log *slog.Logger, lookupNicknames bool) *Resolver {
	if log == nil {
		log = slog.Default()
	}

	return &Resolver{
		log:             log,
		cache:           make(map[string][]ResolvedAddr),
		lookupNicknames: lookupNicknames,
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
		return []ResolvedAddr{{Addr: net.JoinHostPort(host, port), Source: "Direct"}}, nil
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

	if tsdnsAddr, ok := r.resolveTSDNSSRV(ctx, domainList, host); ok {
		results := []ResolvedAddr{{Addr: tsdnsAddr, Source: "TSDNS-SRV"}}

		return r.setCache(inputAddr, results), nil
	}

	if tsdnsAddr, ok := r.resolveTSDNSDirect(ctx, domainList, host); ok {
		results := []ResolvedAddr{{Addr: tsdnsAddr, Source: "TSDNS-Direct"}}

		return r.setCache(inputAddr, results), nil
	}

	r.log.Debug("falling back to direct dns", slog.String("host", host), slog.String("port", port))
	results := []ResolvedAddr{{
		Addr:   net.JoinHostPort(host, port),
		Source: "Direct",
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
	nickAddr, err := resolveNickname(ctx, host)
	if err != nil || nickAddr == "" {
		r.log.Debug("nickname resolution failed", slog.String("nickname", host), slog.Any("error", err))

		return "", false
	}
	r.log.Debug("nickname resolved", slog.String("nickname", host), slog.String("result", nickAddr))

	return nickAddr, true
}

func (r *Resolver) resolveSRV(ctx context.Context, host string) ([]ResolvedAddr, bool) {
	r.log.Debug("trying dns srv", slog.String("host", host))
	_, srvs, err := net.DefaultResolver.LookupSRV(ctx, "ts3", "udp", host)
	if err != nil || len(srvs) == 0 {
		r.log.Debug("dns srv failed", slog.String("host", host), slog.Any("error", err))

		return nil, false
	}

	results := make([]ResolvedAddr, 0, len(srvs))
	for _, srv := range srvs {
		target := strings.TrimSuffix(srv.Target, ".")
		results = append(results, ResolvedAddr{
			Addr:   net.JoinHostPort(target, strconv.FormatUint(uint64(srv.Port), 10)),
			Source: "SRV",
		})
	}
	r.log.Debug("dns srv succeeded", slog.String("host", host), slog.String("result", results[0].Addr))

	return results, true
}

func (r *Resolver) resolveTSDNSSRV(ctx context.Context, domains []string, queryHost string) (string, bool) {
	for _, domain := range domains {
		r.log.Debug("trying tsdns srv", slog.String("domain", domain))
		_, srvs, err := net.DefaultResolver.LookupSRV(ctx, "tsdns", "tcp", domain)
		if err != nil || len(srvs) == 0 {
			r.log.Debug("tsdns srv failed", slog.String("domain", domain))

			continue
		}
		for _, srv := range srvs {
			target := strings.TrimSuffix(srv.Target, ".")
			tsdnsAddr, queryErr := queryTSDNS(
				ctx, net.JoinHostPort(target, strconv.FormatUint(uint64(srv.Port), 10)), queryHost,
			)
			if queryErr == nil && tsdnsAddr != "" {
				r.log.Debug("tsdns srv succeeded", slog.String("domain", domain), slog.String("result", tsdnsAddr))

				return tsdnsAddr, true
			}
		}
	}

	return "", false
}

func (r *Resolver) resolveTSDNSDirect(ctx context.Context, domains []string, queryHost string) (string, bool) {
	for _, domain := range domains {
		r.log.Debug("trying tsdns direct", slog.String("domain", domain))
		tsdnsAddr, err := queryTSDNS(ctx, net.JoinHostPort(domain, TSDNSDefaultPort), queryHost)
		if err == nil && tsdnsAddr != "" {
			r.log.Debug("tsdns direct succeeded", slog.String("domain", domain), slog.String("result", tsdnsAddr))

			return tsdnsAddr, true
		}
		r.log.Debug("tsdns direct failed", slog.String("domain", domain))
	}

	return "", false
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

func resolveNickname(ctx context.Context, nickname string) (string, error) {
	return lookupNickname(ctx, NicknameLookup, nickname)
}

// lookupNickname asks the nickname service at endpoint for nickname.
func lookupNickname(ctx context.Context, endpoint, nickname string) (string, error) {
	lookupURL, err := url.Parse(endpoint)
	if err != nil {
		return "", err
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

func queryTSDNS(ctx context.Context, tsdnsFullAddr, queryHost string) (string, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", tsdnsFullAddr)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	_, err = fmt.Fprintf(conn, "%s\n", queryHost)
	if err != nil {
		return "", err
	}

	// A line longer than maxResponseSize ends in io.EOF, an error.
	reader := bufio.NewReader(io.LimitReader(conn, maxResponseSize))
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	line = strings.TrimSpace(line)
	if line == "" || line == "404" || line == "errors" {
		return "", errTSDNSNotFound
	}

	return line, nil
}
