package client

import (
	"context"
	"log/slog"
	"net"
	"net/http"

	"github.com/honeybbq/teamspeak-go/internal/discovery"
)

// The values of ResolvedAddr.Source the default Resolver sets. A custom
// AddrResolver may set any string.
const (
	// ResolveSourceSRV is a _ts3._udp SRV record.
	ResolveSourceSRV = discovery.SourceSRV
	// ResolveSourceTSDNSSRV is a TSDNS server found through a _tsdns._tcp SRV
	// record.
	ResolveSourceTSDNSSRV = discovery.SourceTSDNSSRV
	// ResolveSourceTSDNSDirect is a TSDNS server on the host's domain at
	// port 41144.
	ResolveSourceTSDNSDirect = discovery.SourceTSDNSDirect
	// ResolveSourceDirect is the address as given.
	ResolveSourceDirect = discovery.SourceDirect
)

// LookupTSDNS asks the TSDNS server at server for host's address. server is
// host or host:port; the port defaults to 41144.
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
	return discovery.LookupTSDNS(ctx, server, host)
}

// ResolverOptions configures NewResolver.
type ResolverOptions struct {
	// Logger receives debug tracing; nil is slog.Default().
	Logger *slog.Logger
	// DNS answers the resolver's SRV lookups (_ts3._udp.<host> and
	// _tsdns._tcp.<domain>); nil is net.DefaultResolver. Set its Dial to use
	// another DNS server, or DNS over a custom transport. Only the SRV
	// lookups use it: the host names in the answers, and the address the
	// client finally dials, are looked up by the client as usual.
	DNS *net.Resolver
	// HTTPClient makes the nickname lookup's request; nil is a client with a
	// five-second timeout. Set it for a proxy or a test.
	HTTPClient *http.Client
	// NicknameService is the nickname lookup endpoint, for a test double or a
	// mirror; empty is https://named.myteamspeak.com/lookup. It is used only
	// when NicknameLookup is true: setting it does not turn the lookup on. The
	// name is sent as the name query parameter and the first line of the
	// answer is the address. A URL that does not parse, or is not http or
	// https, makes the nickname step fail, and resolution goes on.
	NicknameService string
	// NicknameLookup sends a dot-less name to MyTeamSpeak's nickname service
	// first. Off by default: it tells a third party which server the user
	// wants.
	NicknameLookup bool
}

// Resolver is the resolution the client uses by default: a _ts3._udp SRV
// record, then a TSDNS server found through SRV or on the host's domain, then
// the address as given; with NicknameLookup, a dot-less name is first looked
// up at the nickname service. It caches answers for ten minutes. A Resolver is safe
// for concurrent use.
type Resolver struct {
	resolver *discovery.Resolver
}

var _ AddrResolver = (*Resolver)(nil)

// NewResolver returns a Resolver configured by options.
func NewResolver(options ResolverOptions) *Resolver {
	return &Resolver{resolver: discovery.NewResolver(discovery.Options{
		Logger:          options.Logger,
		DNS:             options.DNS,
		HTTPClient:      options.HTTPClient,
		NicknameService: options.NicknameService,
		LookupNicknames: options.NicknameLookup,
	})}
}

// Resolve returns the addresses to try for addr, in order. addr is host or
// host:port; the port defaults to 9987.
func (r *Resolver) Resolve(ctx context.Context, addr string) ([]ResolvedAddr, error) {
	found, err := r.resolver.Resolve(ctx, addr)
	if err != nil {
		return nil, err
	}
	out := make([]ResolvedAddr, len(found))
	for i, f := range found {
		out[i] = ResolvedAddr(f)
	}

	return out, nil
}
