package teamspeak

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// API keys and query logins: the credentials a ServerQuery or WebQuery client
// signs in with.
//
// Both hand out a secret exactly once — the key itself, a generated password —
// so the types that carry one redact it from fmt and log/slog, as PrivilegeKey
// does with its token.

// APIKeyScope is what an API key may do (scope).
type APIKeyScope string

const (
	// APIKeyScopeManage lets the key manage the server, including its other
	// keys.
	APIKeyScopeManage APIKeyScope = "manage"
	// APIKeyScopeWrite lets the key read and change.
	APIKeyScopeWrite APIKeyScope = "write"
	// APIKeyScopeRead lets the key read only.
	APIKeyScopeRead APIKeyScope = "read"
)

// APIKey is an API key, as apikeylist reports one. The key's value is not in
// it: the server shows that once, when the key is made, and AddAPIKey returns
// it as APIKeyCreated.Key.
type APIKey struct {
	// Created is when the key was made (created_at).
	Created time.Time
	// Expires is when the key stops working (expires_at); zero for a key that
	// never expires.
	Expires time.Time
	// Scope is what the key may do (scope).
	Scope APIKeyScope
	// CustomID is the key's custom id (custom_id). TeamSpeak 6 sends it, empty
	// unless one was set; TeamSpeak 3 does not send it.
	CustomID string
	// TimeLeft is how long the key still works (time_left, in seconds); 0 for a
	// key that never expires, which Unlimited reports.
	TimeLeft time.Duration
	// ID identifies the key, for DeleteAPIKey (id).
	ID APIKeyID
	// ServerID is the virtual server the key belongs to (sid).
	ServerID ServerID
	// OwnerDatabaseID is the database id of the client the key belongs to
	// (cldbid).
	OwnerDatabaseID ClientDBID
	// Unlimited reports a key that never expires. The server sends
	// time_left=unlimited for it, and an expires_at equal to created_at.
	Unlimited bool
}

func parseAPIKey(row map[string]string) APIKey {
	key := APIKey{
		ID:              APIKeyID(fieldUint(row, "id")),
		ServerID:        ServerID(fieldUint(row, "sid")),
		OwnerDatabaseID: ClientDBID(fieldUint(row, "cldbid")),
		Scope:           APIKeyScope(fieldStr(row, "scope")),
		CustomID:        fieldStr(row, "custom_id"),
		Created:         fieldTime(row, "created_at"),
	}
	if row["time_left"] == "unlimited" {
		key.Unlimited = true

		return key
	}
	key.TimeLeft = fieldDuration(row, "time_left", time.Second)
	key.Expires = fieldTime(row, "expires_at")

	return key
}

// APIKeyCreated is an API key AddAPIKey just made: the key as ListAPIKeys
// would report it, with its value.
//
// Key is a secret, shown once: it signs in as the key's owner, and the server
// does not show it again, so keep it where it is needed and do not log it.
// String, GoString and LogValue leave it out, so the value can reach fmt and
// log/slog safely. encoding/json does not: the key is the caller's own data,
// which they may need to store, so json.Marshal includes it.
type APIKeyCreated struct {
	APIKey

	// Key is the key itself (apikey).
	Key string
}

// String describes the key without the key itself.
func (k APIKeyCreated) String() string {
	return fmt.Sprintf("{ID:%d Scope:%s OwnerDatabaseID:%d ServerID:%d Unlimited:%t Key:redacted}",
		k.ID, k.Scope, k.OwnerDatabaseID, k.ServerID, k.Unlimited)
}

// GoString is String, so %#v redacts too.
func (k APIKeyCreated) GoString() string { return k.String() }

// LogValue describes the key to log/slog without the key itself, so the JSON
// handler, which would otherwise marshal the fields, redacts too.
func (k APIKeyCreated) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Uint64("id", uint64(k.ID)),
		slog.String("scope", string(k.Scope)),
		slog.Uint64("owner_database_id", uint64(k.OwnerDatabaseID)),
		slog.Uint64("server_id", uint64(k.ServerID)),
		slog.Bool("unlimited", k.Unlimited),
		slog.String("key", "redacted"),
	)
}

// APIKeyOptions describe an API key to create.
type APIKeyOptions struct {
	// Lifetime is how long the key works, sent in whole days, rounded to the
	// nearest and never down to 0 for a positive one. nil leaves it to the
	// server, which gives 14 days; a pointer to 0 makes a key that never
	// expires (lifetime).
	Lifetime *time.Duration
	// Scope is what the key may do (scope). Required: an empty one is refused
	// with ErrInvalidCommand.
	Scope APIKeyScope
	// OwnerDatabaseID is the client the key is made for (cldbid); 0 is this
	// connection's own client. Another client's takes
	// b_virtualserver_apikey_manage.
	OwnerDatabaseID ClientDBID
}

// AddAPIKey creates an API key and returns it, with the key itself, which the
// server does not show again: store it now. It sends apikeyadd.
//
// Needs b_virtualserver_apikey_add, and b_virtualserver_apikey_manage for
// OwnerDatabaseID. A server that does not know the owner answers 512, "invalid
// clientID". Both TeamSpeak 3 (3.13) and TeamSpeak 6 serve it, over
// ServerQuery and the voice protocol; TeamSpeak 6 adds custom_id to the
// answer.
func (c *Commands) AddAPIKey(ctx context.Context, opts APIKeyOptions) (APIKeyCreated, error) {
	scope := optStrArg("scope", string(opts.Scope))
	if opts.Scope == "" {
		scope = invalidArg("an API key needs a scope")
	}

	row, err := c.queryRow(ctx, "apikeyadd", "apikey", []param{
		scope,
		durationPtrArg("lifetime", opts.Lifetime, 24*time.Hour),
		optIDArg("cldbid", opts.OwnerDatabaseID),
	})
	if err != nil {
		return APIKeyCreated{}, err
	}

	return APIKeyCreated{APIKey: parseAPIKey(row), Key: fieldStr(row, "apikey")}, nil
}

// APIKeyListOptions are ListAPIKeys' optional parameters.
type APIKeyListOptions struct {
	// OwnerDatabaseID lists this client's keys (cldbid); 0 lists the keys of
	// this connection's own client. Another client's takes
	// b_virtualserver_apikey_manage.
	OwnerDatabaseID ClientDBID
	// Start is how many keys to skip (start); 0 starts at the first.
	Start int
	// Limit is how many keys to return at most (duration); 0 leaves it to the
	// server.
	Limit int
	// AllOwners lists every client's keys (cldbid=*), which takes
	// b_virtualserver_apikey_manage. It is exclusive with OwnerDatabaseID.
	AllOwners bool
}

// ListAPIKeys returns API keys, without their key values, none when there are
// none. It sends apikeylist.
//
// A negative Start or Limit, or OwnerDatabaseID together with AllOwners, is
// refused with ErrInvalidCommand. Measured on TeamSpeak 3 and 6, over
// ServerQuery and the voice protocol.
func (c *Commands) ListAPIKeys(ctx context.Context, opts APIKeyListOptions) ([]APIKey, error) {
	owner := optIDArg("cldbid", opts.OwnerDatabaseID)
	switch {
	case opts.AllOwners && opts.OwnerDatabaseID != 0:
		owner = invalidArg("cldbid: AllOwners and OwnerDatabaseID name two owners")
	case opts.AllOwners:
		owner = strArg("cldbid", "*")
	}

	rows, err := c.list(ctx, "apikeylist", append(pageParams(opts.Start, opts.Limit), owner))
	if err != nil {
		return nil, err
	}

	out := make([]APIKey, 0, len(rows))
	for _, row := range rows {
		out = append(out, parseAPIKey(row))
	}

	return out, nil
}

// DeleteAPIKey removes an API key. It sends apikeydel.
//
// A key of this connection's own client can always be deleted; another's takes
// b_virtualserver_apikey_manage. A key that does not exist is 5123, "invalid
// apikey id".
func (c *Commands) DeleteAPIKey(ctx context.Context, id APIKeyID) error {
	return c.exec(ctx, "apikeydel", []param{idArg("id", id)})
}

// pageParams encodes a page of a list command: the offset (start) and the
// size (duration), each left out when 0, each refused when negative.
func pageParams(start, limit int) []param {
	params := make([]param, 0, 3)
	if start != 0 {
		params = append(params, nonNegativeArg("start", start))
	}
	if limit != 0 {
		params = append(params, nonNegativeArg("duration", limit))
	}

	return params
}

// ---- Query logins -----------------------------------------------------------

// QueryLogin is a ServerQuery login, as queryloginlist reports one. The
// password is not in it: the server shows a generated one once, and AddQueryLogin
// and SetQueryLogin return it as QueryLoginCreated.Password.
type QueryLogin struct {
	// Name is the login name (client_login_name).
	Name string
	// DatabaseID is the database id of the client the login belongs to
	// (cldbid).
	DatabaseID ClientDBID
	// ServerID is the virtual server the login belongs to (sid); 0 for a
	// global login, one made with no server selected.
	ServerID ServerID
}

func parseQueryLogin(row map[string]string) QueryLogin {
	return QueryLogin{
		Name:       fieldStr(row, "client_login_name"),
		DatabaseID: ClientDBID(fieldUint(row, "cldbid")),
		ServerID:   ServerID(fieldUint(row, "sid")),
	}
}

// QueryLoginCreated is a ServerQuery login a command just made or renamed: the
// login as ListQueryLogins would report it, with its generated password.
//
// Password is a secret, shown once: it signs in as the login, and the server
// does not show it again, so keep it where it is needed and do not log it.
// String, GoString and LogValue leave it out, so the value can reach fmt and
// log/slog safely. encoding/json does not: the password is the caller's own
// data, which they may need to store, so json.Marshal includes it.
type QueryLoginCreated struct {
	QueryLogin

	// Password is the generated password (client_login_password).
	Password string
}

// String describes the login without its password.
func (l QueryLoginCreated) String() string {
	return fmt.Sprintf("{Name:%q DatabaseID:%d ServerID:%d Password:redacted}", l.Name, l.DatabaseID, l.ServerID)
}

// GoString is String, so %#v redacts too.
func (l QueryLoginCreated) GoString() string { return l.String() }

// LogValue describes the login to log/slog without its password, so the JSON
// handler, which would otherwise marshal the fields, redacts too.
func (l QueryLoginCreated) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("name", l.Name),
		slog.Uint64("database_id", uint64(l.DatabaseID)),
		slog.Uint64("server_id", uint64(l.ServerID)),
		slog.String("password", "redacted"),
	)
}

// QueryLoginOptions are AddQueryLogin's optional parameters.
type QueryLoginOptions struct {
	// DatabaseID is the client to enable the login for (cldbid). With a server
	// selected it is required: the server answers 1539, "parameter not found",
	// without it. With none selected the server makes a new global login, and 0
	// is right.
	DatabaseID ClientDBID
}

// AddQueryLogin creates a ServerQuery login named name and returns it with its
// generated password, which the server does not show again: store it now. It
// sends queryloginadd.
//
// Needs b_serverquery_login_create. A name already taken is 1282, "database
// duplicate entry". ServerQuery only: the voice protocol answers 2, "not
// implemented". Measured on TeamSpeak 3 and 6.
func (c *Commands) AddQueryLogin(ctx context.Context, name string, opts QueryLoginOptions) (QueryLoginCreated, error) {
	row, err := c.queryRow(ctx, "queryloginadd", "client_login_password", []param{
		strArg("client_login_name", name),
		optIDArg("cldbid", opts.DatabaseID),
	})
	if err != nil {
		return QueryLoginCreated{}, err
	}

	return QueryLoginCreated{
		QueryLogin: parseQueryLogin(row),
		Password:   fieldStr(row, "client_login_password"),
	}, nil
}

// QueryLoginListOptions are ListQueryLogins' optional parameters.
type QueryLoginListOptions struct {
	// Pattern matches the login name, with SQL wildcards such as % (pattern);
	// "" lists every login.
	Pattern string
	// Start is how many logins to skip (start); 0 starts at the first.
	Start int
	// Limit is how many logins to return at most (duration); 0 leaves it to the
	// server.
	Limit int
}

// ListQueryLogins returns ServerQuery logins, without their passwords, none
// when there are none. It sends queryloginlist.
//
// With a server selected it lists that server's logins; with none, all of
// them. Needs b_serverquery_login_list. A negative Start or Limit is refused
// with ErrInvalidCommand. ServerQuery only, measured on TeamSpeak 3 and 6.
func (c *Commands) ListQueryLogins(ctx context.Context, opts QueryLoginListOptions) ([]QueryLogin, error) {
	rows, err := c.list(ctx, "queryloginlist",
		append(pageParams(opts.Start, opts.Limit), optStrArg("pattern", opts.Pattern)))
	if err != nil {
		return nil, err
	}

	out := make([]QueryLogin, 0, len(rows))
	for _, row := range rows {
		out = append(out, parseQueryLogin(row))
	}

	return out, nil
}

// DeleteQueryLogin removes the ServerQuery login of a client. It sends
// querylogindel.
//
// With a server selected it removes that server's login; with none, the global
// one. Needs b_serverquery_login_delete. ServerQuery only, measured on
// TeamSpeak 3 and 6.
func (c *Commands) DeleteQueryLogin(ctx context.Context, clientDBID ClientDBID) error {
	return c.exec(ctx, "querylogindel", []param{idArg("cldbid", clientDBID)})
}

// SetQueryLogin renames this connection's own ServerQuery login and returns it
// with a newly generated password, replacing the old one: store it now. It
// sends clientsetserverquerylogin.
//
// The answer carries only the password, so the result's Name is name and its
// other fields are empty. Needs b_client_create_modify_serverquery_login. The
// connection must be a client of a selected server, not the instance: without
// one the server answers 512, "invalid clientID". Both TeamSpeak 3 and 6
// answer it over ServerQuery, and over the voice protocol too.
func (c *Commands) SetQueryLogin(ctx context.Context, name string) (QueryLoginCreated, error) {
	row, err := c.queryRow(ctx, "clientsetserverquerylogin", "client_login_password", []param{
		strArg("client_login_name", name),
	})
	if err != nil {
		return QueryLoginCreated{}, err
	}

	return QueryLoginCreated{
		QueryLogin: QueryLogin{Name: name},
		Password:   fieldStr(row, "client_login_password"),
	}, nil
}
