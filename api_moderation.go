package teamspeak

import (
	"context"
	"time"
)

// Bans, complaints, offline messages, text messages and the server log.
//
// All administrative: expect a permission error, not an empty list, when the
// client lacks the rights.

// BanEntry is a ban as banlist reports it.
type BanEntry struct {
	// Created is when the ban was made.
	Created time.Time
	// IP is the regular expression the ban matches addresses with (ip); "" if it
	// matches none.
	IP string
	// Name is the regular expression the ban matches nicknames with (name); ""
	// if it matches none.
	Name string
	// UID is the client identity the ban matches (uid); "" if it matches none.
	UID UID
	// LastNickname is the banned client's nickname when the ban was made
	// (lastnickname).
	LastNickname string
	// InvokerName is who made the ban (invokername).
	InvokerName string
	// InvokerUID is the identity of who made the ban (invokeruid).
	InvokerUID UID
	// Reason is the reason given for the ban (reason).
	Reason string
	// ID identifies the ban, for DeleteBan (banid).
	ID BanID
	// Duration is how long the ban lasts from Created, in whole seconds; 0
	// is a permanent ban.
	Duration time.Duration
	// InvokerDatabaseID is the database id of who made the ban (invokercldbid).
	InvokerDatabaseID ClientDBID
}

func parseBan(row map[string]string) BanEntry {
	return BanEntry{
		ID:                BanID(fieldUint(row, "banid")),
		IP:                fieldStr(row, "ip"),
		Name:              fieldStr(row, "name"),
		UID:               UID(fieldStr(row, "uid")),
		LastNickname:      fieldStr(row, "lastnickname"),
		Created:           fieldTime(row, "created"),
		Duration:          fieldDuration(row, "duration", time.Second),
		InvokerDatabaseID: ClientDBID(fieldUint(row, "invokercldbid")),
		InvokerName:       fieldStr(row, "invokername"),
		InvokerUID:        UID(fieldStr(row, "invokeruid")),
		Reason:            fieldStr(row, "reason"),
	}
}

// ListBans returns every active ban.
func (c *Commands) ListBans(ctx context.Context) ([]BanEntry, error) {
	rows, err := c.list(ctx, "banlist", nil)
	if err != nil {
		return nil, err
	}

	out := make([]BanEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, parseBan(row))
	}

	return out, nil
}

// BanOptions describe a ban. IP and Name are regular expressions matched
// against a client's address and nickname. At least one of IP, Name or UID
// must be set; a ban matching nothing is refused with ErrInvalidCommand.
type BanOptions struct {
	// IP is a regular expression matched against a client's address (ip).
	IP string
	// Name is a regular expression matched against a client's nickname (name).
	Name string
	// UID is a client identity to ban (uid).
	UID UID
	// Reason is shown to the banned client; "" sends none.
	Reason string
	// Duration is how long the ban lasts, sent in whole seconds. 0 is a
	// permanent ban, so a positive duration under a second is sent as one
	// second rather than rounded down to forever.
	Duration time.Duration
}

// banDurationArg encodes a ban's duration. A permanent ban omits it: the
// server's default is permanent, which is also what time=0 means.
func banDurationArg(d time.Duration) param {
	if d == 0 {
		return param{Key: "time"}
	}

	return durationArg("time", d, time.Second)
}

// AddBan adds a ban and returns its id.
func (c *Commands) AddBan(ctx context.Context, opts BanOptions) (BanID, error) {
	target := optStrArg("ip", opts.IP)
	if opts.IP == "" && opts.Name == "" && opts.UID == "" {
		target = invalidArg("a ban needs an IP, a name or a UID to match")
	}

	rows, err := c.query(ctx, "banadd", []param{
		target,
		optStrArg("name", opts.Name),
		optStrArg("uid", string(opts.UID)),
		banDurationArg(opts.Duration),
		optStrArg("banreason", opts.Reason),
	})
	if err != nil {
		return 0, err
	}

	return BanID(firstOrEmpty(rows, "banid")), nil
}

// BanClientOptions are BanClient's optional parameters.
type BanClientOptions struct {
	// Reason is shown to the banned client; "" sends none.
	Reason string
	// Duration is how long the ban lasts, sent in whole seconds; 0 bans
	// permanently, as for BanOptions.
	Duration time.Duration
}

// BanClient bans a connected client and returns the ban id.
func (c *Commands) BanClient(ctx context.Context, clid ClientID, opts BanClientOptions) (BanID, error) {
	rows, err := c.query(ctx, "banclient", []param{
		idArg("clid", clid),
		banDurationArg(opts.Duration),
		optStrArg("banreason", opts.Reason),
	})
	if err != nil {
		return 0, err
	}

	return BanID(firstOrEmpty(rows, "banid")), nil
}

// DeleteBan removes a ban.
func (c *Commands) DeleteBan(ctx context.Context, banID BanID) error {
	return c.exec(ctx, "bandel", []param{idArg("banid", banID)})
}

// DeleteAllBans removes every ban.
func (c *Commands) DeleteAllBans(ctx context.Context) error {
	return c.exec(ctx, "bandelall", nil)
}

// ---- Complaints -------------------------------------------------------------

// Complaint is one client's complaint against another.
type Complaint struct {
	// Timestamp is when the complaint was filed.
	Timestamp time.Time
	// TargetName is the nickname of the client complained about (tname).
	TargetName string
	// FromName is the nickname of the client who complained (fname).
	FromName string
	// Message is the complaint's text (message).
	Message string
	// TargetDatabaseID is the database id of the client complained about
	// (tcldbid).
	TargetDatabaseID ClientDBID
	// FromDatabaseID is the database id of the client who complained (fcldbid).
	FromDatabaseID ClientDBID
}

// ComplaintListOptions are ListComplaints' optional parameters.
type ComplaintListOptions struct {
	// TargetDatabaseID lists only the complaints against this client; 0 lists
	// every complaint.
	TargetDatabaseID ClientDBID
}

// ListComplaints returns complaints, filtered as opts says.
func (c *Commands) ListComplaints(ctx context.Context, opts ComplaintListOptions) ([]Complaint, error) {
	rows, err := c.list(ctx, "complainlist", []param{optIDArg("tcldbid", opts.TargetDatabaseID)})
	if err != nil {
		return nil, err
	}

	out := make([]Complaint, 0, len(rows))
	for _, row := range rows {
		out = append(out, Complaint{
			TargetDatabaseID: ClientDBID(fieldUint(row, "tcldbid")),
			TargetName:       fieldStr(row, "tname"),
			FromDatabaseID:   ClientDBID(fieldUint(row, "fcldbid")),
			FromName:         fieldStr(row, "fname"),
			Message:          fieldStr(row, "message"),
			Timestamp:        fieldTime(row, "timestamp"),
		})
	}

	return out, nil
}

// AddComplaint files a complaint against a client.
func (c *Commands) AddComplaint(ctx context.Context, targetDBID ClientDBID, message string) error {
	return c.exec(ctx, "complainadd", []param{
		idArg("tcldbid", targetDBID),
		strArg("message", message),
	})
}

// DeleteComplaint withdraws one complaint.
func (c *Commands) DeleteComplaint(ctx context.Context, targetDBID, fromDBID ClientDBID) error {
	return c.exec(ctx, "complaindel", []param{
		idArg("tcldbid", targetDBID),
		idArg("fcldbid", fromDBID),
	})
}

// DeleteAllComplaints withdraws every complaint against a client.
func (c *Commands) DeleteAllComplaints(ctx context.Context, targetDBID ClientDBID) error {
	return c.exec(ctx, "complaindelall", []param{idArg("tcldbid", targetDBID)})
}

// ---- Offline messages -------------------------------------------------------

// OfflineMessage is a message left for a client while they were away.
type OfflineMessage struct {
	// Timestamp is when the message was sent.
	Timestamp time.Time
	// UID is the sender's.
	UID UID
	// Subject is the message's subject (subject).
	Subject string
	// Message is the message's body (message).
	Message string
	// ID identifies the message (msgid).
	ID MessageID
	// IsRead reports whether the message has been read (flag_read).
	IsRead bool
}

func parseMessage(row map[string]string) OfflineMessage {
	return OfflineMessage{
		ID:        MessageID(fieldUint(row, "msgid")),
		UID:       UID(fieldStr(row, "cluid")),
		Subject:   fieldStr(row, "subject"),
		Message:   fieldStr(row, "message"),
		Timestamp: fieldTime(row, "timestamp"),
		IsRead:    fieldBool(row, "flag_read"),
	}
}

// ListMessages returns offline messages for this client.
func (c *Commands) ListMessages(ctx context.Context) ([]OfflineMessage, error) {
	rows, err := c.list(ctx, "messagelist", nil)
	if err != nil {
		return nil, err
	}

	out := make([]OfflineMessage, 0, len(rows))
	for _, row := range rows {
		out = append(out, parseMessage(row))
	}

	return out, nil
}

// GetMessage returns one offline message.
func (c *Commands) GetMessage(ctx context.Context, messageID MessageID) (OfflineMessage, error) {
	rows, err := c.query(ctx, "messageget", []param{idArg("msgid", messageID)})
	if err != nil {
		return OfflineMessage{}, err
	}

	if len(rows) == 0 {
		return OfflineMessage{}, ErrNoData
	}

	return parseMessage(rows[0]), nil
}

// DeleteMessage removes an offline message.
func (c *Commands) DeleteMessage(ctx context.Context, messageID MessageID) error {
	return c.exec(ctx, "messagedel", []param{idArg("msgid", messageID)})
}

// UpdateMessageFlag marks a message read or unread.
func (c *Commands) UpdateMessageFlag(ctx context.Context, messageID MessageID, read bool) error {
	return c.exec(ctx, "messageupdateflag", []param{
		idArg("msgid", messageID),
		boolArg("flag", read),
	})
}

// ---- Text messages ----------------------------------------------------------

// TextMessageTarget is where a text message goes (targetmode).
type TextMessageTarget int

const (
	// TextMessageTargetClient is a private message to one client.
	TextMessageTargetClient TextMessageTarget = 1
	// TextMessageTargetChannel is a message to the sender's current channel.
	TextMessageTargetChannel TextMessageTarget = 2
	// TextMessageTargetServer is a message to everyone on the virtual server.
	TextMessageTargetServer TextMessageTarget = 3
)

var textMessageTargetNames = [...]string{
	TextMessageTargetClient:  "client",
	TextMessageTargetChannel: "channel",
	TextMessageTargetServer:  "server",
}

// String returns the text message target's name, or "text message target N" for a value this version does
// not know.
func (t TextMessageTarget) String() string {
	return enumName(t, textMessageTargetNames[:], "text message target")
}

// Text messages are three commands rather than one taking a mode and an id,
// because the id meant a different thing in each mode — a clid, a cid, or
// nothing — and an untyped one let a channel id reach an unrelated client.
//
// Each waits for the server's answer, so a refusal — no permission to message
// that target — is returned rather than lost. Call one from a goroutine to send
// without waiting.

// SendPrivateMessage sends a text message to one client.
func (c *Commands) SendPrivateMessage(ctx context.Context, clid ClientID, message string) error {
	return c.exec(ctx, "sendtextmessage", []param{
		intArg("targetmode", int64(TextMessageTargetClient)),
		idArg("target", clid),
		strArg("msg", message),
	})
}

// SendChannelMessage sends a text message to the channel this connection is
// in.
//
// It takes no channel because the server takes none: measured on TS3 and TS6,
// a channel message naming another channel still arrives in the sender's own.
// To write to another channel, move there first.
func (c *Commands) SendChannelMessage(ctx context.Context, message string) error {
	return c.exec(ctx, "sendtextmessage", []param{
		intArg("targetmode", int64(TextMessageTargetChannel)),
		strArg("msg", message),
	})
}

// SendServerMessage sends a text message to everyone on the virtual server.
func (c *Commands) SendServerMessage(ctx context.Context, message string) error {
	return c.exec(ctx, "sendtextmessage", []param{
		intArg("targetmode", int64(TextMessageTargetServer)),
		strArg("msg", message),
	})
}

// ---- Log --------------------------------------------------------------------

// LogLevel is a server log severity, matching the server's own levels.
type LogLevel int

const (
	// LogLevelError is an error.
	LogLevelError LogLevel = 1
	// LogLevelWarning is a warning.
	LogLevelWarning LogLevel = 2
	// LogLevelDebug is debugging detail.
	LogLevelDebug LogLevel = 3
	// LogLevelInfo is routine information.
	LogLevelInfo LogLevel = 4
)

var logLevelNames = [...]string{
	LogLevelError:   "error",
	LogLevelWarning: "warning",
	LogLevelDebug:   "debug",
	LogLevelInfo:    "info",
}

// String returns the log level's name, or "log level N" for a value this version does
// not know.
func (l LogLevel) String() string {
	return enumName(l, logLevelNames[:], "log level")
}

// LogPage is one read of the server log.
type LogPage struct {
	// Lines are the log lines read, oldest first unless the read was reversed.
	Lines []string
	// LastPosition is the byte offset the read stopped at. Pass it as the next
	// read's BeginPosition to continue from there.
	LastPosition uint64
	// FileSize is the log file's size in bytes.
	FileSize uint64
}

// LogViewOptions select which part of the log to read.
//
// The log is paged by byte offset rather than by row, so there is no iterator
// as there is for the client database: read a page, then pass its
// LastPosition as BeginPosition for the next.
type LogViewOptions struct {
	// BeginPosition is the byte offset to read from. A pointer because 0 is
	// meaningful — the start of the log — while nil omits the parameter and
	// leaves where to start to the server.
	BeginPosition *uint64
	// Lines is how many lines to read, at most 100; 0 leaves it to the server.
	Lines uint
	// Reverse reads backwards from BeginPosition, newest line first.
	Reverse bool
	// Instance reads the instance log rather than the virtual server's.
	Instance bool
}

// ViewLog reads a page of the server log.
func (c *Commands) ViewLog(ctx context.Context, opts LogViewOptions) (LogPage, error) {
	params := []param{
		boolArg("reverse", opts.Reverse),
		boolArg("instance", opts.Instance),
		uintPtrArg("begin_pos", opts.BeginPosition),
	}
	if opts.Lines > 0 {
		params = append(params, uintArg("lines", uint64(opts.Lines)))
	}

	rows, err := c.query(ctx, "logview", params)
	if err != nil {
		return LogPage{}, err
	}

	if len(rows) == 0 {
		return LogPage{}, nil
	}

	page := LogPage{
		LastPosition: fieldUint(rows[0], "last_pos"),
		FileSize:     fieldUint(rows[0], "file_size"),
	}
	// One line per row, under the key l (tsdeclarations: ServerLog). This
	// used to read only a "log" field from the first row, which the server
	// does not send; it is still read, should a server send the lines that
	// way.
	for _, row := range rows {
		if line, ok := row["l"]; ok {
			page.Lines = append(page.Lines, line)
		}
	}
	if text := fieldStr(rows[0], "log"); text != "" && len(page.Lines) == 0 {
		page.Lines = splitLines(text)
	}

	return page, nil
}

// AddLog writes an entry to the server log.
func (c *Commands) AddLog(ctx context.Context, level LogLevel, message string) error {
	return c.exec(ctx, "logadd", []param{
		intArg("loglevel", int64(level)),
		strArg("logmsg", message),
	})
}
