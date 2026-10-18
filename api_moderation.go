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
	// MyTSID is the MyTeamSpeak id the ban matches (mytsid); "" if it matches
	// none. TeamSpeak 3 and 6 both send the field, empty unless one was set.
	MyTSID string
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
	// Enforcements is how many times the ban has turned a client away
	// (enforcements). TeamSpeak 3 and 6 both send it.
	Enforcements uint64
}

func parseBan(row map[string]string) BanEntry {
	return BanEntry{
		ID:                BanID(fieldUint(row, "banid")),
		IP:                fieldStr(row, "ip"),
		Name:              fieldStr(row, "name"),
		UID:               UID(fieldStr(row, "uid")),
		LastNickname:      fieldStr(row, "lastnickname"),
		MyTSID:            fieldStr(row, "mytsid"),
		Created:           fieldTime(row, "created"),
		Duration:          fieldDuration(row, "duration", time.Second),
		InvokerDatabaseID: ClientDBID(fieldUint(row, "invokercldbid")),
		InvokerName:       fieldStr(row, "invokername"),
		InvokerUID:        UID(fieldStr(row, "invokeruid")),
		Reason:            fieldStr(row, "reason"),
		Enforcements:      fieldUint(row, "enforcements"),
	}
}

// BanListOptions are ListBans' optional parameters.
type BanListOptions struct {
	// Start is how many bans to skip (start); 0 starts at the first.
	Start int
	// Limit is how many bans to return at most (duration); 0 leaves it to the
	// server, which then returns every ban. The server caps a given Limit at
	// 200, so a larger one returns 200: to walk a long list, ask for pages and
	// step Start by how many came back.
	Limit int
}

// ListBans returns active bans: every one, or the page BanListOptions names.
// It sends banlist.
//
// The server answers an empty list, or a Start past the last ban, with error
// 1281, which here is no bans. A negative Start or Limit is refused with
// ErrInvalidCommand. banlist also takes -count, which adds the total to each
// row; it is not sent, as the result has nowhere to put it.
func (c *Commands) ListBans(ctx context.Context, opts BanListOptions) ([]BanEntry, error) {
	rows, err := c.list(ctx, "banlist", pageParams(opts.Start, opts.Limit))
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
// against a client's address and nickname. At least one of IP, Name, UID or
// MyTSID must be set; a ban matching nothing is refused with
// ErrInvalidCommand.
type BanOptions struct {
	// IP is a regular expression matched against a client's address (ip).
	IP string
	// Name is a regular expression matched against a client's nickname (name).
	Name string
	// UID is a client identity to ban (uid).
	UID UID
	// MyTSID is a MyTeamSpeak id to ban (mytsid): 44 characters of base64, the
	// 32 bytes of a client's id. The server refuses anything else with 1538,
	// "invalid parameter", except the word "empty", which it takes and stores
	// as written. "" sends none. TeamSpeak 3 (3.13) and 6 both take it.
	MyTSID string
	// LastNickname is the nickname to show for the ban in the list
	// (lastnickname); "" sends none.
	LastNickname string
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

// AddBan adds a ban and returns its id. The second return value is false when
// the server reported no id, and the BanID is then meaningless: over the voice
// protocol TeamSpeak 3 and 6 answer banadd with nothing, measured — the ban is
// made all the same, and ListBans finds its id. Over ServerQuery the server
// answers one banid, so there the id is there.
func (c *Commands) AddBan(ctx context.Context, opts BanOptions) (BanID, bool, error) {
	target := optStrArg("ip", opts.IP)
	if opts.IP == "" && opts.Name == "" && opts.UID == "" && opts.MyTSID == "" {
		target = invalidArg("a ban needs an IP, a name, a UID or a MyTeamSpeak id to match")
	}

	rows, err := c.query(ctx, "banadd", []param{
		target,
		optStrArg("name", opts.Name),
		optStrArg("uid", string(opts.UID)),
		optStrArg("mytsid", opts.MyTSID),
		banDurationArg(opts.Duration),
		optStrArg("banreason", opts.Reason),
		optStrArg("lastnickname", opts.LastNickname),
	})
	if err != nil {
		return 0, false, err
	}

	ids := banIDs(rows)
	if len(ids) == 0 {
		return 0, false, nil
	}

	return ids[0], true, nil
}

// banIDs reads the banid of every row that carries one.
//
// A row counts when it names banid with a value, not when the number is
// non-zero. Reading the value and dropping it at 0 threw away a banid the
// server did report, and left a zero meaning both "ban 0" and "no ban
// reported" — the ambiguity AddBan's found result exists to remove. An empty
// value is not one: the package reads a field the row sent empty as absent,
// which is what requireRow does. A row with no banid at all is the server
// having answered nothing, which is what banadd does over the voice protocol.
func banIDs(rows []map[string]string) []BanID {
	ids := make([]BanID, 0, len(rows))
	for _, row := range rows {
		if row["banid"] != "" {
			ids = append(ids, BanID(fieldUint(row, "banid")))
		}
	}

	return ids
}

// BanClientOptions are BanClient's optional parameters.
type BanClientOptions struct {
	// Reason is shown to the banned client; "" sends none.
	Reason string
	// Duration is how long the ban lasts, sent in whole seconds; 0 bans
	// permanently, as for BanOptions.
	Duration time.Duration
}

// BanClient bans a connected client and returns the id of every ban the
// server reported creating. The server bans the client's uid and IP address,
// and its MyTeamSpeak id when it has one: over ServerQuery it answers one banid
// each: measured on TeamSpeak 3 3.13.8 and 6 beta13.1, two (the uid and the
// address), and none for a MyTeamSpeak id when the client has none. TeamSpeak 6
// has answered with no banid at all, though both bans were made (once in about
// a hundred calls over SSH and WebQuery). Over the voice protocol both servers
// answer nothing, so the result is empty though the bans are made. An empty
// result therefore does not mean no ban: ListBans finds what was made, and a
// caller that must undo it lists the bans before and after rather than relying
// on the ids, since a ban on the address refuses every later connection from it.
func (c *Commands) BanClient(ctx context.Context, clid ClientID, opts BanClientOptions) ([]BanID, error) {
	rows, err := c.query(ctx, "banclient", []param{
		idArg("clid", clid),
		banDurationArg(opts.Duration),
		optStrArg("banreason", opts.Reason),
	})
	if err != nil {
		return nil, err
	}

	return banIDs(rows), nil
}

// BanClientsOptions are BanClients' optional parameters.
type BanClientsOptions struct {
	// Reason is shown to the banned clients; "" sends none.
	Reason string
	// Duration is how long the bans last, sent in whole seconds; 0 bans
	// permanently, as for BanOptions.
	Duration time.Duration
	// ContinueOnError sends -continueonerror, so an id that cannot be banned is
	// left out and the others are banned. See BanClients.
	ContinueOnError bool
}

// BanClients bans several connected clients in one command (banclient, one
// clid row each) and returns the id of every ban the server reported creating,
// which BanClient explains: the ids can be fewer than the bans made, and are
// none over the voice protocol. Banning none sends nothing.
//
// The server answers one status for the whole command and never one per
// client. Measured on TeamSpeak 3 3.13.8 and 6 beta13.1, over raw ServerQuery,
// SSH, WebQuery and the voice protocol alike: the server first checks that
// every id is a connected client, and without ContinueOnError an unknown id
// refuses the command with 512 and bans nobody. The bans then go in order; one
// that fails midway (the same client listed twice, which the first ban
// kicked) stops the rest with its error and the bans before it stay. With
// ContinueOnError unknown ids are left out, the others are banned, and the
// answer is success even when no id could be banned, so a failure is not
// reported. Banning two clients through one address made three bans over
// ServerQuery: a uid rule each and one rule on the address. A ban on the address
// refuses every later connection from it: remove what a call made.
func (c *Commands) BanClients(ctx context.Context, clids []ClientID, opts BanClientsOptions) ([]BanID, error) {
	if len(clids) == 0 {
		return nil, nil
	}

	rows, err := c.query(ctx, "banclient", []param{
		continueOnErrorArg(opts.ContinueOnError),
		banDurationArg(opts.Duration),
		optStrArg("banreason", opts.Reason),
		idRowsArg("clid", clids),
	})
	if err != nil {
		return nil, err
	}

	return banIDs(rows), nil
}

// DeleteBan removes a ban.
func (c *Commands) DeleteBan(ctx context.Context, banID BanID) error {
	return c.exec(ctx, "bandel", []param{idArg("banid", banID)})
}

// DeleteAllBans removes every ban.
func (c *Commands) DeleteAllBans(ctx context.Context) error {
	return c.exec(ctx, "bandelall", nil)
}

// BanCriteria say which bans FindBans looks for. A ban matches when it
// holds the value given; at least one field is required.
type BanCriteria struct {
	// IP is an address to look for (ip): the bans whose address pattern covers
	// it.
	IP string
	// Name is a nickname to look for (name).
	Name string
	// UID is a client identity to look for (uid).
	UID UID
	// MyTSID is a MyTeamSpeak id to look for (mytsid).
	MyTSID string
}

// FindBans returns the active bans that match criteria, none when none do. It
// sends banfind.
//
// TeamSpeak 6 only, and needs b_client_ban_list. Criteria with
// nothing set is refused with ErrInvalidCommand. TeamSpeak 3 answers 256,
// "command not found", over ServerQuery and not at all over the voice
// protocol, where the command waits out its timeout. TeamSpeak 6 serves it
// over SSH and the voice protocol; WebQuery refuses it with 1538, "invalid
// parameter".
func (c *Commands) FindBans(ctx context.Context, criteria BanCriteria) ([]BanEntry, error) {
	first := optStrArg("ip", criteria.IP)
	if criteria.IP == "" && criteria.Name == "" && criteria.UID == "" && criteria.MyTSID == "" {
		first = invalidArg("banfind needs an IP, a name, a UID or a MyTeamSpeak id to look for")
	}

	rows, err := c.list(ctx, "banfind", []param{
		first,
		optStrArg("name", criteria.Name),
		optStrArg("uid", string(criteria.UID)),
		optStrArg("mytsid", criteria.MyTSID),
	})
	if err != nil {
		return nil, err
	}

	out := make([]BanEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, parseBan(row))
	}

	return out, nil
}

// ---- Complaints -------------------------------------------------------------

// Complaint is one client's complaint against another.
type Complaint struct {
	// Created is when the complaint was filed.
	Created time.Time
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
			Created:          fieldTime(row, "timestamp"),
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
	// Sent is when the message was sent.
	Sent time.Time
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
		ID:      MessageID(fieldUint(row, "msgid")),
		UID:     UID(fieldStr(row, "cluid")),
		Subject: fieldStr(row, "subject"),
		Message: fieldStr(row, "message"),
		Sent:    fieldTime(row, "timestamp"),
		IsRead:  fieldBool(row, "flag_read"),
	}
}

// SendOfflineMessage leaves a message for a client, to read when it next
// connects. It sends messageadd with the recipient's identity (cluid).
//
// The recipient must be a client the server knows: an identity that never
// connected is refused with 512, "invalid clientID". The recipient's own
// ListMessages and GetMessage read it, and the server tells a connected
// recipient through client_unread_messages in a notifyclientupdated. Needs no
// permission; both TeamSpeak 3 and 6 serve it, over ServerQuery and the voice
// protocol.
func (c *Commands) SendOfflineMessage(ctx context.Context, recipient UID, subject, message string) error {
	return c.exec(ctx, "messageadd", []param{
		strArg("cluid", string(recipient)),
		strArg("subject", subject),
		strArg("message", message),
	})
}

// MessageListOptions are ListMessages' optional parameters. It has no fields
// yet: it is reserved for the parameters of messagelist.
type MessageListOptions struct{}

// ListMessages returns offline messages for this client.
func (c *Commands) ListMessages(ctx context.Context, _ MessageListOptions) ([]OfflineMessage, error) {
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
	row, err := c.queryRow(ctx, "messageget", "", []param{idArg("msgid", messageID)})
	if err != nil {
		return OfflineMessage{}, err
	}

	return parseMessage(row), nil
}

// DeleteMessage removes an offline message.
func (c *Commands) DeleteMessage(ctx context.Context, messageID MessageID) error {
	return c.exec(ctx, "messagedel", []param{idArg("msgid", messageID)})
}

// MessageFlags are the flags UpdateMessageFlag sets on an offline message. The
// flags are sent whole, so a field left false clears its flag.
type MessageFlags struct {
	// Read marks the message read; false marks it unread (flag).
	Read bool
}

// UpdateMessageFlag sets an offline message's flags, marking it read or
// unread.
func (c *Commands) UpdateMessageFlag(ctx context.Context, messageID MessageID, flags MessageFlags) error {
	return c.exec(ctx, "messageupdateflag", []param{
		idArg("msgid", messageID),
		boolArg("flag", flags.Read),
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
	// Reverse reads backwards from BeginPosition, newest line first. Always
	// sent, as reverse=0 or 1.
	Reverse bool
	// Instance reads the instance log rather than the virtual server's.
	// Always sent, as instance=0 or 1.
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

	_, err = requireRow(rows, "logview", "")
	if err != nil {
		return LogPage{}, err
	}

	page := LogPage{
		LastPosition: fieldUint(rows[0], "last_pos"),
		FileSize:     fieldUint(rows[0], "file_size"),
	}
	// One line per row, under the key l. This
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
