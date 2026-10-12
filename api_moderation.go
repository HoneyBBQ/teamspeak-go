package teamspeak

import "context"

// Bans, complaints, offline messages, text messages and the server log.
//
// All administrative: expect a permission error, not an empty list, when the
// client lacks the rights.

// BanEntry is a ban as banlist reports it.
type BanEntry struct {
	IP                string
	Name              string
	UID               string
	LastNickname      string
	InvokerName       string
	InvokerUID        string
	Reason            string
	ID                uint64
	Created           uint64
	Duration          uint64
	InvokerDatabaseID uint64
}

func parseBan(row map[string]string) BanEntry {
	return BanEntry{
		ID:                fieldUint(row, "banid"),
		IP:                fieldStr(row, "ip"),
		Name:              fieldStr(row, "name"),
		UID:               fieldStr(row, "uid"),
		LastNickname:      fieldStr(row, "lastnickname"),
		Created:           fieldUint(row, "created"),
		Duration:          fieldUint(row, "duration"),
		InvokerDatabaseID: fieldUint(row, "invokercldbid"),
		InvokerName:       fieldStr(row, "invokername"),
		InvokerUID:        fieldStr(row, "invokeruid"),
		Reason:            fieldStr(row, "reason"),
	}
}

// ListBans returns every active ban.
func (c *Commands) ListBans(ctx context.Context) ([]BanEntry, error) {
	rows, err := c.query(ctx, "banlist", nil)
	if err != nil {
		return nil, err
	}

	out := make([]BanEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, parseBan(row))
	}

	return out, nil
}

// BanOptions describe a ban. At least one of IP, Name or UID must be set, or the
// server rejects the call.
type BanOptions struct {
	IP     *string
	Name   *string
	UID    *string
	Reason *string
	// Duration is in seconds; 0 means permanent.
	Duration *uint64
}

// AddBan adds a ban and returns its id.
func (c *Commands) AddBan(ctx context.Context, opts BanOptions) (uint64, error) {
	rows, err := c.query(ctx, "banadd", []param{
		strPtrArg("ip", opts.IP),
		strPtrArg("name", opts.Name),
		strPtrArg("uid", opts.UID),
		uintPtrArg("time", opts.Duration),
		strPtrArg("banreason", opts.Reason),
	})
	if err != nil {
		return 0, err
	}

	return firstOrEmpty(rows, "banid"), nil
}

// BanClient bans a connected client by clid and returns the ban id.
func (c *Commands) BanClient(ctx context.Context, clid uint16, duration *uint64, reason *string) (uint64, error) {
	rows, err := c.query(ctx, "banclient", []param{
		uintArg("clid", uint64(clid)),
		uintPtrArg("time", duration),
		strPtrArg("banreason", reason),
	})
	if err != nil {
		return 0, err
	}

	return firstOrEmpty(rows, "banid"), nil
}

// DeleteBan removes a ban.
func (c *Commands) DeleteBan(ctx context.Context, banID uint64) error {
	return c.exec(ctx, "bandel", []param{uintArg("banid", banID)})
}

// DeleteAllBans removes every ban.
func (c *Commands) DeleteAllBans(ctx context.Context) error {
	return c.exec(ctx, "bandelall", nil)
}

// ---- Complaints -------------------------------------------------------------

// Complaint is one client's complaint against another.
type Complaint struct {
	TargetName       string
	FromName         string
	Message          string
	TargetDatabaseID uint64
	FromDatabaseID   uint64
	Timestamp        uint64
}

// ListComplaints returns complaints, optionally only those against one client.
func (c *Commands) ListComplaints(ctx context.Context, targetDBID *uint64) ([]Complaint, error) {
	rows, err := c.query(ctx, "complainlist", []param{uintPtrArg("tcldbid", targetDBID)})
	if err != nil {
		return nil, err
	}

	out := make([]Complaint, 0, len(rows))
	for _, row := range rows {
		out = append(out, Complaint{
			TargetDatabaseID: fieldUint(row, "tcldbid"),
			TargetName:       fieldStr(row, "tname"),
			FromDatabaseID:   fieldUint(row, "fcldbid"),
			FromName:         fieldStr(row, "fname"),
			Message:          fieldStr(row, "message"),
			Timestamp:        fieldUint(row, "timestamp"),
		})
	}

	return out, nil
}

// AddComplaint files a complaint against a client.
func (c *Commands) AddComplaint(ctx context.Context, targetDBID uint64, message string) error {
	return c.exec(ctx, "complainadd", []param{
		uintArg("tcldbid", targetDBID),
		strArg("message", message),
	})
}

// DeleteComplaint withdraws one complaint.
func (c *Commands) DeleteComplaint(ctx context.Context, targetDBID, fromDBID uint64) error {
	return c.exec(ctx, "complaindel", []param{
		uintArg("tcldbid", targetDBID),
		uintArg("fcldbid", fromDBID),
	})
}

// DeleteAllComplaints withdraws every complaint against a client.
func (c *Commands) DeleteAllComplaints(ctx context.Context, targetDBID uint64) error {
	return c.exec(ctx, "complaindelall", []param{uintArg("tcldbid", targetDBID)})
}

// ---- Offline messages -------------------------------------------------------

// OfflineMessage is a message left for a client while they were away.
type OfflineMessage struct {
	UID       string
	Subject   string
	Message   string
	ID        uint64
	Timestamp uint64
	IsRead    bool
}

func parseMessage(row map[string]string) OfflineMessage {
	return OfflineMessage{
		ID:        fieldUint(row, "msgid"),
		UID:       fieldStr(row, "cluid"),
		Subject:   fieldStr(row, "subject"),
		Message:   fieldStr(row, "message"),
		Timestamp: fieldUint(row, "timestamp"),
		IsRead:    fieldBool(row, "flag_read"),
	}
}

// ListMessages returns offline messages for this client.
func (c *Commands) ListMessages(ctx context.Context) ([]OfflineMessage, error) {
	rows, err := c.query(ctx, "messagelist", nil)
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
func (c *Commands) GetMessage(ctx context.Context, messageID uint64) (OfflineMessage, error) {
	rows, err := c.query(ctx, "messageget", []param{uintArg("msgid", messageID)})
	if err != nil {
		return OfflineMessage{}, err
	}

	if len(rows) == 0 {
		return OfflineMessage{}, errNoDataReturned
	}

	return parseMessage(rows[0]), nil
}

// DeleteMessage removes an offline message.
func (c *Commands) DeleteMessage(ctx context.Context, messageID uint64) error {
	return c.exec(ctx, "messagedel", []param{uintArg("msgid", messageID)})
}

// UpdateMessageFlag marks a message read or unread.
func (c *Commands) UpdateMessageFlag(ctx context.Context, messageID uint64, read bool) error {
	return c.exec(ctx, "messageupdateflag", []param{
		uintArg("msgid", messageID),
		boolArg("flag", read),
	})
}

// ---- Text messages ----------------------------------------------------------

// TextMessageTarget is where SendTextMessage delivers.
type TextMessageTarget int

const (
	// TextMessageTargetClient is a private message; the target is a clid.
	TextMessageTargetClient TextMessageTarget = 1
	// TextMessageTargetChannel is a message in one channel; the target is a cid.
	TextMessageTargetChannel TextMessageTarget = 2
	// TextMessageTargetServer is a message to everyone; no target.
	TextMessageTargetServer TextMessageTarget = 3
)

// SendTextMessage sends a text message.
//
// The target is a clid, a cid or nothing depending on mode, which is why the two
// are separate parameters rather than one polymorphic id: passing a channel id
// to a client-mode message reaches an unrelated client. Pass 0 as the target for
// a server-wide message.
//
// It waits for the server's answer, so a refusal — no permission to message
// that target — is returned rather than lost. Call it from a goroutine to send
// without waiting.
func (c *Commands) SendTextMessage(ctx context.Context, mode TextMessageTarget, target uint64, message string) error {
	params := []param{
		intArg("targetmode", int64(mode)),
		strArg("msg", message),
	}
	if mode != TextMessageTargetServer {
		params = append(params, uintArg("target", target))
	}

	return c.exec(ctx, "sendtextmessage", params)
}

// ---- Log --------------------------------------------------------------------

// LogLevel is a server log severity, matching the server's own levels.
type LogLevel int

const (
	LogLevelError   LogLevel = 1
	LogLevelWarning LogLevel = 2
	LogLevelDebug   LogLevel = 3
	LogLevelInfo    LogLevel = 4
)

// LogPage is one read of the server log.
type LogPage struct {
	Lines []string
	// LastPosition is the server's offset, for paging with BeginPosition.
	LastPosition uint64
	FileSize     uint64
}

// LogViewOptions select which part of the log to read.
type LogViewOptions struct {
	Lines         *uint64
	BeginPosition *uint64
	Reverse       *bool
	Instance      *bool
}

// ViewLog reads the server log.
func (c *Commands) ViewLog(ctx context.Context, opts LogViewOptions) (LogPage, error) {
	rows, err := c.query(ctx, "logview", []param{
		uintPtrArg("lines", opts.Lines),
		boolPtrArg("reverse", opts.Reverse),
		boolPtrArg("instance", opts.Instance),
		uintPtrArg("begin_pos", opts.BeginPosition),
	})
	if err != nil {
		return LogPage{}, err
	}

	if len(rows) == 0 {
		return LogPage{}, nil
	}

	row := rows[0]
	page := LogPage{
		LastPosition: fieldUint(row, "last_pos"),
		FileSize:     fieldUint(row, "file_size"),
	}
	if text := fieldStr(row, "log"); text != "" {
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
