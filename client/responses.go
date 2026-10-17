package client

import "slices"

// Where each command's answer actually arrives.
//
// ServerQuery answers a query with nameless rows followed by error. The voice
// protocol often does not: it answers servergrouplist with a named
// notifyservergrouplist command, clientgetuidfromclid with
// notifyclientuidfromclid, and so on. A client that only collects nameless rows
// reports an empty success for every one of those — which this SDK did, and
// documented as a property of the protocol.
//
// Notifications carry no return_code, so nothing on the wire ties one to the
// command that caused it. The pairing is a property of the command, and this
// table is where it lives. It was measured command by command against TS3
// 3.13.8 and TS6 6.0.0-beta13.1, which answer identically; the TypeScript
// SDK's scripts/probe-response-shapes.mts re-runs that measurement.
//
// Commands not listed answer with nameless rows, or with nothing.

// correlation describes an answer that arrives after the command's error.
//
// File transfer negotiation reports its key once the command has already
// succeeded, echoing the clientftfid the request carried; that echo is the only
// link between the two.
type correlation struct {
	// Key is the request parameter the answer echoes back.
	Key string
	// Failure is a notification that reports failure rather than data. Its
	// status is an ordinary server error id: an ftinitupload refused for
	// permissions answers error id=0 and then this with status=2568.
	Failure string
	// Notifications are the answers, including Failure.
	Notifications []string
}

// responseSpec is how the voice protocol delivers one command's data.
type responseSpec struct {
	// Correlated is set for answers matched on a request field wherever they fall
	// against the error. One that has arrived by the error is taken; if none has,
	// the command waits for it until the caller gives up.
	Correlated *correlation
	// EchoKey names the request parameter an answer echoes back, to tell it
	// from the same notification sent for someone else: notifyclientupdated
	// is sent whenever any client changes, so the row answering clientgetvariables clid=7 is the one
	// with clid=7. A row without the key is taken.
	EchoKey string
	// Notifications carry the data and are sent before the command's error.
	//
	// The same notification can also arrive unprompted —
	// notifyservergrouplist after someone else edits a group — so it is still
	// dispatched as an event.
	Notifications []string
	// OwnRowsOnly keeps only rows whose invokerid is the client itself.
	// notifychannelcreated is broadcast for every channel anyone creates; the
	// one answering our channelcreate is the one we invoked.
	OwnRowsOnly bool
}

// declares reports whether the spec names notification as an answer, before or
// after the error.
func (s *responseSpec) declares(notification string) bool {
	if s == nil {
		return false
	}
	if slices.Contains(s.Notifications, notification) {
		return true
	}

	return s.Correlated != nil && slices.Contains(s.Correlated.Notifications, notification)
}

// isInline reports whether notification is one of the answers sent before the
// error.
func (s *responseSpec) isInline(notification string) bool {
	return s != nil && slices.Contains(s.Notifications, notification)
}

func inline(notifications ...string) *responseSpec {
	return &responseSpec{Notifications: notifications}
}

func fileTransfer(answer string) *responseSpec {
	return &responseSpec{Correlated: &correlation{
		Key:           "clientftfid",
		Failure:       "notifystatusfiletransfer",
		Notifications: []string{answer, "notifystatusfiletransfer"},
	}}
}

var responses = map[string]*responseSpec{
	"apikeyadd":                 inline("notifyapikeyadd"),
	"apikeylist":                inline("notifyapikeylist"),
	"banfind":                   inline("notifybanfind"),
	"banlist":                   inline("notifybanlist"),
	"channelclientpermlist":     inline("notifychannelclientpermlist"),
	"channelcreate":             {Notifications: []string{"notifychannelcreated"}, OwnRowsOnly: true},
	"channelgetdescription":     inline("notifychanneledited"),
	"channelgroupadd":           inline("notifychannelgrouplist"),
	"channelgroupclientlist":    inline("notifychannelgroupclientlist"),
	"channelgroupcopy":          inline("notifychannelgrouplist"),
	"channelgrouplist":          inline("notifychannelgrouplist"),
	"channelgrouppermlist":      inline("notifychannelgrouppermlist"),
	"channelpermlist":           inline("notifychannelpermlist"),
	"clientdbfind":              inline("notifyclientdbfind"),
	"clientdblist":              inline("notifyclientdblist"),
	"clientgetdbidfromuid":      inline("notifyclientdbidfromuid"),
	"clientgetids":              inline("notifyclientids"),
	"clientgetnamefromdbid":     inline("notifyclientnamefromdbid"),
	"clientgetnamefromuid":      inline("notifyclientnamefromuid"),
	"clientgetuidfromclid":      inline("notifyclientuidfromclid"),
	"clientgetvariables":        {Notifications: []string{"notifyclientupdated"}, EchoKey: "clid"},
	"clientpermlist":            inline("notifyclientpermlist"),
	"clientsetserverquerylogin": inline("notifyclientserverqueryloginpassword"),
	"complainlist":              inline("notifycomplainlist"),
	"ftgetfileinfo":             inline("notifyfileinfo"),
	"ftgetfilelist":             inline("notifyfilelist"),
	"ftinitdownload":            fileTransfer("notifystartdownload"),
	"ftinitupload":              fileTransfer("notifystartupload"),
	"ftlist":                    inline("notifyfiletransferlist"),
	// Matched on the echoed clid, wherever the row falls against the error:
	// TeamSpeak 6 sent error id=0 ahead of the notifyconnectioninfo row in about
	// 3% of the commands (6 of 240) when four were in flight at once, never with
	// one at a time (over 800 sequential commands, both servers); TeamSpeak 3
	// never did. Rows for the same client also arrive unprompted, when the target
	// answers the server's notifyconnectioninforequest, so a row's position says
	// nothing about which command it answers; the echo does.
	"getconnectioninfo": {Correlated: &correlation{
		Key: "clid", Notifications: []string{"notifyconnectioninfo"},
	}},
	"logview":                     inline("notifyserverlog"),
	"messageget":                  inline("notifymessage"),
	"messagelist":                 inline("notifymessagelist"),
	"permfind":                    inline("notifypermfind"),
	"permget":                     inline("notifypermget"),
	"permissionlist":              inline("notifypermissionlist"),
	"permoverview":                inline("notifypermoverview"),
	"privilegekeyadd":             inline("notifytokenadd"),
	"privilegekeylist":            inline("notifytokenlist"),
	"servergroupadd":              inline("notifyservergrouplist"),
	"servergroupclientlist":       inline("notifyservergroupclientlist"),
	"servergroupcopy":             inline("notifyservergrouplist"),
	"servergetvariables":          inline("notifyserverupdated"),
	"servergrouplist":             inline("notifyservergrouplist"),
	"servergrouppermlist":         inline("notifyservergrouppermlist"),
	"servergroupsbyclientid":      inline("notifyservergroupsbyclientid"),
	"serverrequestconnectioninfo": inline("notifyserverconnectioninfo"),
	"servertemppasswordlist":      inline("notifyservertemppasswordlist"),
	"tokenadd":                    inline("notifytokenadd"),
	"tokenlist":                   inline("notifytokenlist"),
}

// responseFor returns the response shape of a command, or nil for plain rows.
func responseFor(command string) *responseSpec {
	return responses[command]
}
