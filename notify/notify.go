// Package notify names the notifications a TeamSpeak server sends, for
// matching client.NotificationEvent.Name in OnNotification:
//
//	c.OnNotification(func(n client.NotificationEvent) {
//		if n.Name == notify.ChannelEdited {
//			fmt.Println("channel", n.Params["cid"], "edited")
//		}
//	})
//
// Many are also how the voice protocol answers a command, such as
// notifyservergrouplist for servergrouplist; the client already pairs those
// with their command. A server may send notifications this package does not
// name.
package notify

// The notifications, in alphabetical order.
const (
	// BanList is notifybanlist: reply to banlist: one row per ban rule on the
	// virtual server.
	BanList = "notifybanlist"
	// ChannelChanged is notifychannelchanged: a channel's properties changed and
	// this client should fetch them again.
	ChannelChanged = "notifychannelchanged"
	// ChannelClientPermList is notifychannelclientpermlist: reply to
	// channelclientpermlist: one row per permission set for a client in a channel.
	ChannelClientPermList = "notifychannelclientpermlist"
	// ChannelCreated is notifychannelcreated: a channel was created: it carries
	// the new channel's properties and who created it.
	ChannelCreated = "notifychannelcreated"
	// ChannelDeleted is notifychanneldeleted: a channel was deleted, with who
	// deleted it.
	ChannelDeleted = "notifychanneldeleted"
	// ChannelDescriptionChanged is notifychanneldescriptionchanged: a channel's
	// description changed; the new text is fetched with channelgetdescription.
	ChannelDescriptionChanged = "notifychanneldescriptionchanged"
	// ChannelEdited is notifychanneledited: a channel was edited and these are its
	// changed properties; it is also the reply to channelgetdescription, carrying
	// the description.
	ChannelEdited = "notifychanneledited"
	// ChannelGroupClientList is notifychannelgroupclientlist: reply to
	// channelgroupclientlist: one row per client assigned to a channel group in a
	// channel.
	ChannelGroupClientList = "notifychannelgroupclientlist"
	// ChannelGroupList is notifychannelgrouplist: reply to channelgrouplist, and
	// sent by the server on joining: one row per channel group.
	ChannelGroupList = "notifychannelgrouplist"
	// ChannelGroupPermList is notifychannelgrouppermlist: reply to
	// channelgrouppermlist: one row per permission set on a channel group.
	ChannelGroupPermList = "notifychannelgrouppermlist"
	// ChannelMoved is notifychannelmoved: a channel was moved under another parent
	// channel or reordered, with who moved it.
	ChannelMoved = "notifychannelmoved"
	// ChannelPasswordChanged is notifychannelpasswordchanged: a channel's password
	// was set or changed.
	ChannelPasswordChanged = "notifychannelpasswordchanged"
	// ChannelPermHints is notifychannelpermhints: the permissions this client
	// holds on a channel changed; a bit set of hints tells which kinds of
	// permission changed.
	ChannelPermHints = "notifychannelpermhints"
	// ChannelPermList is notifychannelpermlist: reply to channelpermlist: one row
	// per permission set on a channel.
	ChannelPermList = "notifychannelpermlist"
	// ChannelSubscribed is notifychannelsubscribed: this client is now subscribed
	// to a channel, so it will see the clients in it.
	ChannelSubscribed = "notifychannelsubscribed"
	// ChannelUnsubscribed is notifychannelunsubscribed: this client is no longer
	// subscribed to a channel, so the clients in it have gone out of view.
	ChannelUnsubscribed = "notifychannelunsubscribed"
	// ClientChannelGroupChanged is notifyclientchannelgroupchanged: a client's
	// channel group in a channel changed, with who changed it.
	ClientChannelGroupChanged = "notifyclientchannelgroupchanged"
	// ClientChatClosed is notifyclientchatclosed: a client closed its private chat
	// with this client.
	ClientChatClosed = "notifyclientchatclosed"
	// ClientChatComposing is notifyclientchatcomposing: a client is typing a
	// private message to this client.
	ClientChatComposing = "notifyclientchatcomposing"
	// ClientDBFind is notifyclientdbfind: reply to clientdbfind: one row per
	// matching client in the database.
	ClientDBFind = "notifyclientdbfind"
	// ClientDBIDFromUID is notifyclientdbidfromuid: reply to clientgetdbidfromuid:
	// the database id of the client with that unique id.
	ClientDBIDFromUID = "notifyclientdbidfromuid"
	// ClientDBList is notifyclientdblist: reply to clientdblist: one row per
	// client known to the server.
	ClientDBList = "notifyclientdblist"
	// ClientEnterView is notifycliententerview: a client came into view: it
	// connected, or moved into a channel this client is subscribed to.
	ClientEnterView = "notifycliententerview"
	// ClientIDs is notifyclientids: reply to clientgetids: the online client ids
	// that belong to a unique id.
	ClientIDs = "notifyclientids"
	// ClientLeftView is notifyclientleftview: a client went out of view: it
	// disconnected, was kicked or banned, or moved out of the subscribed channels.
	ClientLeftView = "notifyclientleftview"
	// ClientMoved is notifyclientmoved: a client moved to another channel, with
	// the reason and who moved it.
	ClientMoved = "notifyclientmoved"
	// ClientNameFromDBID is notifyclientnamefromdbid: reply to
	// clientgetnamefromdbid: the unique id and nickname of the client with that
	// database id.
	ClientNameFromDBID = "notifyclientnamefromdbid"
	// ClientNameFromUID is notifyclientnamefromuid: reply to clientgetnamefromuid:
	// the database id and nickname of the client with that unique id.
	ClientNameFromUID = "notifyclientnamefromuid"
	// ClientNeededPermissions is notifyclientneededpermissions: a command failed
	// or a feature is unavailable because this client lacks a permission; it names
	// the permission id and the value needed.
	ClientNeededPermissions = "notifyclientneededpermissions"
	// ClientPermHints is notifyclientpermhints: the permissions this client holds
	// changed; a bit set of hints tells which kinds of permission changed.
	ClientPermHints = "notifyclientpermhints"
	// ClientPermList is notifyclientpermlist: reply to clientpermlist: one row per
	// permission set on a client.
	ClientPermList = "notifyclientpermlist"
	// ClientPoke is notifyclientpoke: another client poked this client with a
	// message.
	ClientPoke = "notifyclientpoke"
	// ClientServerQueryLoginPassword is notifyclientserverqueryloginpassword:
	// reply to clientsetserverquerylogin: the generated ServerQuery password.
	ClientServerQueryLoginPassword = "notifyclientserverqueryloginpassword"
	// ClientUIDFromCLID is notifyclientuidfromclid: reply to clientgetuidfromclid:
	// the unique id and nickname of the client with that client id.
	ClientUIDFromCLID = "notifyclientuidfromclid"
	// ClientUpdated is notifyclientupdated: a client in view changed some of its
	// properties, such as its nickname, mute state or away message.
	ClientUpdated = "notifyclientupdated"
	// ComplainList is notifycomplainlist: reply to complainlist: one row per
	// complaint.
	ComplainList = "notifycomplainlist"
	// ConnectionInfo is notifyconnectioninfo: a client's connection statistics,
	// sent in answer to a request for them (getconnectioninfo).
	ConnectionInfo = "notifyconnectioninfo"
	// ConnectionInfoRequest is notifyconnectioninforequest: the server asks this
	// client to report its own connection statistics with setconnectioninfo.
	ConnectionInfoRequest = "notifyconnectioninforequest"
	// FileInfo is notifyfileinfo: reply to ftgetfileinfo: one row per file, with
	// its size and modification time.
	FileInfo = "notifyfileinfo"
	// FileList is notifyfilelist: reply to ftgetfilelist: one row per file or
	// directory in a channel's file repository.
	FileList = "notifyfilelist"
	// FileListFinished is notifyfilelistfinished: the server has sent every
	// notifyfilelist row for a channel path.
	FileListFinished = "notifyfilelistfinished"
	// FileTransferList is notifyfiletransferlist: reply to ftlist: one row per
	// running file transfer.
	FileTransferList = "notifyfiletransferlist"
	// Message is notifymessage: reply to messageget: an offline message with its
	// subject and body.
	Message = "notifymessage"
	// MessageList is notifymessagelist: reply to messagelist: one row per offline
	// message in this client's inbox.
	MessageList = "notifymessagelist"
	// PermFind is notifypermfind: reply to permfind: one row per place a
	// permission is assigned.
	PermFind = "notifypermfind"
	// PermissionList is notifypermissionlist: reply to permissionlist: one row per
	// permission the server knows, with its id, name and description.
	PermissionList = "notifypermissionlist"
	// PermOverview is notifypermoverview: reply to permoverview: one row per
	// permission assignment that applies to a client in a channel.
	PermOverview = "notifypermoverview"
	// PluginCmd is notifyplugincmd: a plugin command another client sent with
	// plugincmd, to this client's channel or to it directly.
	PluginCmd = "notifyplugincmd"
	// ServerConnectionInfo is notifyserverconnectioninfo: reply to
	// serverrequestconnectioninfo: the virtual server's traffic and bandwidth
	// statistics.
	ServerConnectionInfo = "notifyserverconnectioninfo"
	// ServerEdited is notifyserveredited: the virtual server's settings were
	// edited, with who edited them and the settings that changed.
	ServerEdited = "notifyserveredited"
	// ServerGroupClientAdded is notifyservergroupclientadded: a client was added
	// to a server group, with who added it.
	ServerGroupClientAdded = "notifyservergroupclientadded"
	// ServerGroupClientDeleted is notifyservergroupclientdeleted: a client was
	// removed from a server group, with who removed it.
	ServerGroupClientDeleted = "notifyservergroupclientdeleted"
	// ServerGroupClientList is notifyservergroupclientlist: reply to
	// servergroupclientlist: one row per client in a server group.
	ServerGroupClientList = "notifyservergroupclientlist"
	// ServerGroupList is notifyservergrouplist: reply to servergrouplist, and sent
	// by the server on joining: one row per server group.
	ServerGroupList = "notifyservergrouplist"
	// ServerGroupPermList is notifyservergrouppermlist: reply to
	// servergrouppermlist: one row per permission set on a server group.
	ServerGroupPermList = "notifyservergrouppermlist"
	// ServerGroupsByClientID is notifyservergroupsbyclientid: reply to
	// servergroupsbyclientid: one row per server group a client belongs to.
	ServerGroupsByClientID = "notifyservergroupsbyclientid"
	// ServerLog is notifyserverlog: reply to logview: a chunk of the server log
	// with the position to read on from.
	ServerLog = "notifyserverlog"
	// ServerTempPasswordList is notifyservertemppasswordlist: reply to
	// servertemppasswordlist: one row per active temporary server password.
	ServerTempPasswordList = "notifyservertemppasswordlist"
	// ServerUpdated is notifyserverupdated: the virtual server's statistics and
	// settings, sent when they change or when this client asks for them.
	ServerUpdated = "notifyserverupdated"
	// StartDownload is notifystartdownload: reply to ftinitdownload: the key, port
	// and size to start a download on the file transfer port.
	StartDownload = "notifystartdownload"
	// StartUpload is notifystartupload: reply to ftinitupload: the key, port and
	// offset to start an upload on the file transfer port.
	StartUpload = "notifystartupload"
	// StatusFileTransfer is notifystatusfiletransfer: a file transfer ended or
	// failed: it carries the status code and message for the transfer's
	// client-side id.
	StatusFileTransfer = "notifystatusfiletransfer"
	// TextMessage is notifytextmessage: a text message arrived, to this client,
	// its channel or the whole server, with who sent it.
	TextMessage = "notifytextmessage"
	// TokenAdd is notifytokenadd: reply to privilegekeyadd: the new privilege key.
	TokenAdd = "notifytokenadd"
	// TokenList is notifytokenlist: reply to privilegekeylist: one row per
	// privilege key.
	TokenList = "notifytokenlist"
	// TokenUsed is notifytokenused: a privilege key was used, with who used it and
	// the groups it granted.
	TokenUsed = "notifytokenused"
)
