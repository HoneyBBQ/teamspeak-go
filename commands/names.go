package commands

// The command names, as a ServerQuery or voice protocol line starts with them,
// in the order the server's help lists them. Build a line for Exec from one:
// the name, then key=value parameters with the values escaped.
//
// A server may know commands this list does not.
const (
	// APIKeyAdd is apikeyadd: creates a new api key with the given scope for the
	// invoking user.
	APIKeyAdd = "apikeyadd"
	// APIKeyDel is apikeydel: deletes an apikey.
	APIKeyDel = "apikeydel"
	// APIKeyList is apikeylist: lists the api keys of the invoking user, or of all
	// users.
	APIKeyList = "apikeylist"
	// AuthenticationToken is authenticationtoken: returns a token other services
	// can use as proof that this server identifies you as a user. TeamSpeak 6
	// only.
	AuthenticationToken = "authenticationtoken"
	// BanAdd is banadd: adds a new ban rule on the selected virtual server.
	BanAdd = "banadd"
	// BanClient is banclient: bans one or more clients specified with the given
	// client ids from the server.
	BanClient = "banclient"
	// BanDel is bandel: deletes the ban rule with ID banid from the server.
	BanDel = "bandel"
	// BanDelAll is bandelall: deletes all active ban rules from the server.
	BanDelAll = "bandelall"
	// BanFind is banfind: displays a list of matching bans on the selected virtual
	// server. TeamSpeak 6 only.
	BanFind = "banfind"
	// BanList is banlist: displays a list of active bans on the selected virtual
	// server.
	BanList = "banlist"
	// BindingList is bindinglist: displays a list of IP addresses used by the
	// server instance on multi-homed machines.
	BindingList = "bindinglist"
	// ChannelAddPerm is channeladdperm: adds a set of specified permissions to a
	// channel.
	ChannelAddPerm = "channeladdperm"
	// ChannelClientAddPerm is channelclientaddperm: adds a set of specified
	// permissions to a client in a specific channel.
	ChannelClientAddPerm = "channelclientaddperm"
	// ChannelClientDelPerm is channelclientdelperm: removes a set of specified
	// permissions from a client in a specific channel.
	ChannelClientDelPerm = "channelclientdelperm"
	// ChannelClientPermList is channelclientpermlist: displays a list of
	// permissions defined for a client in a specific channel.
	ChannelClientPermList = "channelclientpermlist"
	// ChannelCreate is channelcreate: creates a new channel using the given
	// properties and displays its ID.
	ChannelCreate = "channelcreate"
	// ChannelDelete is channeldelete: deletes an existing channel by ID.
	ChannelDelete = "channeldelete"
	// ChannelDelPerm is channeldelperm: removes a set of specified permissions
	// from a channel.
	ChannelDelPerm = "channeldelperm"
	// ChannelEdit is channeledit: changes a channel's configuration using given
	// properties.
	ChannelEdit = "channeledit"
	// ChannelFind is channelfind: displays a list of channels matching a given
	// name pattern.
	ChannelFind = "channelfind"
	// ChannelGetDescription is channelgetdescription: asks the server for a
	// channel's description, which it is not sent with the channel list. Voice
	// protocol only.
	ChannelGetDescription = "channelgetdescription"
	// ChannelGroupAdd is channelgroupadd: creates a new channel group using a
	// given name and displays its ID.
	ChannelGroupAdd = "channelgroupadd"
	// ChannelGroupAddPerm is channelgroupaddperm: adds a set of specified
	// permissions to a channel group.
	ChannelGroupAddPerm = "channelgroupaddperm"
	// ChannelGroupClientList is channelgroupclientlist: displays all the client
	// and/or channel IDs currently assigned to channel groups.
	ChannelGroupClientList = "channelgroupclientlist"
	// ChannelGroupCopy is channelgroupcopy: creates a copy of a channel group, or
	// overwrites an existing group with it.
	ChannelGroupCopy = "channelgroupcopy"
	// ChannelGroupDel is channelgroupdel: deletes a channel group by ID.
	ChannelGroupDel = "channelgroupdel"
	// ChannelGroupDelPerm is channelgroupdelperm: removes a set of specified
	// permissions from the channel group.
	ChannelGroupDelPerm = "channelgroupdelperm"
	// ChannelGroupList is channelgrouplist: displays a list of channel groups
	// available on the selected virtual server.
	ChannelGroupList = "channelgrouplist"
	// ChannelGroupPermList is channelgrouppermlist: displays a list of permissions
	// assigned to the channel group specified with cgid.
	ChannelGroupPermList = "channelgrouppermlist"
	// ChannelGroupRename is channelgrouprename: changes the name of a specified
	// channel group.
	ChannelGroupRename = "channelgrouprename"
	// ChannelInfo is channelinfo: displays detailed configuration information
	// about a channel including ID, topic, description, etc.
	ChannelInfo = "channelinfo"
	// ChannelList is channellist: displays a list of channels created on a virtual
	// server including their ID, order, name, etc.
	ChannelList = "channellist"
	// ChannelMove is channelmove: moves a channel to a new parent channel with the
	// ID cpid.
	ChannelMove = "channelmove"
	// ChannelPermList is channelpermlist: displays a list of permissions defined
	// for a channel.
	ChannelPermList = "channelpermlist"
	// ChannelSubscribe is channelsubscribe: subscribes this client to a channel so
	// it sees the clients in it and their voice. Voice protocol only.
	ChannelSubscribe = "channelsubscribe"
	// ChannelSubscribeAll is channelsubscribeall: subscribes this client to every
	// channel on the server. Voice protocol only.
	ChannelSubscribeAll = "channelsubscribeall"
	// ChannelUnsubscribe is channelunsubscribe: unsubscribes this client from a
	// channel, so the clients in it go out of view. Voice protocol only.
	ChannelUnsubscribe = "channelunsubscribe"
	// ChannelUnsubscribeAll is channelunsubscribeall: unsubscribes this client
	// from every channel. Voice protocol only.
	ChannelUnsubscribeAll = "channelunsubscribeall"
	// ChatLoginToken is chatlogintoken: returns a JSON Web Token for logging in to
	// the Matrix server the server uses for chat. TeamSpeak 6 only.
	ChatLoginToken = "chatlogintoken"
	// ClientAddPerm is clientaddperm: adds a set of specified permissions to a
	// client.
	ClientAddPerm = "clientaddperm"
	// ClientAddServerGroup is clientaddservergroup: adds a client to one or more
	// server groups specified with sgid.
	ClientAddServerGroup = "clientaddservergroup"
	// ClientDBDelete is clientdbdelete: deletes a client's properties from the
	// database.
	ClientDBDelete = "clientdbdelete"
	// ClientDBEdit is clientdbedit: changes a client's settings using given
	// properties.
	ClientDBEdit = "clientdbedit"
	// ClientDBFind is clientdbfind: displays a list of client database IDs
	// matching a given pattern.
	ClientDBFind = "clientdbfind"
	// ClientDBInfo is clientdbinfo: displays detailed database information about a
	// client including unique ID, creation date, etc.
	ClientDBInfo = "clientdbinfo"
	// ClientDBList is clientdblist: displays a list of client identities known by
	// the server including their database ID, last nickname, etc.
	ClientDBList = "clientdblist"
	// ClientDelPerm is clientdelperm: removes a set of specified permissions from
	// a client.
	ClientDelPerm = "clientdelperm"
	// ClientDelServerGroup is clientdelservergroup: removes a client from one or
	// more server groups.
	ClientDelServerGroup = "clientdelservergroup"
	// ClientDisconnect is clientdisconnect: tells the server this client is
	// leaving, with an optional reason message. Voice protocol only.
	ClientDisconnect = "clientdisconnect"
	// ClientEdit is clientedit: changes a client's settings using given
	// properties.
	ClientEdit = "clientedit"
	// ClientFind is clientfind: displays a list of clients matching a given name
	// pattern.
	ClientFind = "clientfind"
	// ClientGetDBIDFromUID is clientgetdbidfromuid: displays the database ID
	// matching the unique identifier specified by cluid.
	ClientGetDBIDFromUID = "clientgetdbidfromuid"
	// ClientGetIDs is clientgetids: displays all client IDs matching the unique
	// identifier specified by cluid.
	ClientGetIDs = "clientgetids"
	// ClientGetNameFromDBID is clientgetnamefromdbid: displays the unique
	// identifier and nickname matching the database ID specified by cldbid.
	ClientGetNameFromDBID = "clientgetnamefromdbid"
	// ClientGetNameFromUID is clientgetnamefromuid: displays the database ID and
	// nickname matching the unique identifier specified by cluid.
	ClientGetNameFromUID = "clientgetnamefromuid"
	// ClientGetUIDFromCLID is clientgetuidfromclid: displays the unique identifier
	// matching the clientID specified by clid.
	ClientGetUIDFromCLID = "clientgetuidfromclid"
	// ClientInfo is clientinfo: displays detailed configuration information about
	// a client including unique ID, nickname, client version, etc.
	ClientInfo = "clientinfo"
	// ClientKick is clientkick: kicks one or more clients from their channel
	// (reasonid 4) or from the server (reasonid 5).
	ClientKick = "clientkick"
	// ClientList is clientlist: displays a list of clients online on a virtual
	// server including their ID, nickname, status flags, etc.
	ClientList = "clientlist"
	// ClientMove is clientmove: moves one or more clients to another channel.
	ClientMove = "clientmove"
	// ClientPermList is clientpermlist: displays a list of permissions defined for
	// a client.
	ClientPermList = "clientpermlist"
	// ClientPoke is clientpoke: sends a poke message to the client specified with
	// clid.
	ClientPoke = "clientpoke"
	// ClientSetServerQueryLogin is clientsetserverquerylogin: updates your own
	// ServerQuery login credentials using a specified username.
	ClientSetServerQueryLogin = "clientsetserverquerylogin"
	// ClientUpdate is clientupdate: changes your ServerQuery clients settings
	// using given properties.
	ClientUpdate = "clientupdate"
	// ComplainAdd is complainadd: submits a complaint about a connected client
	// with database ID tcldbid to the server.
	ComplainAdd = "complainadd"
	// ComplainDel is complaindel: deletes the complaint about the client with ID
	// tcldbid submitted by the client with ID fcldbid from the server.
	ComplainDel = "complaindel"
	// ComplainDelAll is complaindelall: deletes all complaints about the client
	// with database ID tcldbid from the server.
	ComplainDelAll = "complaindelall"
	// ComplainList is complainlist: displays a list of complaints on the selected
	// virtual server.
	ComplainList = "complainlist"
	// CustomDelete is customdelete: removes a custom property from a client
	// specified by the cldbid.
	CustomDelete = "customdelete"
	// CustomInfo is custominfo: displays a list of custom properties for the
	// client specified with cldbid.
	CustomInfo = "custominfo"
	// CustomSearch is customsearch: searches for custom client properties
	// specified by ident and value.
	CustomSearch = "customsearch"
	// CustomSet is customset: creates or updates a custom property for client
	// specified by the cldbid.
	CustomSet = "customset"
	// FTCreateDir is ftcreatedir: creates new directory in a channel's file
	// repository.
	FTCreateDir = "ftcreatedir"
	// FTDeleteFile is ftdeletefile: deletes one or more files stored in a
	// channel's file repository.
	FTDeleteFile = "ftdeletefile"
	// FTGetChannelFileHTTPToken is ftgetchannelfilehttptoken: returns a JSON Web
	// Token for authenticating to a HTTP file transfer server. TeamSpeak 6 only.
	FTGetChannelFileHTTPToken = "ftgetchannelfilehttptoken"
	// FTGetFileInfo is ftgetfileinfo: displays detailed information about one or
	// more specified files stored in a channel's file repository.
	FTGetFileInfo = "ftgetfileinfo"
	// FTGetFileList is ftgetfilelist: displays a list of files and directories
	// stored in the specified channels file repository.
	FTGetFileList = "ftgetfilelist"
	// FTInitDownload is ftinitdownload: initializes a file transfer download.
	FTInitDownload = "ftinitdownload"
	// FTInitUpload is ftinitupload: initializes a file transfer upload.
	FTInitUpload = "ftinitupload"
	// FTList is ftlist: displays a list of running file transfers on the selected
	// virtual server.
	FTList = "ftlist"
	// FTRenameFile is ftrenamefile: renames a file in a channel's file repository.
	FTRenameFile = "ftrenamefile"
	// FTStop is ftstop: stops the running file transfer with server-side ID
	// serverftfid.
	FTStop = "ftstop"
	// GM is gm: sends a text message to all clients on all virtual servers in the
	// server instance.
	GM = "gm"
	// Help is help: lists all commands, or shows the usage, permissions and
	// parameters of one command.
	Help = "help"
	// HomeBaseDel is homebasedel: unsets this server as the matrix homebase server
	// for the calling client, or the client specified with cldbid if given.
	// TeamSpeak 6 only.
	HomeBaseDel = "homebasedel"
	// HomeBaseIsSet is homebaseisset: checks if this server is set as the matrix
	// homebase server for the calling client, or the client specified with cldbid
	// if given. TeamSpeak 6 only.
	HomeBaseIsSet = "homebaseisset"
	// HomeBaseList is homebaselist: lists all users that have set this server as
	// their matrix homebase. TeamSpeak 6 only.
	HomeBaseList = "homebaselist"
	// HomeBaseSet is homebaseset: sets this server as the matrix homebase server
	// for the calling client, or the client specified with cldbid if given.
	// TeamSpeak 6 only.
	HomeBaseSet = "homebaseset"
	// HostInfo is hostinfo: displays detailed connection information about the
	// server instance including uptime, number of virtual servers online, traffic
	// information, etc.
	HostInfo = "hostinfo"
	// InstanceEdit is instanceedit: changes the server instance configuration
	// using given properties.
	InstanceEdit = "instanceedit"
	// InstanceInfo is instanceinfo: displays the server instance configuration
	// including database revision number, the file transfer port, default group
	// IDs, etc.
	InstanceInfo = "instanceinfo"
	// LicenseSignMessage is licensesignmessage: signs the message with the private
	// key of your license. TeamSpeak 6 only.
	LicenseSignMessage = "licensesignmessage"
	// LogAdd is logadd: writes a custom entry into the server's log.
	LogAdd = "logadd"
	// Login is login: authenticates with the server instance using given
	// ServerQuery login credentials.
	Login = "login"
	// Logout is logout: deselects the active virtual server and logs out from the
	// server instance.
	Logout = "logout"
	// LogView is logview: displays a specified number of entries from the server's
	// log.
	LogView = "logview"
	// MessageAdd is messageadd: sends an offline message to the client specified
	// by cluid.
	MessageAdd = "messageadd"
	// MessageDel is messagedel: deletes an existing offline message with ID msgid
	// from your inbox.
	MessageDel = "messagedel"
	// MessageGet is messageget: displays an existing offline message with ID msgid
	// from your inbox.
	MessageGet = "messageget"
	// MessageList is messagelist: displays a list of offline messages you've
	// received.
	MessageList = "messagelist"
	// MessageUpdateFlag is messageupdateflag: updates the flag_read property of
	// the offline message specified with msgid.
	MessageUpdateFlag = "messageupdateflag"
	// PermFind is permfind: displays detailed information about all assignments of
	// the permission specified with permid.
	PermFind = "permfind"
	// PermGet is permget: displays the current value of the permission specified
	// with permid or permsid for your own connection.
	PermGet = "permget"
	// PermIDGetByName is permidgetbyname: displays the database ID of one or more
	// permissions specified by permsid.
	PermIDGetByName = "permidgetbyname"
	// PermissionList is permissionlist: displays a list of permissions available
	// on the server instance including ID, name and description.
	PermissionList = "permissionlist"
	// PermOverview is permoverview: displays all permissions assigned to a client
	// for the channel specified with cid.
	PermOverview = "permoverview"
	// PermReset is permreset: restores the default permission settings on the
	// selected virtual server and creates a new initial administrator token.
	PermReset = "permreset"
	// PrivilegeKeyAdd is privilegekeyadd: creates a new privilege key, a token
	// that grants a server or channel group.
	PrivilegeKeyAdd = "privilegekeyadd"
	// PrivilegeKeyDelete is privilegekeydelete: deletes an existing token matching
	// the token key specified with token.
	PrivilegeKeyDelete = "privilegekeydelete"
	// PrivilegeKeyList is privilegekeylist: displays a list of privilege keys
	// available including their type and group IDs.
	PrivilegeKeyList = "privilegekeylist"
	// PrivilegeKeyUse is privilegekeyuse: uses a privilege key to gain access to a
	// server or channel group.
	PrivilegeKeyUse = "privilegekeyuse"
	// QueryLoginAdd is queryloginadd: adds a new query client login, or enables
	// query login for existing clients.
	QueryLoginAdd = "queryloginadd"
	// QueryLoginDel is querylogindel: deletes an existing server query login on
	// selected server.
	QueryLoginDel = "querylogindel"
	// QueryLoginList is queryloginlist: lists existing query client logins.
	QueryLoginList = "queryloginlist"
	// Quit is quit: closes the ServerQuery connection to the server instance.
	Quit = "quit"
	// SendTextMessage is sendtextmessage: sends a text message to a specified
	// target.
	SendTextMessage = "sendtextmessage"
	// ServerCreate is servercreate: creates a new virtual server using the given
	// properties and displays its ID, port and initial administrator privilege
	// key.
	ServerCreate = "servercreate"
	// ServerDelete is serverdelete: deletes the virtual server specified with sid.
	ServerDelete = "serverdelete"
	// ServerEdit is serveredit: changes the selected virtual server's
	// configuration using given properties.
	ServerEdit = "serveredit"
	// ServerGroupAdd is servergroupadd: creates a new server group using the name
	// specified with name and displays its ID.
	ServerGroupAdd = "servergroupadd"
	// ServerGroupAddClient is servergroupaddclient: adds one or more clients to
	// the server group specified with sgid.
	ServerGroupAddClient = "servergroupaddclient"
	// ServerGroupAddPerm is servergroupaddperm: adds a set of specified
	// permissions to the server group specified with sgid.
	ServerGroupAddPerm = "servergroupaddperm"
	// ServerGroupAutoAddPerm is servergroupautoaddperm: adds a set of specified
	// permissions to all regular server groups on all virtual servers.
	ServerGroupAutoAddPerm = "servergroupautoaddperm"
	// ServerGroupAutoDelPerm is servergroupautodelperm: removes a set of specified
	// permissions from all regular server groups on all virtual servers.
	ServerGroupAutoDelPerm = "servergroupautodelperm"
	// ServerGroupClientList is servergroupclientlist: displays the IDs of all
	// clients currently residing in the server group specified with sgid.
	ServerGroupClientList = "servergroupclientlist"
	// ServerGroupCopy is servergroupcopy: creates a copy of a server group, or
	// overwrites an existing group with it.
	ServerGroupCopy = "servergroupcopy"
	// ServerGroupDel is servergroupdel: deletes the server group specified with
	// sgid.
	ServerGroupDel = "servergroupdel"
	// ServerGroupDelClient is servergroupdelclient: removes one or more clients
	// specified with cldbid from the server group specified with sgid.
	ServerGroupDelClient = "servergroupdelclient"
	// ServerGroupDelPerm is servergroupdelperm: removes a set of specified
	// permissions from the server group specified with sgid.
	ServerGroupDelPerm = "servergroupdelperm"
	// ServerGroupList is servergrouplist: displays a list of server groups
	// available.
	ServerGroupList = "servergrouplist"
	// ServerGroupPermList is servergrouppermlist: displays a list of permissions
	// assigned to the server group specified with sgid.
	ServerGroupPermList = "servergrouppermlist"
	// ServerGroupRename is servergrouprename: changes the name of the server group
	// specified with sgid.
	ServerGroupRename = "servergrouprename"
	// ServerGroupsByClientID is servergroupsbyclientid: displays all server groups
	// the client specified with cldbid is currently residing in.
	ServerGroupsByClientID = "servergroupsbyclientid"
	// ServerIDGetByPort is serveridgetbyport: displays the database ID of the
	// virtual server running on the UDP port specified by virtualserver_port.
	ServerIDGetByPort = "serveridgetbyport"
	// ServerInfo is serverinfo: displays detailed configuration information about
	// the selected virtual server including unique ID, number of clients online,
	// configuration, etc.
	ServerInfo = "serverinfo"
	// ServerList is serverlist: displays a list of virtual servers including their
	// ID, status, number of clients online, etc.
	ServerList = "serverlist"
	// ServerNotifyRegister is servernotifyregister: registers for a specified
	// category of events on a virtual server to receive notification messages.
	ServerNotifyRegister = "servernotifyregister"
	// ServerNotifyUnregister is servernotifyunregister: unregisters from one
	// category of events, or from all of them when no event is given.
	ServerNotifyUnregister = "servernotifyunregister"
	// ServerProcessStop is serverprocessstop: stops the entire server instance by
	// shutting down the process.
	ServerProcessStop = "serverprocessstop"
	// ServerRequestConnectionInfo is serverrequestconnectioninfo: displays
	// detailed connection information about the selected virtual server including
	// uptime, traffic information, etc.
	ServerRequestConnectionInfo = "serverrequestconnectioninfo"
	// ServerSnapshotCreate is serversnapshotcreate: displays a snapshot of the
	// selected virtual server containing all settings, groups and known client
	// identities.
	ServerSnapshotCreate = "serversnapshotcreate"
	// ServerSnapshotDeploy is serversnapshotdeploy: restores the selected virtual
	// server's configuration using the data from a previously created server
	// snapshot.
	ServerSnapshotDeploy = "serversnapshotdeploy"
	// ServerStart is serverstart: starts the virtual server specified with sid.
	ServerStart = "serverstart"
	// ServerStop is serverstop: stops the virtual server specified with sid.
	ServerStop = "serverstop"
	// ServerTempPasswordAdd is servertemppasswordadd: sets a new temporary server
	// password specified with pw.
	ServerTempPasswordAdd = "servertemppasswordadd"
	// ServerTempPasswordDel is servertemppassworddel: deletes the temporary server
	// password specified with pw.
	ServerTempPasswordDel = "servertemppassworddel"
	// ServerTempPasswordList is servertemppasswordlist: returns a list of active
	// temporary server passwords.
	ServerTempPasswordList = "servertemppasswordlist"
	// SetClientChannelGroup is setclientchannelgroup: sets the channel group of a
	// client to the ID specified with cgid.
	SetClientChannelGroup = "setclientchannelgroup"
	// TokenAdd is tokenadd: alias for privilegekeyadd.
	TokenAdd = "tokenadd"
	// TokenDelete is tokendelete: alias for privilegekeydelete.
	TokenDelete = "tokendelete"
	// TokenList is tokenlist: alias for privilegekeylist.
	TokenList = "tokenlist"
	// TokenUse is tokenuse: alias for privilegekeyuse.
	TokenUse = "tokenuse"
	// Use is use: selects the virtual server specified with sid or port to allow
	// further interaction.
	Use = "use"
	// Version is version: displays the server's version information including
	// platform and build number.
	Version = "version"
	// WhoAmI is whoami: displays information about your current ServerQuery
	// connection including your loginname, etc.
	WhoAmI = "whoami"
)
