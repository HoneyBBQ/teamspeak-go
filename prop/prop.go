// Package prop names the property keys of the teamspeak.Properties maps that
// GetServerInfo, GetInstanceInfo, GetHostInfo and GetClientInfo return and
// EditServer and EditInstance take:
//
//	info, err := c.GetServerInfo(ctx)
//	name := info[prop.VirtualServerName]
//
// The constants are the keys TeamSpeak 3.13 and 6 servers send, measured with
// serverinfo, instanceinfo, hostinfo and clientinfo; those marked TeamSpeak 6
// only or TeamSpeak 3 only are missing on the other. A server may send keys
// this package does not name, and which ones appear depends on the caller's
// permissions.
package prop

// Virtual server properties, as serverinfo returns them; those marked editable
// are accepted by EditServer (serveredit).
const (
	// VirtualServerUniqueIdentifier is virtualserver_unique_identifier: the
	// server's unique id, a base64 string that stays the same when the server
	// moves.
	VirtualServerUniqueIdentifier = "virtualserver_unique_identifier"
	// VirtualServerName is virtualserver_name: the name of the virtual server.
	// Editable.
	VirtualServerName = "virtualserver_name"
	// VirtualServerWelcomeMessage is virtualserver_welcomemessage: the welcome
	// message of the server. Editable.
	VirtualServerWelcomeMessage = "virtualserver_welcomemessage"
	// VirtualServerPlatform is virtualserver_platform: operating system the server
	// runs on, such as Linux.
	VirtualServerPlatform = "virtualserver_platform"
	// VirtualServerVersion is virtualserver_version: server version and build, for
	// example 3.13.8 [Build: 1779874471].
	VirtualServerVersion = "virtualserver_version"
	// VirtualServerMaxClients is virtualserver_maxclients: the maximum number of
	// clients to allow. Editable.
	VirtualServerMaxClients = "virtualserver_maxclients"
	// VirtualServerPassword is virtualserver_password: the password required to
	// enter. Editable.
	VirtualServerPassword = "virtualserver_password"
	// VirtualServerClientsOnline is virtualserver_clientsonline: number of clients
	// online, voice and ServerQuery clients together.
	VirtualServerClientsOnline = "virtualserver_clientsonline"
	// VirtualServerChannelsOnline is virtualserver_channelsonline: number of
	// channels on the server.
	VirtualServerChannelsOnline = "virtualserver_channelsonline"
	// VirtualServerCreated is virtualserver_created: when the virtual server was
	// created, as a Unix timestamp in seconds.
	VirtualServerCreated = "virtualserver_created"
	// VirtualServerUptime is virtualserver_uptime: seconds since the virtual
	// server started.
	VirtualServerUptime = "virtualserver_uptime"
	// VirtualServerCodecEncryptionMode is virtualserver_codec_encryption_mode: the
	// global codec encryption mode of the virtual server. Editable.
	VirtualServerCodecEncryptionMode = "virtualserver_codec_encryption_mode"
	// VirtualServerHostMessage is virtualserver_hostmessage: the host message of
	// the server. Editable.
	VirtualServerHostMessage = "virtualserver_hostmessage"
	// VirtualServerHostMessageMode is virtualserver_hostmessage_mode: the host
	// message mode of the server (0 for None, 1 for message in chatlog, 2 for
	// message as a modal, 3 for modal dialog and then quit). Editable.
	VirtualServerHostMessageMode = "virtualserver_hostmessage_mode"
	// VirtualServerFileBase is virtualserver_filebase: path of the server's file
	// storage, relative to the server's working directory.
	VirtualServerFileBase = "virtualserver_filebase"
	// VirtualServerDefaultServerGroup is virtualserver_default_server_group: the
	// default server group to use. Editable.
	VirtualServerDefaultServerGroup = "virtualserver_default_server_group"
	// VirtualServerDefaultChannelGroup is virtualserver_default_channel_group: the
	// default channel group to use. Editable.
	VirtualServerDefaultChannelGroup = "virtualserver_default_channel_group"
	// VirtualServerFlagPassword is virtualserver_flag_password: 1 if the server
	// has a password, 0 if it does not.
	VirtualServerFlagPassword = "virtualserver_flag_password"
	// VirtualServerDefaultChannelAdminGroup is
	// virtualserver_default_channel_admin_group: the default channel administrator
	// group to use. Editable.
	VirtualServerDefaultChannelAdminGroup = "virtualserver_default_channel_admin_group"
	// VirtualServerMaxDownloadTotalBandwidth is
	// virtualserver_max_download_total_bandwidth: the max bandwidth for outgoing
	// file transfers on the virtual server (Bytes/s). Editable.
	VirtualServerMaxDownloadTotalBandwidth = "virtualserver_max_download_total_bandwidth"
	// VirtualServerMaxUploadTotalBandwidth is
	// virtualserver_max_upload_total_bandwidth: the max bandwidth for incoming
	// file transfers on the virtual server (Bytes/s). Editable.
	VirtualServerMaxUploadTotalBandwidth = "virtualserver_max_upload_total_bandwidth"
	// VirtualServerHostBannerURL is virtualserver_hostbanner_url: URL for the host
	// banner. Editable.
	VirtualServerHostBannerURL = "virtualserver_hostbanner_url"
	// VirtualServerHostBannerGFXURL is virtualserver_hostbanner_gfx_url: URL for
	// the host banner image. Editable.
	VirtualServerHostBannerGFXURL = "virtualserver_hostbanner_gfx_url"
	// VirtualServerHostBannerGFXInterval is virtualserver_hostbanner_gfx_interval:
	// refresh time for the host banner image on the client side (in seconds).
	// Editable.
	VirtualServerHostBannerGFXInterval = "virtualserver_hostbanner_gfx_interval"
	// VirtualServerComplainAutoBanCount is virtualserver_complain_autoban_count:
	// the number of complaints about a client we will tolerate before a ban.
	// Editable.
	VirtualServerComplainAutoBanCount = "virtualserver_complain_autoban_count"
	// VirtualServerComplainAutoBanTime is virtualserver_complain_autoban_time: the
	// amount of time (in seconds) an autobanned client will be banned for.
	// Editable.
	VirtualServerComplainAutoBanTime = "virtualserver_complain_autoban_time"
	// VirtualServerComplainRemoveTime is virtualserver_complain_remove_time: the
	// amount of time (in seconds) before a complaint is deleted automatically.
	// Editable.
	VirtualServerComplainRemoveTime = "virtualserver_complain_remove_time"
	// VirtualServerMinClientsInChannelBeforeForcedSilence is
	// virtualserver_min_clients_in_channel_before_forced_silence: number of
	// clients in the same channel needed to force silence. Editable.
	VirtualServerMinClientsInChannelBeforeForcedSilence = "virtualserver_min_clients_in_channel_before_forced_silence"
	// VirtualServerPrioritySpeakerDimmModificator is
	// virtualserver_priority_speaker_dimm_modificator: client volume lowered
	// automatically while a priority speaker is talking. Editable.
	VirtualServerPrioritySpeakerDimmModificator = "virtualserver_priority_speaker_dimm_modificator"
	// VirtualServerID is virtualserver_id: the virtual server's id, as used by use
	// sid=.
	VirtualServerID = "virtualserver_id"
	// VirtualServerAntiFloodPointsTickReduce is
	// virtualserver_antiflood_points_tick_reduce: anti-flood points removed from a
	// client for being good. Editable.
	VirtualServerAntiFloodPointsTickReduce = "virtualserver_antiflood_points_tick_reduce"
	// VirtualServerAntiFloodPointsNeededCommandBlock is
	// virtualserver_antiflood_points_needed_command_block: anti-flood points
	// needed to block commands being executed by the client. Editable.
	VirtualServerAntiFloodPointsNeededCommandBlock = "virtualserver_antiflood_points_needed_command_block"
	// VirtualServerAntiFloodPointsNeededIPBlock is
	// virtualserver_antiflood_points_needed_ip_block: anti-flood points needed to
	// block incoming connections from the client. Editable.
	VirtualServerAntiFloodPointsNeededIPBlock = "virtualserver_antiflood_points_needed_ip_block"
	// VirtualServerClientConnections is virtualserver_client_connections: number
	// of voice client connections made since the server started.
	VirtualServerClientConnections = "virtualserver_client_connections"
	// VirtualServerQueryClientConnections is
	// virtualserver_query_client_connections: number of ServerQuery connections
	// made since the server started.
	VirtualServerQueryClientConnections = "virtualserver_query_client_connections"
	// VirtualServerHostButtonTooltip is virtualserver_hostbutton_tooltip: text
	// used for the tooltip of the host button on client-side. Editable.
	VirtualServerHostButtonTooltip = "virtualserver_hostbutton_tooltip"
	// VirtualServerHostButtonURL is virtualserver_hostbutton_url: URL opened on
	// click on the host button. Editable.
	VirtualServerHostButtonURL = "virtualserver_hostbutton_url"
	// VirtualServerHostButtonGFXURL is virtualserver_hostbutton_gfx_url: URL for
	// the host button on client-side. Editable.
	VirtualServerHostButtonGFXURL = "virtualserver_hostbutton_gfx_url"
	// VirtualServerQueryClientsOnline is virtualserver_queryclientsonline: number
	// of ServerQuery clients online.
	VirtualServerQueryClientsOnline = "virtualserver_queryclientsonline"
	// VirtualServerDownloadQuota is virtualserver_download_quota: download quota
	// for the virtual server (MByte). Editable.
	VirtualServerDownloadQuota = "virtualserver_download_quota"
	// VirtualServerUploadQuota is virtualserver_upload_quota: upload quota for the
	// virtual server (MByte). Editable.
	VirtualServerUploadQuota = "virtualserver_upload_quota"
	// VirtualServerMonthBytesDownloaded is virtualserver_month_bytes_downloaded:
	// bytes of file transfer downloads this month.
	VirtualServerMonthBytesDownloaded = "virtualserver_month_bytes_downloaded"
	// VirtualServerMonthBytesUploaded is virtualserver_month_bytes_uploaded: bytes
	// of file transfer uploads this month.
	VirtualServerMonthBytesUploaded = "virtualserver_month_bytes_uploaded"
	// VirtualServerTotalBytesDownloaded is virtualserver_total_bytes_downloaded:
	// bytes of file transfer downloads in total.
	VirtualServerTotalBytesDownloaded = "virtualserver_total_bytes_downloaded"
	// VirtualServerTotalBytesUploaded is virtualserver_total_bytes_uploaded: bytes
	// of file transfer uploads in total.
	VirtualServerTotalBytesUploaded = "virtualserver_total_bytes_uploaded"
	// VirtualServerPort is virtualserver_port: UDP port the virtual server is
	// listening on. Editable.
	VirtualServerPort = "virtualserver_port"
	// VirtualServerAutoStart is virtualserver_autostart: 1 if started
	// automatically with the instance, or 0 otherwise. Editable.
	VirtualServerAutoStart = "virtualserver_autostart"
	// VirtualServerMachineID is virtualserver_machine_id: machine id that tells
	// servers on one machine apart when they share a database; empty if unset.
	VirtualServerMachineID = "virtualserver_machine_id"
	// VirtualServerNeededIdentitySecurityLevel is
	// virtualserver_needed_identity_security_level: minimum client identity
	// security level required to connect to the virtual server. Editable.
	VirtualServerNeededIdentitySecurityLevel = "virtualserver_needed_identity_security_level"
	// VirtualServerLogClient is virtualserver_log_client: indicates whether the
	// server logs events related to clients or not. Editable.
	VirtualServerLogClient = "virtualserver_log_client"
	// VirtualServerLogQuery is virtualserver_log_query: indicates whether the
	// server logs events related to ServerQuery clients or not. Editable.
	VirtualServerLogQuery = "virtualserver_log_query"
	// VirtualServerLogChannel is virtualserver_log_channel: indicates whether the
	// server logs events related to channels or not. Editable.
	VirtualServerLogChannel = "virtualserver_log_channel"
	// VirtualServerLogPermissions is virtualserver_log_permissions: indicates
	// whether the server logs events related to permissions or not. Editable.
	VirtualServerLogPermissions = "virtualserver_log_permissions"
	// VirtualServerLogServer is virtualserver_log_server: indicates whether the
	// server logs events related to server changes or not. Editable.
	VirtualServerLogServer = "virtualserver_log_server"
	// VirtualServerLogFileTransfer is virtualserver_log_filetransfer: indicates
	// whether the server logs events related to file transfers or not. Editable.
	VirtualServerLogFileTransfer = "virtualserver_log_filetransfer"
	// VirtualServerMinClientVersion is virtualserver_min_client_version: minimal
	// desktop client version required to connect (a build number). Editable.
	VirtualServerMinClientVersion = "virtualserver_min_client_version"
	// VirtualServerNamePhonetic is virtualserver_name_phonetic: phonetic name of
	// the virtual server. Editable.
	VirtualServerNamePhonetic = "virtualserver_name_phonetic"
	// VirtualServerIconID is virtualserver_icon_id: CRC32 checksum of the virtual
	// server icon. Editable.
	VirtualServerIconID = "virtualserver_icon_id"
	// VirtualServerReservedSlots is virtualserver_reserved_slots: number of
	// reserved slots available on the virtual server. Editable.
	VirtualServerReservedSlots = "virtualserver_reserved_slots"
	// VirtualServerTotalPacketLossSpeech is virtualserver_total_packetloss_speech:
	// average packet loss of voice packets, as a fraction between 0 and 1.
	VirtualServerTotalPacketLossSpeech = "virtualserver_total_packetloss_speech"
	// VirtualServerTotalPacketLossKeepAlive is
	// virtualserver_total_packetloss_keepalive: average packet loss of keepalive
	// packets, as a fraction between 0 and 1.
	VirtualServerTotalPacketLossKeepAlive = "virtualserver_total_packetloss_keepalive"
	// VirtualServerTotalPacketLossControl is
	// virtualserver_total_packetloss_control: average packet loss of control
	// packets, as a fraction between 0 and 1.
	VirtualServerTotalPacketLossControl = "virtualserver_total_packetloss_control"
	// VirtualServerTotalPacketLossTotal is virtualserver_total_packetloss_total:
	// average packet loss over all packets, as a fraction between 0 and 1.
	VirtualServerTotalPacketLossTotal = "virtualserver_total_packetloss_total"
	// VirtualServerTotalPing is virtualserver_total_ping: average ping of all
	// clients, in milliseconds.
	VirtualServerTotalPing = "virtualserver_total_ping"
	// VirtualServerIP is virtualserver_ip: IP addresses the virtual server listens
	// on, separated by commas.
	VirtualServerIP = "virtualserver_ip"
	// VirtualServerWebListEnabled is virtualserver_weblist_enabled: indicates
	// whether the server appears in the global web server list or not. Editable.
	VirtualServerWebListEnabled = "virtualserver_weblist_enabled"
	// VirtualServerAskForPrivilegeKey is virtualserver_ask_for_privilegekey: 1 if
	// clients are asked for a privilege key on their first connection to an
	// unclaimed server, 0 if not.
	VirtualServerAskForPrivilegeKey = "virtualserver_ask_for_privilegekey"
	// VirtualServerHostBannerMode is virtualserver_hostbanner_mode: the display
	// mode for the virtual servers hostbanner. Editable.
	VirtualServerHostBannerMode = "virtualserver_hostbanner_mode"
	// VirtualServerChannelTempDeleteDelayDefault is
	// virtualserver_channel_temp_delete_delay_default: default delay, in seconds,
	// before an empty temporary channel is deleted.
	VirtualServerChannelTempDeleteDelayDefault = "virtualserver_channel_temp_delete_delay_default"
	// VirtualServerMinAndroidVersion is virtualserver_min_android_version: minimal
	// Android client version required to connect. Editable.
	VirtualServerMinAndroidVersion = "virtualserver_min_android_version"
	// VirtualServerMinIOSVersion is virtualserver_min_ios_version: minimal iOS
	// client version required to connect. Editable.
	VirtualServerMinIOSVersion = "virtualserver_min_ios_version"
	// VirtualServerNickname is virtualserver_nickname: nickname the server uses
	// when it speaks, for example in server messages; empty uses the default.
	VirtualServerNickname = "virtualserver_nickname"
	// VirtualServerAntiFloodPointsNeededPluginBlock is
	// virtualserver_antiflood_points_needed_plugin_block: anti-flood points needed
	// to block plugin commands from the client; if set to 0, the same as
	// virtualserver_antiflood_points_needed_command_block is used. Editable.
	VirtualServerAntiFloodPointsNeededPluginBlock = "virtualserver_antiflood_points_needed_plugin_block"
	// VirtualServerCapabilityExtensions is virtualserver_capability_extensions:
	// optional protocol features the server supports, separated by commas.
	VirtualServerCapabilityExtensions = "virtualserver_capability_extensions"
	// VirtualServerFileStorageClass is virtualserver_file_storage_class: storage
	// backend of the server's files; empty for the local disk. TeamSpeak 3 only.
	VirtualServerFileStorageClass = "virtualserver_file_storage_class"
	// VirtualServerStatus is virtualserver_status: status of the virtual server
	// (online | virtual online | offline | booting up | shutting down). Editable.
	VirtualServerStatus = "virtualserver_status"
	// ConnectionFileTransferBandwidthSent is
	// connection_filetransfer_bandwidth_sent: current file transfer upload speed,
	// in bytes per second. Also in hostinfo and clientinfo.
	ConnectionFileTransferBandwidthSent = "connection_filetransfer_bandwidth_sent"
	// ConnectionFileTransferBandwidthReceived is
	// connection_filetransfer_bandwidth_received: current file transfer download
	// speed, in bytes per second. Also in hostinfo and clientinfo.
	ConnectionFileTransferBandwidthReceived = "connection_filetransfer_bandwidth_received"
	// ConnectionFileTransferBytesSentTotal is
	// connection_filetransfer_bytes_sent_total: total bytes sent by file transfers
	// since the server started. Also in hostinfo.
	ConnectionFileTransferBytesSentTotal = "connection_filetransfer_bytes_sent_total"
	// ConnectionFileTransferBytesReceivedTotal is
	// connection_filetransfer_bytes_received_total: total bytes received by file
	// transfers since the server started. Also in hostinfo.
	ConnectionFileTransferBytesReceivedTotal = "connection_filetransfer_bytes_received_total"
	// ConnectionPacketsSentSpeech is connection_packets_sent_speech: voice packets
	// sent since the server started.
	ConnectionPacketsSentSpeech = "connection_packets_sent_speech"
	// ConnectionBytesSentSpeech is connection_bytes_sent_speech: bytes of voice
	// packets sent since the server started.
	ConnectionBytesSentSpeech = "connection_bytes_sent_speech"
	// ConnectionPacketsReceivedSpeech is connection_packets_received_speech: voice
	// packets received since the server started.
	ConnectionPacketsReceivedSpeech = "connection_packets_received_speech"
	// ConnectionBytesReceivedSpeech is connection_bytes_received_speech: bytes of
	// voice packets received since the server started.
	ConnectionBytesReceivedSpeech = "connection_bytes_received_speech"
	// ConnectionPacketsSentKeepAlive is connection_packets_sent_keepalive:
	// keepalive packets sent since the server started.
	ConnectionPacketsSentKeepAlive = "connection_packets_sent_keepalive"
	// ConnectionBytesSentKeepAlive is connection_bytes_sent_keepalive: bytes of
	// keepalive packets sent since the server started.
	ConnectionBytesSentKeepAlive = "connection_bytes_sent_keepalive"
	// ConnectionPacketsReceivedKeepAlive is connection_packets_received_keepalive:
	// keepalive packets received since the server started.
	ConnectionPacketsReceivedKeepAlive = "connection_packets_received_keepalive"
	// ConnectionBytesReceivedKeepAlive is connection_bytes_received_keepalive:
	// bytes of keepalive packets received since the server started.
	ConnectionBytesReceivedKeepAlive = "connection_bytes_received_keepalive"
	// ConnectionPacketsSentControl is connection_packets_sent_control: control
	// (command) packets sent since the server started.
	ConnectionPacketsSentControl = "connection_packets_sent_control"
	// ConnectionBytesSentControl is connection_bytes_sent_control: bytes of
	// control packets sent since the server started.
	ConnectionBytesSentControl = "connection_bytes_sent_control"
	// ConnectionPacketsReceivedControl is connection_packets_received_control:
	// control packets received since the server started.
	ConnectionPacketsReceivedControl = "connection_packets_received_control"
	// ConnectionBytesReceivedControl is connection_bytes_received_control: bytes
	// of control packets received since the server started.
	ConnectionBytesReceivedControl = "connection_bytes_received_control"
	// ConnectionPacketsSentTotal is connection_packets_sent_total: all packets
	// sent since the server started. Also in hostinfo and clientinfo.
	ConnectionPacketsSentTotal = "connection_packets_sent_total"
	// ConnectionBytesSentTotal is connection_bytes_sent_total: all bytes sent
	// since the server started. Also in hostinfo and clientinfo.
	ConnectionBytesSentTotal = "connection_bytes_sent_total"
	// ConnectionPacketsReceivedTotal is connection_packets_received_total: all
	// packets received since the server started. Also in hostinfo and clientinfo.
	ConnectionPacketsReceivedTotal = "connection_packets_received_total"
	// ConnectionBytesReceivedTotal is connection_bytes_received_total: all bytes
	// received since the server started. Also in hostinfo and clientinfo.
	ConnectionBytesReceivedTotal = "connection_bytes_received_total"
	// ConnectionBandwidthSentLastSecondTotal is
	// connection_bandwidth_sent_last_second_total: bytes per second sent, averaged
	// over the last second. Also in hostinfo and clientinfo.
	ConnectionBandwidthSentLastSecondTotal = "connection_bandwidth_sent_last_second_total"
	// ConnectionBandwidthSentLastMinuteTotal is
	// connection_bandwidth_sent_last_minute_total: bytes per second sent, averaged
	// over the last minute. Also in hostinfo and clientinfo.
	ConnectionBandwidthSentLastMinuteTotal = "connection_bandwidth_sent_last_minute_total"
	// ConnectionBandwidthReceivedLastSecondTotal is
	// connection_bandwidth_received_last_second_total: bytes per second received,
	// averaged over the last second. Also in hostinfo and clientinfo.
	ConnectionBandwidthReceivedLastSecondTotal = "connection_bandwidth_received_last_second_total"
	// ConnectionBandwidthReceivedLastMinuteTotal is
	// connection_bandwidth_received_last_minute_total: bytes per second received,
	// averaged over the last minute. Also in hostinfo and clientinfo.
	ConnectionBandwidthReceivedLastMinuteTotal = "connection_bandwidth_received_last_minute_total"
	// VirtualServerAddress is virtualserver_address: public address of the server.
	// TeamSpeak 6 only.
	VirtualServerAddress = "virtualserver_address"
	// VirtualServerAdministrativeDomain is virtualserver_administrative_domain:
	// administrative domain of the server. TeamSpeak 6 only.
	VirtualServerAdministrativeDomain = "virtualserver_administrative_domain"
	// VirtualServerCanonicalName is virtualserver_canonical_name: canonical name
	// of the server. TeamSpeak 6 only.
	VirtualServerCanonicalName = "virtualserver_canonical_name"
	// VirtualServerHomeBaseStorageQuota is virtualserver_homebase_storage_quota:
	// storage quota for homebase data, in bytes; 4294967295 means unlimited.
	// TeamSpeak 6 only.
	VirtualServerHomeBaseStorageQuota = "virtualserver_homebase_storage_quota"
	// VirtualServerHomeBases is virtualserver_homebases: number of homebase users
	// on this server. TeamSpeak 6 only.
	VirtualServerHomeBases = "virtualserver_homebases"
	// VirtualServerMaxHomeBases is virtualserver_max_homebases: maximum number of
	// homebase users this server accepts. TeamSpeak 6 only.
	VirtualServerMaxHomeBases = "virtualserver_max_homebases"
	// VirtualServerMyTSIDConnectOnly is virtualserver_mytsid_connect_only: 1 if
	// only clients with a MyTeamSpeak id may connect, 0 if not. TeamSpeak 6 only.
	VirtualServerMyTSIDConnectOnly = "virtualserver_mytsid_connect_only"
	// VirtualServerSFUEndpoint is virtualserver_sfu_endpoint: address of the
	// server's SFU endpoint; empty if none. TeamSpeak 6 only.
	VirtualServerSFUEndpoint = "virtualserver_sfu_endpoint"
	// VirtualServerStorageQuota is virtualserver_storage_quota: total file storage
	// quota of the server, in bytes; 4294967295 means unlimited. TeamSpeak 6 only.
	VirtualServerStorageQuota = "virtualserver_storage_quota"
	// VirtualServerVersionSign is virtualserver_version_sign: signature that
	// proves the server's version string is genuine, base64. TeamSpeak 6 only.
	VirtualServerVersionSign = "virtualserver_version_sign"
)

// Server instance properties, as instanceinfo returns them; those marked
// editable are accepted by EditInstance (instanceedit).
const (
	// ServerInstanceDatabaseVersion is serverinstance_database_version: revision
	// of the server database schema.
	ServerInstanceDatabaseVersion = "serverinstance_database_version"
	// ServerInstanceFileTransferPort is serverinstance_filetransfer_port: TCP port
	// of the file transfer service. Editable.
	ServerInstanceFileTransferPort = "serverinstance_filetransfer_port"
	// ServerInstanceMaxDownloadTotalBandwidth is
	// serverinstance_max_download_total_bandwidth: maximum bandwidth of file
	// transfer downloads for the whole instance, in bytes per second. Editable.
	ServerInstanceMaxDownloadTotalBandwidth = "serverinstance_max_download_total_bandwidth"
	// ServerInstanceMaxUploadTotalBandwidth is
	// serverinstance_max_upload_total_bandwidth: maximum bandwidth of file
	// transfer uploads for the whole instance, in bytes per second. Editable.
	ServerInstanceMaxUploadTotalBandwidth = "serverinstance_max_upload_total_bandwidth"
	// ServerInstanceGuestServerQueryGroup is
	// serverinstance_guest_serverquery_group: id of the server group given to
	// ServerQuery clients that have not logged in. Editable.
	ServerInstanceGuestServerQueryGroup = "serverinstance_guest_serverquery_group"
	// ServerInstanceServerQueryFloodCommands is
	// serverinstance_serverquery_flood_commands: commands a ServerQuery client may
	// send within the flood time before it is banned. Editable.
	ServerInstanceServerQueryFloodCommands = "serverinstance_serverquery_flood_commands"
	// ServerInstanceServerQueryFloodTime is serverinstance_serverquery_flood_time:
	// time window, in seconds, in which ServerQuery commands are counted against
	// the flood limit. Editable.
	ServerInstanceServerQueryFloodTime = "serverinstance_serverquery_flood_time"
	// ServerInstanceServerQueryBanTime is serverinstance_serverquery_ban_time: how
	// long, in seconds, a ServerQuery client is banned for flooding. Editable.
	ServerInstanceServerQueryBanTime = "serverinstance_serverquery_ban_time"
	// ServerInstanceTemplateServerAdminGroup is
	// serverinstance_template_serveradmin_group: id of the template server group
	// used for server admins of new virtual servers. Editable.
	ServerInstanceTemplateServerAdminGroup = "serverinstance_template_serveradmin_group"
	// ServerInstanceTemplateServerDefaultGroup is
	// serverinstance_template_serverdefault_group: id of the template server group
	// used as the default group of new virtual servers. Editable.
	ServerInstanceTemplateServerDefaultGroup = "serverinstance_template_serverdefault_group"
	// ServerInstanceTemplateChannelAdminGroup is
	// serverinstance_template_channeladmin_group: id of the template channel group
	// used for channel admins of new virtual servers. Editable.
	ServerInstanceTemplateChannelAdminGroup = "serverinstance_template_channeladmin_group"
	// ServerInstanceTemplateChannelDefaultGroup is
	// serverinstance_template_channeldefault_group: id of the template channel
	// group used as the default channel group of new virtual servers. Editable.
	ServerInstanceTemplateChannelDefaultGroup = "serverinstance_template_channeldefault_group"
	// ServerInstancePermissionsVersion is serverinstance_permissions_version:
	// revision of the permission set the server knows.
	ServerInstancePermissionsVersion = "serverinstance_permissions_version"
	// ServerInstancePendingConnectionsPerIP is
	// serverinstance_pending_connections_per_ip: connections an IP address may
	// have waiting to finish connecting; 0 means no limit. Editable.
	ServerInstancePendingConnectionsPerIP = "serverinstance_pending_connections_per_ip"
	// ServerInstanceServerQueryMaxConnectionsPerIP is
	// serverinstance_serverquery_max_connections_per_ip: serverQuery connections
	// one IP address may hold open at the same time. Editable.
	ServerInstanceServerQueryMaxConnectionsPerIP = "serverinstance_serverquery_max_connections_per_ip"
	// ServerInstanceMaxHomeBases is serverinstance_max_homebases: maximum number
	// of homebase users across the instance; -1 means unlimited. Editable.
	// TeamSpeak 6 only.
	ServerInstanceMaxHomeBases = "serverinstance_max_homebases"
)

// Host properties, as hostinfo returns them.
const (
	// InstanceUptime is instance_uptime: seconds since the server instance
	// started.
	InstanceUptime = "instance_uptime"
	// HostTimestampUTC is host_timestamp_utc: the server's current time, as a Unix
	// timestamp in seconds.
	HostTimestampUTC = "host_timestamp_utc"
	// VirtualServersRunningTotal is virtualservers_running_total: number of
	// virtual servers running.
	VirtualServersRunningTotal = "virtualservers_running_total"
	// VirtualServersTotalMaxClients is virtualservers_total_maxclients: sum of the
	// client limits of all running virtual servers.
	VirtualServersTotalMaxClients = "virtualservers_total_maxclients"
	// VirtualServersTotalClientsOnline is virtualservers_total_clients_online:
	// clients online across all virtual servers.
	VirtualServersTotalClientsOnline = "virtualservers_total_clients_online"
	// VirtualServersTotalChannelsOnline is virtualservers_total_channels_online:
	// channels across all virtual servers.
	VirtualServersTotalChannelsOnline = "virtualservers_total_channels_online"
	// VirtualServersTotalHomeBases is virtualservers_total_homebases: number of
	// homebase users across all virtual servers. TeamSpeak 6 only.
	VirtualServersTotalHomeBases = "virtualservers_total_homebases"
	// VirtualServersTotalMaxHomeBases is virtualservers_total_max_homebases:
	// maximum number of homebase users across all virtual servers; -1 means
	// unlimited. TeamSpeak 6 only.
	VirtualServersTotalMaxHomeBases = "virtualservers_total_max_homebases"
)

// Client properties, as clientinfo returns them.
const (
	// CID is cid: id of the channel the client is in.
	CID = "cid"
	// ClientIdleTime is client_idle_time: milliseconds since the client was last
	// active.
	ClientIdleTime = "client_idle_time"
	// ClientUniqueIdentifier is client_unique_identifier: the client's unique id,
	// derived from its identity; a ServerQuery client has its login name.
	ClientUniqueIdentifier = "client_unique_identifier"
	// ClientNickname is client_nickname: nickname of the client. Editable.
	ClientNickname = "client_nickname"
	// ClientVersion is client_version: client version and build as the client
	// reports it.
	ClientVersion = "client_version"
	// ClientPlatform is client_platform: operating system the client reports, such
	// as Windows.
	ClientPlatform = "client_platform"
	// ClientInputMuted is client_input_muted: 1 if the client's microphone is
	// muted, 0 if not.
	ClientInputMuted = "client_input_muted"
	// ClientOutputMuted is client_output_muted: 1 if the client's speakers are
	// muted, 0 if not.
	ClientOutputMuted = "client_output_muted"
	// ClientOutputOnlyMuted is client_outputonly_muted: 1 if the client has muted
	// all other clients' sound but not its own, 0 if not.
	ClientOutputOnlyMuted = "client_outputonly_muted"
	// ClientInputHardware is client_input_hardware: 1 if the client has a working
	// capture device, 0 if not.
	ClientInputHardware = "client_input_hardware"
	// ClientOutputHardware is client_output_hardware: 1 if the client has a
	// working playback device, 0 if not.
	ClientOutputHardware = "client_output_hardware"
	// ClientDefaultChannel is client_default_channel: path of the channel the
	// client asked to join first; empty for none.
	ClientDefaultChannel = "client_default_channel"
	// ClientMetaData is client_meta_data: free-form data the client attaches to
	// itself.
	ClientMetaData = "client_meta_data"
	// ClientIsRecording is client_is_recording: 1 if the client is recording the
	// conversation, 0 if not.
	ClientIsRecording = "client_is_recording"
	// ClientVersionSign is client_version_sign: signature that proves the client's
	// version string is genuine, base64.
	ClientVersionSign = "client_version_sign"
	// ClientSecurityHash is client_security_hash: the client's security hash;
	// empty if it sent none.
	ClientSecurityHash = "client_security_hash"
	// ClientIsStreaming is client_is_streaming: 1 if the client is streaming, 0 if
	// not. TeamSpeak 6 only.
	ClientIsStreaming = "client_is_streaming"
	// ClientLoginName is client_login_name: serverQuery login name the client
	// logged in with; empty for voice clients.
	ClientLoginName = "client_login_name"
	// ClientDatabaseID is client_database_id: the client's id in the server
	// database.
	ClientDatabaseID = "client_database_id"
	// ClientChannelGroupID is client_channel_group_id: id of the client's channel
	// group in its current channel.
	ClientChannelGroupID = "client_channel_group_id"
	// ClientServerGroups is client_servergroups: ids of the client's server
	// groups, separated by commas.
	ClientServerGroups = "client_servergroups"
	// ClientCreated is client_created: when the client first connected, as a Unix
	// timestamp in seconds.
	ClientCreated = "client_created"
	// ClientLastConnected is client_lastconnected: when the client last connected,
	// as a Unix timestamp in seconds.
	ClientLastConnected = "client_lastconnected"
	// ClientTotalConnections is client_totalconnections: how many times the client
	// has connected.
	ClientTotalConnections = "client_totalconnections"
	// ClientAway is client_away: 1 if the client is away, 0 if not.
	ClientAway = "client_away"
	// ClientAwayMessage is client_away_message: the client's away message.
	ClientAwayMessage = "client_away_message"
	// ClientType is client_type: 0 for a voice client, 1 for a ServerQuery client.
	ClientType = "client_type"
	// ClientFlagAvatar is client_flag_avatar: checksum of the client's avatar
	// file; empty if it has none.
	ClientFlagAvatar = "client_flag_avatar"
	// ClientTalkPower is client_talk_power: the client's talk power in its
	// channel.
	ClientTalkPower = "client_talk_power"
	// ClientTalkRequest is client_talk_request: nonzero if the client has asked
	// for talk power in a moderated channel, 0 if not.
	ClientTalkRequest = "client_talk_request"
	// ClientTalkRequestMsg is client_talk_request_msg: message that came with the
	// client's request for talk power.
	ClientTalkRequestMsg = "client_talk_request_msg"
	// ClientDescription is client_description: brief description of the client
	// (max 200 chars). Editable.
	ClientDescription = "client_description"
	// ClientIsTalker is client_is_talker: indicates whether the client is able to
	// talk or not. Editable.
	ClientIsTalker = "client_is_talker"
	// ClientMonthBytesUploaded is client_month_bytes_uploaded: bytes of file
	// transfer uploads by the client this month.
	ClientMonthBytesUploaded = "client_month_bytes_uploaded"
	// ClientMonthBytesDownloaded is client_month_bytes_downloaded: bytes of file
	// transfer downloads by the client this month.
	ClientMonthBytesDownloaded = "client_month_bytes_downloaded"
	// ClientTotalBytesUploaded is client_total_bytes_uploaded: bytes of file
	// transfer uploads by the client in total.
	ClientTotalBytesUploaded = "client_total_bytes_uploaded"
	// ClientTotalBytesDownloaded is client_total_bytes_downloaded: bytes of file
	// transfer downloads by the client in total.
	ClientTotalBytesDownloaded = "client_total_bytes_downloaded"
	// ClientIsPrioritySpeaker is client_is_priority_speaker: 1 if the client is a
	// priority speaker, 0 if not.
	ClientIsPrioritySpeaker = "client_is_priority_speaker"
	// ClientUnreadMessages is client_unread_messages: number of offline messages
	// the client has not read.
	ClientUnreadMessages = "client_unread_messages"
	// ClientNicknamePhonetic is client_nickname_phonetic: phonetic spelling of the
	// client's nickname.
	ClientNicknamePhonetic = "client_nickname_phonetic"
	// ClientNeededServerQueryViewPower is client_needed_serverquery_view_power:
	// power a ServerQuery client needs to see this client.
	ClientNeededServerQueryViewPower = "client_needed_serverquery_view_power"
	// ClientDefaultToken is client_default_token: privilege key the client used to
	// connect, if any.
	ClientDefaultToken = "client_default_token"
	// ClientIconID is client_icon_id: CRC32 checksum of the client icon. Editable.
	ClientIconID = "client_icon_id"
	// ClientIsChannelCommander is client_is_channel_commander: indicates whether
	// the client is a channel commander or not. Editable.
	ClientIsChannelCommander = "client_is_channel_commander"
	// ClientCountry is client_country: two-letter country code of the client;
	// empty if unknown.
	ClientCountry = "client_country"
	// ClientChannelGroupInheritedChannelID is
	// client_channel_group_inherited_channel_id: id of the channel the client's
	// channel group applies from, which is an ancestor when the group is
	// inherited.
	ClientChannelGroupInheritedChannelID = "client_channel_group_inherited_channel_id"
	// ClientBadges is client_badges: badges the client shows, as a string.
	ClientBadges = "client_badges"
	// ClientMyTeamSpeakID is client_myteamspeak_id: the client's MyTeamSpeak id;
	// empty if it is not logged in.
	ClientMyTeamSpeakID = "client_myteamspeak_id"
	// ClientIntegrations is client_integrations: integrations the client has
	// linked to its MyTeamSpeak account; empty for none.
	ClientIntegrations = "client_integrations"
	// ClientMyTeamSpeakAvatar is client_myteamspeak_avatar: checksum of the
	// client's MyTeamSpeak avatar; empty for none.
	ClientMyTeamSpeakAvatar = "client_myteamspeak_avatar"
	// ClientSignedBadges is client_signed_badges: badges the client shows, signed
	// by TeamSpeak.
	ClientSignedBadges = "client_signed_badges"
	// ClientUserTag is client_user_tag: free-form tag the user has set for itself.
	// TeamSpeak 6 only.
	ClientUserTag = "client_user_tag"
	// ClientPublicKeyRaw is client_public_key_raw: the client's raw public key,
	// base64. TeamSpeak 6 only.
	ClientPublicKeyRaw = "client_public_key_raw"
	// ClientBase64HashClientUID is client_base64HashClientUID: the client's unique
	// id hashed and re-encoded with the letters a to p, the form the TeamSpeak
	// client uses to name its avatar files.
	ClientBase64HashClientUID = "client_base64HashClientUID"
	// ConnectionConnectedTime is connection_connected_time: milliseconds since the
	// client connected.
	ConnectionConnectedTime = "connection_connected_time"
	// ConnectionClientIP is connection_client_ip: the client's IP address.
	ConnectionClientIP = "connection_client_ip"
)
