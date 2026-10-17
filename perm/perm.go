// Package perm names the permissions a TeamSpeak server checks, for
// teamspeak.PermissionByName:
//
//	c.AddChannelPermission(ctx, cid, teamspeak.PermissionByName(perm.ClientNeededTalkPower), 50)
//
// The constants are the names TeamSpeak 3.13 and 6 servers list, in the order
// they list them, measured with permissionlist; the fourteen marked TeamSpeak 6
// only are missing on TeamSpeak 3. A name starting b_ is a switch, granted or
// not; one starting i_ is a value, such as a power compared with a needed
// power. Every permission has a twin, i_needed_modify_power_ followed by its
// name, which sets the modify power needed to change it; those are the second
// block, named NeededModifyPower followed by the permission's own name. A server
// may know permissions this list does not, which is why
// PermissionByName takes any string.
package perm

// The permissions, in the order the server lists them.
const (
	// ServerInstanceHelpView is b_serverinstance_help_view: retrieve information
	// about ServerQuery commands.
	ServerInstanceHelpView = "b_serverinstance_help_view"
	// ServerInstanceInfoView is b_serverinstance_info_view: retrieve global server
	// information.
	ServerInstanceInfoView = "b_serverinstance_info_view"
	// ServerInstanceVirtualServerList is b_serverinstance_virtualserver_list: list
	// virtual servers stored in the database.
	ServerInstanceVirtualServerList = "b_serverinstance_virtualserver_list"
	// ServerInstanceBindingList is b_serverinstance_binding_list: list active IP
	// bindings on multi-homed machines.
	ServerInstanceBindingList = "b_serverinstance_binding_list"
	// ServerInstancePermissionList is b_serverinstance_permission_list: list
	// permissions available on the server instance.
	ServerInstancePermissionList = "b_serverinstance_permission_list"
	// ServerInstancePermissionFind is b_serverinstance_permission_find: search
	// permission assignments by name or ID.
	ServerInstancePermissionFind = "b_serverinstance_permission_find"
	// VirtualServerCreate is b_virtualserver_create: create virtual servers.
	VirtualServerCreate = "b_virtualserver_create"
	// VirtualServerDelete is b_virtualserver_delete: delete virtual servers.
	VirtualServerDelete = "b_virtualserver_delete"
	// VirtualServerStartAny is b_virtualserver_start_any: start any virtual server
	// in the server instance.
	VirtualServerStartAny = "b_virtualserver_start_any"
	// VirtualServerStopAny is b_virtualserver_stop_any: stop any virtual server in
	// the server instance.
	VirtualServerStopAny = "b_virtualserver_stop_any"
	// VirtualServerChangeMachineID is b_virtualserver_change_machine_id: change a
	// virtual servers machine ID.
	VirtualServerChangeMachineID = "b_virtualserver_change_machine_id"
	// VirtualServerChangeTemplate is b_virtualserver_change_template: edit virtual
	// server default template values.
	VirtualServerChangeTemplate = "b_virtualserver_change_template"
	// ServerQueryLogin is b_serverquery_login: login to ServerQuery.
	ServerQueryLogin = "b_serverquery_login"
	// ServerQueryLoginCreate is b_serverquery_login_create: create a new server
	// query login.
	ServerQueryLoginCreate = "b_serverquery_login_create"
	// ServerQueryLoginDelete is b_serverquery_login_delete: delete a server query
	// login.
	ServerQueryLoginDelete = "b_serverquery_login_delete"
	// ServerQueryLoginList is b_serverquery_login_list: list server query logins.
	ServerQueryLoginList = "b_serverquery_login_list"
	// ServerInstanceTextMessageSend is b_serverinstance_textmessage_send: send
	// text messages to all virtual servers at once.
	ServerInstanceTextMessageSend = "b_serverinstance_textmessage_send"
	// ServerInstanceLogView is b_serverinstance_log_view: retrieve global server
	// log.
	ServerInstanceLogView = "b_serverinstance_log_view"
	// ServerInstanceLogAdd is b_serverinstance_log_add: write to global server
	// log.
	ServerInstanceLogAdd = "b_serverinstance_log_add"
	// ServerInstanceStop is b_serverinstance_stop: shutdown the server process.
	ServerInstanceStop = "b_serverinstance_stop"
	// ServerInstanceLicenseSignMessage is b_serverinstance_licensesign_message:
	// sign arbitrary message with license key. TeamSpeak 6 only.
	ServerInstanceLicenseSignMessage = "b_serverinstance_licensesign_message"
	// ServerInstanceModifySettings is b_serverinstance_modify_settings: edit
	// global settings.
	ServerInstanceModifySettings = "b_serverinstance_modify_settings"
	// ServerInstanceModifyQueryGroup is b_serverinstance_modify_querygroup: edit
	// global ServerQuery groups.
	ServerInstanceModifyQueryGroup = "b_serverinstance_modify_querygroup"
	// ServerInstanceModifyTemplates is b_serverinstance_modify_templates: edit
	// global template groups.
	ServerInstanceModifyTemplates = "b_serverinstance_modify_templates"
	// VirtualServerSelect is b_virtualserver_select: select a virtual server.
	VirtualServerSelect = "b_virtualserver_select"
	// VirtualServerInfoView is b_virtualserver_info_view: retrieve virtual server
	// information.
	VirtualServerInfoView = "b_virtualserver_info_view"
	// VirtualServerConnectionInfoView is b_virtualserver_connectioninfo_view:
	// retrieve virtual server connection information.
	VirtualServerConnectionInfoView = "b_virtualserver_connectioninfo_view"
	// VirtualServerChannelList is b_virtualserver_channel_list: list channels on a
	// virtual server.
	VirtualServerChannelList = "b_virtualserver_channel_list"
	// VirtualServerChannelSearch is b_virtualserver_channel_search: search for
	// channels on a virtual server.
	VirtualServerChannelSearch = "b_virtualserver_channel_search"
	// VirtualServerClientList is b_virtualserver_client_list: list clients online
	// on a virtual server.
	VirtualServerClientList = "b_virtualserver_client_list"
	// VirtualServerClientSearch is b_virtualserver_client_search: search for
	// clients online on a virtual server.
	VirtualServerClientSearch = "b_virtualserver_client_search"
	// VirtualServerClientDBList is b_virtualserver_client_dblist: list client
	// identities known by the virtual server.
	VirtualServerClientDBList = "b_virtualserver_client_dblist"
	// VirtualServerClientDBSearch is b_virtualserver_client_dbsearch: search for
	// client identities known by the virtual server.
	VirtualServerClientDBSearch = "b_virtualserver_client_dbsearch"
	// VirtualServerClientDBInfo is b_virtualserver_client_dbinfo: retrieve client
	// information.
	VirtualServerClientDBInfo = "b_virtualserver_client_dbinfo"
	// VirtualServerPermissionFind is b_virtualserver_permission_find: find
	// permissions.
	VirtualServerPermissionFind = "b_virtualserver_permission_find"
	// VirtualServerCustomSearch is b_virtualserver_custom_search: find custom
	// fields.
	VirtualServerCustomSearch = "b_virtualserver_custom_search"
	// VirtualServerStart is b_virtualserver_start: start own virtual server.
	VirtualServerStart = "b_virtualserver_start"
	// VirtualServerStop is b_virtualserver_stop: stop own virtual server.
	VirtualServerStop = "b_virtualserver_stop"
	// VirtualServerTokenList is b_virtualserver_token_list: list privilege keys
	// available.
	VirtualServerTokenList = "b_virtualserver_token_list"
	// VirtualServerTokenAdd is b_virtualserver_token_add: create new privilege
	// keys.
	VirtualServerTokenAdd = "b_virtualserver_token_add"
	// VirtualServerTokenUse is b_virtualserver_token_use: use a privilege keys to
	// gain access to groups.
	VirtualServerTokenUse = "b_virtualserver_token_use"
	// VirtualServerTokenDelete is b_virtualserver_token_delete: delete a privilege
	// key.
	VirtualServerTokenDelete = "b_virtualserver_token_delete"
	// VirtualServerAPIKeyAdd is b_virtualserver_apikey_add: create a new API key.
	VirtualServerAPIKeyAdd = "b_virtualserver_apikey_add"
	// VirtualServerAPIKeyManage is b_virtualserver_apikey_manage: manage existing
	// API keys.
	VirtualServerAPIKeyManage = "b_virtualserver_apikey_manage"
	// VirtualServerLogView is b_virtualserver_log_view: retrieve virtual server
	// log.
	VirtualServerLogView = "b_virtualserver_log_view"
	// VirtualServerLogAdd is b_virtualserver_log_add: write to virtual server log.
	VirtualServerLogAdd = "b_virtualserver_log_add"
	// VirtualServerJoinIgnorePassword is b_virtualserver_join_ignore_password:
	// join virtual server ignoring its password.
	VirtualServerJoinIgnorePassword = "b_virtualserver_join_ignore_password"
	// VirtualServerNotifyRegister is b_virtualserver_notify_register: register for
	// server notifications.
	VirtualServerNotifyRegister = "b_virtualserver_notify_register"
	// VirtualServerNotifyUnregister is b_virtualserver_notify_unregister:
	// unregister from server notifications.
	VirtualServerNotifyUnregister = "b_virtualserver_notify_unregister"
	// VirtualServerSnapshotCreate is b_virtualserver_snapshot_create: create
	// server snapshots.
	VirtualServerSnapshotCreate = "b_virtualserver_snapshot_create"
	// VirtualServerSnapshotDeploy is b_virtualserver_snapshot_deploy: deploy
	// server snapshots.
	VirtualServerSnapshotDeploy = "b_virtualserver_snapshot_deploy"
	// VirtualServerPermissionReset is b_virtualserver_permission_reset: reset the
	// server permission settings to default values.
	VirtualServerPermissionReset = "b_virtualserver_permission_reset"
	// VirtualServerCanonicalNameManage is b_virtualserver_canonical_name_manage:
	// manage canonical name of the virtual server. TeamSpeak 6 only.
	VirtualServerCanonicalNameManage = "b_virtualserver_canonical_name_manage"
	// VirtualServerModifyName is b_virtualserver_modify_name: modify server name.
	VirtualServerModifyName = "b_virtualserver_modify_name"
	// VirtualServerModifyWelcomeMessage is b_virtualserver_modify_welcomemessage:
	// modify welcome message.
	VirtualServerModifyWelcomeMessage = "b_virtualserver_modify_welcomemessage"
	// VirtualServerModifyMaxClients is b_virtualserver_modify_maxclients: modify
	// servers max clients.
	VirtualServerModifyMaxClients = "b_virtualserver_modify_maxclients"
	// VirtualServerModifyReservedSlots is b_virtualserver_modify_reserved_slots:
	// modify reserved slots.
	VirtualServerModifyReservedSlots = "b_virtualserver_modify_reserved_slots"
	// VirtualServerModifyPassword is b_virtualserver_modify_password: modify
	// server password.
	VirtualServerModifyPassword = "b_virtualserver_modify_password"
	// VirtualServerModifyDefaultServerGroup is
	// b_virtualserver_modify_default_servergroup: modify default Server Group.
	VirtualServerModifyDefaultServerGroup = "b_virtualserver_modify_default_servergroup"
	// VirtualServerModifyDefaultChannelGroup is
	// b_virtualserver_modify_default_channelgroup: modify default Channel Group.
	VirtualServerModifyDefaultChannelGroup = "b_virtualserver_modify_default_channelgroup"
	// VirtualServerModifyDefaultChannelAdminGroup is
	// b_virtualserver_modify_default_channeladmingroup: modify default Channel
	// Admin Group.
	VirtualServerModifyDefaultChannelAdminGroup = "b_virtualserver_modify_default_channeladmingroup"
	// VirtualServerModifyChannelForcedSilence is
	// b_virtualserver_modify_channel_forced_silence: modify channel force silence
	// value.
	VirtualServerModifyChannelForcedSilence = "b_virtualserver_modify_channel_forced_silence"
	// VirtualServerModifyComplain is b_virtualserver_modify_complain: modify
	// individual complain settings.
	VirtualServerModifyComplain = "b_virtualserver_modify_complain"
	// VirtualServerModifyAntiflood is b_virtualserver_modify_antiflood: modify
	// individual antiflood settings.
	VirtualServerModifyAntiflood = "b_virtualserver_modify_antiflood"
	// VirtualServerModifyFTSettings is b_virtualserver_modify_ft_settings: modify
	// file transfer settings.
	VirtualServerModifyFTSettings = "b_virtualserver_modify_ft_settings"
	// VirtualServerModifyFTQuotas is b_virtualserver_modify_ft_quotas: modify file
	// transfer quotas.
	VirtualServerModifyFTQuotas = "b_virtualserver_modify_ft_quotas"
	// VirtualServerModifyHostMessage is b_virtualserver_modify_hostmessage: modify
	// individual hostmessage settings.
	VirtualServerModifyHostMessage = "b_virtualserver_modify_hostmessage"
	// VirtualServerModifyHostBanner is b_virtualserver_modify_hostbanner: modify
	// individual hostbanner settings.
	VirtualServerModifyHostBanner = "b_virtualserver_modify_hostbanner"
	// VirtualServerModifyHostButton is b_virtualserver_modify_hostbutton: modify
	// individual hostbutton settings.
	VirtualServerModifyHostButton = "b_virtualserver_modify_hostbutton"
	// VirtualServerModifyPort is b_virtualserver_modify_port: modify server port.
	VirtualServerModifyPort = "b_virtualserver_modify_port"
	// VirtualServerModifyAutoStart is b_virtualserver_modify_autostart: modify
	// server autostart.
	VirtualServerModifyAutoStart = "b_virtualserver_modify_autostart"
	// VirtualServerModifyNeededIdentitySecurityLevel is
	// b_virtualserver_modify_needed_identity_security_level: modify required
	// identity security level.
	VirtualServerModifyNeededIdentitySecurityLevel = "b_virtualserver_modify_needed_identity_security_level"
	// VirtualServerModifyPrioritySpeakerDimmModificator is
	// b_virtualserver_modify_priority_speaker_dimm_modificator: modify priority
	// speaker dimm modificator.
	VirtualServerModifyPrioritySpeakerDimmModificator = "b_virtualserver_modify_priority_speaker_dimm_modificator"
	// VirtualServerModifyLogSettings is b_virtualserver_modify_log_settings:
	// modify log settings.
	VirtualServerModifyLogSettings = "b_virtualserver_modify_log_settings"
	// VirtualServerModifyMinClientVersion is
	// b_virtualserver_modify_min_client_version: modify min client version.
	VirtualServerModifyMinClientVersion = "b_virtualserver_modify_min_client_version"
	// VirtualServerModifyIconID is b_virtualserver_modify_icon_id: modify server
	// icon.
	VirtualServerModifyIconID = "b_virtualserver_modify_icon_id"
	// VirtualServerModifyWebList is b_virtualserver_modify_weblist: modify web
	// server list reporting settings.
	VirtualServerModifyWebList = "b_virtualserver_modify_weblist"
	// VirtualServerModifyCodecEncryptionMode is
	// b_virtualserver_modify_codec_encryption_mode: modify codec encryption mode.
	VirtualServerModifyCodecEncryptionMode = "b_virtualserver_modify_codec_encryption_mode"
	// VirtualServerModifyTemporaryPasswords is
	// b_virtualserver_modify_temporary_passwords: modify temporary
	// serverpasswords.
	VirtualServerModifyTemporaryPasswords = "b_virtualserver_modify_temporary_passwords"
	// VirtualServerModifyTemporaryPasswordsOwn is
	// b_virtualserver_modify_temporary_passwords_own: modify own temporary
	// serverpasswords.
	VirtualServerModifyTemporaryPasswordsOwn = "b_virtualserver_modify_temporary_passwords_own"
	// VirtualServerModifyChannelTempDeleteDelayDefault is
	// b_virtualserver_modify_channel_temp_delete_delay_default: modify default
	// temporary channel delete delay.
	VirtualServerModifyChannelTempDeleteDelayDefault = "b_virtualserver_modify_channel_temp_delete_delay_default"
	// VirtualServerModifyNickname is b_virtualserver_modify_nickname: modify
	// server nicknames.
	VirtualServerModifyNickname = "b_virtualserver_modify_nickname"
	// VirtualServerModifyIntegrations is b_virtualserver_modify_integrations:
	// modify integrations.
	VirtualServerModifyIntegrations = "b_virtualserver_modify_integrations"
	// VirtualServerModifyMyTSIDConnect is b_virtualserver_modify_mytsid_connect:
	// modify mytsid connect. TeamSpeak 6 only.
	VirtualServerModifyMyTSIDConnect = "b_virtualserver_modify_mytsid_connect"
	// ChannelMinDepth is i_channel_min_depth: min channel creation depth in
	// hierarchy.
	ChannelMinDepth = "i_channel_min_depth"
	// ChannelMaxDepth is i_channel_max_depth: max channel creation depth in
	// hierarchy.
	ChannelMaxDepth = "i_channel_max_depth"
	// ChannelGroupInheritanceEnd is b_channel_group_inheritance_end: stop
	// inheritance of channel group permissions.
	ChannelGroupInheritanceEnd = "b_channel_group_inheritance_end"
	// ChannelPermissionModifyPower is i_channel_permission_modify_power: modify
	// channel permission power.
	ChannelPermissionModifyPower = "i_channel_permission_modify_power"
	// ChannelNeededPermissionModifyPower is
	// i_channel_needed_permission_modify_power: needed modify channel permission
	// power.
	ChannelNeededPermissionModifyPower = "i_channel_needed_permission_modify_power"
	// ChannelInfoView is b_channel_info_view: retrieve channel information.
	ChannelInfoView = "b_channel_info_view"
	// ChannelCreateChild is b_channel_create_child: create sub-channels.
	ChannelCreateChild = "b_channel_create_child"
	// ChannelCreatePermanent is b_channel_create_permanent: create permanent
	// channels.
	ChannelCreatePermanent = "b_channel_create_permanent"
	// ChannelCreateSemiPermanent is b_channel_create_semi_permanent: create
	// semi-permanent channels.
	ChannelCreateSemiPermanent = "b_channel_create_semi_permanent"
	// ChannelCreateTemporary is b_channel_create_temporary: create temporary
	// channels.
	ChannelCreateTemporary = "b_channel_create_temporary"
	// ChannelCreateWithTopic is b_channel_create_with_topic: create channels with
	// a topic.
	ChannelCreateWithTopic = "b_channel_create_with_topic"
	// ChannelCreateWithDescription is b_channel_create_with_description: create
	// channels with a description.
	ChannelCreateWithDescription = "b_channel_create_with_description"
	// ChannelCreateWithPassword is b_channel_create_with_password: create password
	// protected channels.
	ChannelCreateWithPassword = "b_channel_create_with_password"
	// ChannelCreateWithBanner is b_channel_create_with_banner: create channel with
	// a banner.
	ChannelCreateWithBanner = "b_channel_create_with_banner"
	// ChannelCreateModifyWithCodecOpusVoice is
	// b_channel_create_modify_with_codec_opusvoice: create channels using OPUS
	// (voice) codec.
	ChannelCreateModifyWithCodecOpusVoice = "b_channel_create_modify_with_codec_opusvoice"
	// ChannelCreateModifyWithCodecOpusMusic is
	// b_channel_create_modify_with_codec_opusmusic: create channels using OPUS
	// (music) codec.
	ChannelCreateModifyWithCodecOpusMusic = "b_channel_create_modify_with_codec_opusmusic"
	// ChannelCreateModifyWithCodecMaxQuality is
	// i_channel_create_modify_with_codec_maxquality: create channels with custom
	// codec quality.
	ChannelCreateModifyWithCodecMaxQuality = "i_channel_create_modify_with_codec_maxquality"
	// ChannelCreateModifyWithCodecLatencyFactorMin is
	// i_channel_create_modify_with_codec_latency_factor_min: create channels with
	// minimal custom codec latency factor.
	ChannelCreateModifyWithCodecLatencyFactorMin = "i_channel_create_modify_with_codec_latency_factor_min"
	// ChannelCreateWithMaxClients is b_channel_create_with_maxclients: create
	// channels with custom max clients.
	ChannelCreateWithMaxClients = "b_channel_create_with_maxclients"
	// ChannelCreateWithMaxFamilyClients is b_channel_create_with_maxfamilyclients:
	// create channels with custom max family clients.
	ChannelCreateWithMaxFamilyClients = "b_channel_create_with_maxfamilyclients"
	// ChannelCreateWithSortOrder is b_channel_create_with_sortorder: create
	// channels with custom sort order.
	ChannelCreateWithSortOrder = "b_channel_create_with_sortorder"
	// ChannelCreateWithDefault is b_channel_create_with_default: create default
	// channels.
	ChannelCreateWithDefault = "b_channel_create_with_default"
	// ChannelCreateWithNeededTalkPower is b_channel_create_with_needed_talk_power:
	// create channels with needed talk power.
	ChannelCreateWithNeededTalkPower = "b_channel_create_with_needed_talk_power"
	// ChannelCreateModifyWithForcePassword is
	// b_channel_create_modify_with_force_password: create new channels only with
	// password.
	ChannelCreateModifyWithForcePassword = "b_channel_create_modify_with_force_password"
	// ChannelCreateModifyWithTempDeleteDelay is
	// i_channel_create_modify_with_temp_delete_delay: max delete delay for
	// temporary channels.
	ChannelCreateModifyWithTempDeleteDelay = "i_channel_create_modify_with_temp_delete_delay"
	// ChannelModifyParent is b_channel_modify_parent: move channels.
	ChannelModifyParent = "b_channel_modify_parent"
	// ChannelModifyMakeDefault is b_channel_modify_make_default: make channel
	// default.
	ChannelModifyMakeDefault = "b_channel_modify_make_default"
	// ChannelModifyMakePermanent is b_channel_modify_make_permanent: make channel
	// permanent.
	ChannelModifyMakePermanent = "b_channel_modify_make_permanent"
	// ChannelModifyMakeSemiPermanent is b_channel_modify_make_semi_permanent: make
	// channel semi-permanent.
	ChannelModifyMakeSemiPermanent = "b_channel_modify_make_semi_permanent"
	// ChannelModifyMakeTemporary is b_channel_modify_make_temporary: make channel
	// temporary.
	ChannelModifyMakeTemporary = "b_channel_modify_make_temporary"
	// ChannelModifyName is b_channel_modify_name: modify channel name.
	ChannelModifyName = "b_channel_modify_name"
	// ChannelModifyTopic is b_channel_modify_topic: modify channel topic.
	ChannelModifyTopic = "b_channel_modify_topic"
	// ChannelModifyDescription is b_channel_modify_description: modify channel
	// description.
	ChannelModifyDescription = "b_channel_modify_description"
	// ChannelModifyPassword is b_channel_modify_password: modify channel password.
	ChannelModifyPassword = "b_channel_modify_password"
	// ChannelModifyBanner is b_channel_modify_banner: modify channel banner.
	ChannelModifyBanner = "b_channel_modify_banner"
	// ChannelModifyCodec is b_channel_modify_codec: modify channel codec.
	ChannelModifyCodec = "b_channel_modify_codec"
	// ChannelModifyCodecQuality is b_channel_modify_codec_quality: modify channel
	// codec quality.
	ChannelModifyCodecQuality = "b_channel_modify_codec_quality"
	// ChannelModifyCodecLatencyFactor is b_channel_modify_codec_latency_factor:
	// modify channel codec latency factor.
	ChannelModifyCodecLatencyFactor = "b_channel_modify_codec_latency_factor"
	// ChannelModifyMaxClients is b_channel_modify_maxclients: modify channels max
	// clients.
	ChannelModifyMaxClients = "b_channel_modify_maxclients"
	// ChannelModifyMaxFamilyClients is b_channel_modify_maxfamilyclients: modify
	// channels max family clients.
	ChannelModifyMaxFamilyClients = "b_channel_modify_maxfamilyclients"
	// ChannelModifySortOrder is b_channel_modify_sortorder: modify channel sort
	// order.
	ChannelModifySortOrder = "b_channel_modify_sortorder"
	// ChannelModifyNeededTalkPower is b_channel_modify_needed_talk_power: change
	// needed channel talk power.
	ChannelModifyNeededTalkPower = "b_channel_modify_needed_talk_power"
	// ChannelModifyPower is i_channel_modify_power: channel modify power.
	ChannelModifyPower = "i_channel_modify_power"
	// ChannelNeededModifyPower is i_channel_needed_modify_power: needed channel
	// modify power.
	ChannelNeededModifyPower = "i_channel_needed_modify_power"
	// ChannelModifyMakeCodecEncrypted is b_channel_modify_make_codec_encrypted:
	// make channel codec encrypted.
	ChannelModifyMakeCodecEncrypted = "b_channel_modify_make_codec_encrypted"
	// ChannelModifyTempDeleteDelay is b_channel_modify_temp_delete_delay: modify
	// temporary channel delete delay.
	ChannelModifyTempDeleteDelay = "b_channel_modify_temp_delete_delay"
	// ChannelModifyFTQuotas is b_channel_modify_ft_quotas: modify file transfer
	// quotas. TeamSpeak 6 only.
	ChannelModifyFTQuotas = "b_channel_modify_ft_quotas"
	// ChannelDeletePermanent is b_channel_delete_permanent: delete permanent
	// channels.
	ChannelDeletePermanent = "b_channel_delete_permanent"
	// ChannelDeleteSemiPermanent is b_channel_delete_semi_permanent: delete
	// semi-permanent channels.
	ChannelDeleteSemiPermanent = "b_channel_delete_semi_permanent"
	// ChannelDeleteTemporary is b_channel_delete_temporary: delete temporary
	// channels.
	ChannelDeleteTemporary = "b_channel_delete_temporary"
	// ChannelDeleteFlagForce is b_channel_delete_flag_force: force channel delete.
	ChannelDeleteFlagForce = "b_channel_delete_flag_force"
	// ChannelDeletePower is i_channel_delete_power: delete channel power.
	ChannelDeletePower = "i_channel_delete_power"
	// ChannelNeededDeletePower is i_channel_needed_delete_power: needed delete
	// channel power.
	ChannelNeededDeletePower = "i_channel_needed_delete_power"
	// ChannelJoinPermanent is b_channel_join_permanent: join permanent channels.
	ChannelJoinPermanent = "b_channel_join_permanent"
	// ChannelJoinSemiPermanent is b_channel_join_semi_permanent: join
	// semi-permanent channels.
	ChannelJoinSemiPermanent = "b_channel_join_semi_permanent"
	// ChannelJoinTemporary is b_channel_join_temporary: join temporary channels.
	ChannelJoinTemporary = "b_channel_join_temporary"
	// ChannelJoinIgnorePassword is b_channel_join_ignore_password: join channel
	// ignoring its password.
	ChannelJoinIgnorePassword = "b_channel_join_ignore_password"
	// ChannelJoinIgnoreMaxClients is b_channel_join_ignore_maxclients: ignore
	// channels max clients limit.
	ChannelJoinIgnoreMaxClients = "b_channel_join_ignore_maxclients"
	// ChannelJoinPower is i_channel_join_power: channel join power.
	ChannelJoinPower = "i_channel_join_power"
	// ChannelNeededJoinPower is i_channel_needed_join_power: needed channel join
	// power.
	ChannelNeededJoinPower = "i_channel_needed_join_power"
	// ChannelSubscribePower is i_channel_subscribe_power: channel subscribe power.
	ChannelSubscribePower = "i_channel_subscribe_power"
	// ChannelNeededSubscribePower is i_channel_needed_subscribe_power: needed
	// channel subscribe power.
	ChannelNeededSubscribePower = "i_channel_needed_subscribe_power"
	// ChannelDescriptionViewPower is i_channel_description_view_power: channel
	// description view power.
	ChannelDescriptionViewPower = "i_channel_description_view_power"
	// ChannelNeededDescriptionViewPower is
	// i_channel_needed_description_view_power: needed channel needed description
	// view power.
	ChannelNeededDescriptionViewPower = "i_channel_needed_description_view_power"
	// IconID is i_icon_id: group icon identifier.
	IconID = "i_icon_id"
	// MaxIconFileSize is i_max_icon_filesize: max icon filesize in bytes.
	MaxIconFileSize = "i_max_icon_filesize"
	// IconManage is b_icon_manage: enables icon management.
	IconManage = "b_icon_manage"
	// GroupIsPermanent is b_group_is_permanent: group is permanent.
	GroupIsPermanent = "b_group_is_permanent"
	// GroupAutoUpdateType is i_group_auto_update_type: group auto-update type.
	GroupAutoUpdateType = "i_group_auto_update_type"
	// GroupAutoUpdateMaxValue is i_group_auto_update_max_value: group auto-update
	// max value.
	GroupAutoUpdateMaxValue = "i_group_auto_update_max_value"
	// GroupSortID is i_group_sort_id: group sort id.
	GroupSortID = "i_group_sort_id"
	// GroupShowNameInTree is i_group_show_name_in_tree: show group name in tree
	// depending on selected mode.
	GroupShowNameInTree = "i_group_show_name_in_tree"
	// VirtualServerServerGroupList is b_virtualserver_servergroup_list: list
	// server groups.
	VirtualServerServerGroupList = "b_virtualserver_servergroup_list"
	// VirtualServerServerGroupPermissionList is
	// b_virtualserver_servergroup_permission_list: list server group permissions.
	VirtualServerServerGroupPermissionList = "b_virtualserver_servergroup_permission_list"
	// VirtualServerServerGroupClientList is
	// b_virtualserver_servergroup_client_list: list clients from a server group.
	VirtualServerServerGroupClientList = "b_virtualserver_servergroup_client_list"
	// VirtualServerChannelGroupList is b_virtualserver_channelgroup_list: list
	// channel groups.
	VirtualServerChannelGroupList = "b_virtualserver_channelgroup_list"
	// VirtualServerChannelGroupPermissionList is
	// b_virtualserver_channelgroup_permission_list: list channel group
	// permissions.
	VirtualServerChannelGroupPermissionList = "b_virtualserver_channelgroup_permission_list"
	// VirtualServerChannelGroupClientList is
	// b_virtualserver_channelgroup_client_list: list clients from a channel group.
	VirtualServerChannelGroupClientList = "b_virtualserver_channelgroup_client_list"
	// VirtualServerClientPermissionList is b_virtualserver_client_permission_list:
	// list client permissions.
	VirtualServerClientPermissionList = "b_virtualserver_client_permission_list"
	// VirtualServerChannelPermissionList is
	// b_virtualserver_channel_permission_list: list channel permissions.
	VirtualServerChannelPermissionList = "b_virtualserver_channel_permission_list"
	// VirtualServerChannelClientPermissionList is
	// b_virtualserver_channelclient_permission_list: list channel client
	// permissions.
	VirtualServerChannelClientPermissionList = "b_virtualserver_channelclient_permission_list"
	// VirtualServerServerGroupCreate is b_virtualserver_servergroup_create: create
	// server groups.
	VirtualServerServerGroupCreate = "b_virtualserver_servergroup_create"
	// VirtualServerChannelGroupCreate is b_virtualserver_channelgroup_create:
	// create channel groups.
	VirtualServerChannelGroupCreate = "b_virtualserver_channelgroup_create"
	// GroupModifyPower is i_group_modify_power: group modify power.
	GroupModifyPower = "i_group_modify_power"
	// GroupNeededModifyPower is i_group_needed_modify_power: needed group modify
	// power.
	GroupNeededModifyPower = "i_group_needed_modify_power"
	// GroupMemberAddPower is i_group_member_add_power: group member add power.
	GroupMemberAddPower = "i_group_member_add_power"
	// GroupNeededMemberAddPower is i_group_needed_member_add_power: needed group
	// member add power.
	GroupNeededMemberAddPower = "i_group_needed_member_add_power"
	// GroupMemberRemovePower is i_group_member_remove_power: group member delete
	// power.
	GroupMemberRemovePower = "i_group_member_remove_power"
	// GroupNeededMemberRemovePower is i_group_needed_member_remove_power: needed
	// group member delete power.
	GroupNeededMemberRemovePower = "i_group_needed_member_remove_power"
	// PermissionModifyPower is i_permission_modify_power: permission modify power.
	PermissionModifyPower = "i_permission_modify_power"
	// PermissionModifyPowerIgnore is b_permission_modify_power_ignore: ignore
	// needed permission modify power.
	PermissionModifyPowerIgnore = "b_permission_modify_power_ignore"
	// VirtualServerServerGroupDelete is b_virtualserver_servergroup_delete: delete
	// server groups.
	VirtualServerServerGroupDelete = "b_virtualserver_servergroup_delete"
	// VirtualServerChannelGroupDelete is b_virtualserver_channelgroup_delete:
	// delete channel groups.
	VirtualServerChannelGroupDelete = "b_virtualserver_channelgroup_delete"
	// ClientPermissionModifyPower is i_client_permission_modify_power: client
	// permission modify power.
	ClientPermissionModifyPower = "i_client_permission_modify_power"
	// ClientNeededPermissionModifyPower is
	// i_client_needed_permission_modify_power: needed client permission modify
	// power.
	ClientNeededPermissionModifyPower = "i_client_needed_permission_modify_power"
	// ClientMaxClonesUID is i_client_max_clones_uid: max additional connections
	// per client identity.
	ClientMaxClonesUID = "i_client_max_clones_uid"
	// ClientMaxIdleTime is i_client_max_idletime: max idle time in seconds.
	ClientMaxIdleTime = "i_client_max_idletime"
	// ClientMaxAvatarFileSize is i_client_max_avatar_filesize: max avatar filesize
	// in bytes.
	ClientMaxAvatarFileSize = "i_client_max_avatar_filesize"
	// ClientMaxChannelSubscriptions is i_client_max_channel_subscriptions: max
	// channel subscriptions.
	ClientMaxChannelSubscriptions = "i_client_max_channel_subscriptions"
	// ClientIsPrioritySpeaker is b_client_is_priority_speaker: client is priority
	// speaker.
	ClientIsPrioritySpeaker = "b_client_is_priority_speaker"
	// ClientSkipChannelGroupPermissions is b_client_skip_channelgroup_permissions:
	// ignore channel group permissions.
	ClientSkipChannelGroupPermissions = "b_client_skip_channelgroup_permissions"
	// ClientForcePushToTalk is b_client_force_push_to_talk: force Push-To-Talk
	// capture mode.
	ClientForcePushToTalk = "b_client_force_push_to_talk"
	// ClientIgnoreBans is b_client_ignore_bans: ignore bans.
	ClientIgnoreBans = "b_client_ignore_bans"
	// ClientIgnoreAntiflood is b_client_ignore_antiflood: ignore antiflood
	// measurements.
	ClientIgnoreAntiflood = "b_client_ignore_antiflood"
	// ClientUseReservedSlot is b_client_use_reserved_slot: use an reserved slot.
	ClientUseReservedSlot = "b_client_use_reserved_slot"
	// ClientUseChannelCommander is b_client_use_channel_commander: use channel
	// commander.
	ClientUseChannelCommander = "b_client_use_channel_commander"
	// ClientRequestTalker is b_client_request_talker: allow to request talk power.
	ClientRequestTalker = "b_client_request_talker"
	// ClientAvatarDeleteOther is b_client_avatar_delete_other: allow deletion of
	// avatars from other clients.
	ClientAvatarDeleteOther = "b_client_avatar_delete_other"
	// ClientIsSticky is b_client_is_sticky: client will be sticked to current
	// channel.
	ClientIsSticky = "b_client_is_sticky"
	// ClientIgnoreSticky is b_client_ignore_sticky: client ignores sticky flag.
	ClientIgnoreSticky = "b_client_ignore_sticky"
	// ClientInfoView is b_client_info_view: retrieve client information.
	ClientInfoView = "b_client_info_view"
	// ClientPermissionOverviewView is b_client_permissionoverview_view: retrieve
	// client permissions overview.
	ClientPermissionOverviewView = "b_client_permissionoverview_view"
	// ClientPermissionOverviewOwn is b_client_permissionoverview_own: retrieve
	// clients own permissions overview.
	ClientPermissionOverviewOwn = "b_client_permissionoverview_own"
	// ClientRemoteAddressView is b_client_remoteaddress_view: view client IP
	// address and port.
	ClientRemoteAddressView = "b_client_remoteaddress_view"
	// ClientServerQueryViewPower is i_client_serverquery_view_power: serverQuery
	// view power.
	ClientServerQueryViewPower = "i_client_serverquery_view_power"
	// ClientNeededServerQueryViewPower is i_client_needed_serverquery_view_power:
	// needed ServerQuery view power.
	ClientNeededServerQueryViewPower = "i_client_needed_serverquery_view_power"
	// ClientCustomInfoView is b_client_custom_info_view: view custom fields.
	ClientCustomInfoView = "b_client_custom_info_view"
	// ClientKickFromServerPower is i_client_kick_from_server_power: client kick
	// power from server.
	ClientKickFromServerPower = "i_client_kick_from_server_power"
	// ClientNeededKickFromServerPower is i_client_needed_kick_from_server_power:
	// needed client kick power from server.
	ClientNeededKickFromServerPower = "i_client_needed_kick_from_server_power"
	// ClientKickFromChannelPower is i_client_kick_from_channel_power: client kick
	// power from channel.
	ClientKickFromChannelPower = "i_client_kick_from_channel_power"
	// ClientNeededKickFromChannelPower is i_client_needed_kick_from_channel_power:
	// needed client kick power from channel.
	ClientNeededKickFromChannelPower = "i_client_needed_kick_from_channel_power"
	// ClientBanPower is i_client_ban_power: client ban power.
	ClientBanPower = "i_client_ban_power"
	// ClientNeededBanPower is i_client_needed_ban_power: needed client ban power.
	ClientNeededBanPower = "i_client_needed_ban_power"
	// ClientMovePower is i_client_move_power: client move power.
	ClientMovePower = "i_client_move_power"
	// ClientNeededMovePower is i_client_needed_move_power: needed client move
	// power.
	ClientNeededMovePower = "i_client_needed_move_power"
	// ClientComplainPower is i_client_complain_power: complain power.
	ClientComplainPower = "i_client_complain_power"
	// ClientNeededComplainPower is i_client_needed_complain_power: needed complain
	// power.
	ClientNeededComplainPower = "i_client_needed_complain_power"
	// ClientComplainList is b_client_complain_list: show complain list.
	ClientComplainList = "b_client_complain_list"
	// ClientComplainDeleteOwn is b_client_complain_delete_own: delete own
	// complains.
	ClientComplainDeleteOwn = "b_client_complain_delete_own"
	// ClientComplainDelete is b_client_complain_delete: delete complains.
	ClientComplainDelete = "b_client_complain_delete"
	// ClientBanList is b_client_ban_list: show banlist.
	ClientBanList = "b_client_ban_list"
	// ClientBanCreate is b_client_ban_create: add a ban.
	ClientBanCreate = "b_client_ban_create"
	// ClientBanDeleteOwn is b_client_ban_delete_own: delete own bans.
	ClientBanDeleteOwn = "b_client_ban_delete_own"
	// ClientBanDelete is b_client_ban_delete: delete bans.
	ClientBanDelete = "b_client_ban_delete"
	// ClientBanMaxBanTime is i_client_ban_max_bantime: max bantime.
	ClientBanMaxBanTime = "i_client_ban_max_bantime"
	// ChannelTextMessageDelete is b_channel_textmessage_delete: delete decentral
	// chat messages. TeamSpeak 6 only.
	ChannelTextMessageDelete = "b_channel_textmessage_delete"
	// ClientPrivateTextMessagePower is i_client_private_textmessage_power: client
	// private message power.
	ClientPrivateTextMessagePower = "i_client_private_textmessage_power"
	// ClientNeededPrivateTextMessagePower is
	// i_client_needed_private_textmessage_power: needed client private message
	// power.
	ClientNeededPrivateTextMessagePower = "i_client_needed_private_textmessage_power"
	// ClientServerTextMessageSend is b_client_server_textmessage_send: send text
	// messages to virtual server.
	ClientServerTextMessageSend = "b_client_server_textmessage_send"
	// ClientChannelTextMessageSend is b_client_channel_textmessage_send: send text
	// messages to channel.
	ClientChannelTextMessageSend = "b_client_channel_textmessage_send"
	// ClientOfflineTextMessageSend is b_client_offline_textmessage_send: send
	// offline messages to clients.
	ClientOfflineTextMessageSend = "b_client_offline_textmessage_send"
	// ClientTalkPower is i_client_talk_power: client talk power.
	ClientTalkPower = "i_client_talk_power"
	// ClientNeededTalkPower is i_client_needed_talk_power: needed client talk
	// power.
	ClientNeededTalkPower = "i_client_needed_talk_power"
	// ClientPokePower is i_client_poke_power: client poke power.
	ClientPokePower = "i_client_poke_power"
	// ClientNeededPokePower is i_client_needed_poke_power: needed client poke
	// power.
	ClientNeededPokePower = "i_client_needed_poke_power"
	// ClientSetFlagTalker is b_client_set_flag_talker: set the talker flag for
	// clients and allow them to speak.
	ClientSetFlagTalker = "b_client_set_flag_talker"
	// ClientWhisperPower is i_client_whisper_power: client whisper power.
	ClientWhisperPower = "i_client_whisper_power"
	// ClientNeededWhisperPower is i_client_needed_whisper_power: client needed
	// whisper power.
	ClientNeededWhisperPower = "i_client_needed_whisper_power"
	// ClientModifyDescription is b_client_modify_description: edit a clients
	// description.
	ClientModifyDescription = "b_client_modify_description"
	// ClientModifyOwnDescription is b_client_modify_own_description: allow client
	// to edit own description.
	ClientModifyOwnDescription = "b_client_modify_own_description"
	// ClientModifyDBProperties is b_client_modify_dbproperties: edit a clients
	// properties in the database.
	ClientModifyDBProperties = "b_client_modify_dbproperties"
	// ClientDeleteDBProperties is b_client_delete_dbproperties: delete a clients
	// properties in the database.
	ClientDeleteDBProperties = "b_client_delete_dbproperties"
	// ClientCreateModifyServerQueryLogin is
	// b_client_create_modify_serverquery_login: create or modify own ServerQuery
	// account.
	ClientCreateModifyServerQueryLogin = "b_client_create_modify_serverquery_login"
	// FTIgnorePassword is b_ft_ignore_password: browse files without channel
	// password.
	FTIgnorePassword = "b_ft_ignore_password"
	// FTTransferList is b_ft_transfer_list: retrieve list of running
	// filetransfers.
	FTTransferList = "b_ft_transfer_list"
	// FTFileUploadPower is i_ft_file_upload_power: file upload power.
	FTFileUploadPower = "i_ft_file_upload_power"
	// FTNeededFileUploadPower is i_ft_needed_file_upload_power: needed file upload
	// power.
	FTNeededFileUploadPower = "i_ft_needed_file_upload_power"
	// FTFileDownloadPower is i_ft_file_download_power: file download power.
	FTFileDownloadPower = "i_ft_file_download_power"
	// FTNeededFileDownloadPower is i_ft_needed_file_download_power: needed file
	// download power.
	FTNeededFileDownloadPower = "i_ft_needed_file_download_power"
	// FTFileDeletePower is i_ft_file_delete_power: file delete power.
	FTFileDeletePower = "i_ft_file_delete_power"
	// FTNeededFileDeletePower is i_ft_needed_file_delete_power: needed file delete
	// power.
	FTNeededFileDeletePower = "i_ft_needed_file_delete_power"
	// FTFileRenamePower is i_ft_file_rename_power: file rename power.
	FTFileRenamePower = "i_ft_file_rename_power"
	// FTNeededFileRenamePower is i_ft_needed_file_rename_power: needed file rename
	// power.
	FTNeededFileRenamePower = "i_ft_needed_file_rename_power"
	// FTFileBrowsePower is i_ft_file_browse_power: file browse power.
	FTFileBrowsePower = "i_ft_file_browse_power"
	// FTNeededFileBrowsePower is i_ft_needed_file_browse_power: needed file browse
	// power.
	FTNeededFileBrowsePower = "i_ft_needed_file_browse_power"
	// FTDirectoryCreatePower is i_ft_directory_create_power: create directory
	// power.
	FTDirectoryCreatePower = "i_ft_directory_create_power"
	// FTNeededDirectoryCreatePower is i_ft_needed_directory_create_power: needed
	// create directory power.
	FTNeededDirectoryCreatePower = "i_ft_needed_directory_create_power"
	// FTQuotaMBDownloadPerClient is i_ft_quota_mb_download_per_client: download
	// quota per client in MByte.
	FTQuotaMBDownloadPerClient = "i_ft_quota_mb_download_per_client"
	// FTQuotaMBUploadPerClient is i_ft_quota_mb_upload_per_client: upload quota
	// per client in MByte.
	FTQuotaMBUploadPerClient = "i_ft_quota_mb_upload_per_client"
	// FTStorageMBPerClient is i_ft_storage_mb_per_client: file Storage space per
	// client in MByte. TeamSpeak 6 only.
	FTStorageMBPerClient = "i_ft_storage_mb_per_client"
	// FTMaxFileSizeMB is i_ft_max_file_size_mb: maximum file size of a single file
	// this client can upload. TeamSpeak 6 only.
	FTMaxFileSizeMB = "i_ft_max_file_size_mb"
)

// The permissions that say how much modify power changing each of the
// permissions above takes, in the order the server lists them. Each is named
// after its permission: NeededModifyPowerChannelCreateChild is the one for
// ChannelCreateChild.
const (
	// NeededModifyPowerServerInstanceHelpView is
	// i_needed_modify_power_serverinstance_help_view: the power needed to modify
	// b_serverinstance_help_view.
	NeededModifyPowerServerInstanceHelpView = "i_needed_modify_power_serverinstance_help_view"
	// NeededModifyPowerServerInstanceInfoView is
	// i_needed_modify_power_serverinstance_info_view: the power needed to modify
	// b_serverinstance_info_view.
	NeededModifyPowerServerInstanceInfoView = "i_needed_modify_power_serverinstance_info_view"
	// NeededModifyPowerServerInstanceVirtualServerList is
	// i_needed_modify_power_serverinstance_virtualserver_list: the power needed
	// to modify b_serverinstance_virtualserver_list.
	NeededModifyPowerServerInstanceVirtualServerList = "i_needed_modify_power_serverinstance_virtualserver_list"
	// NeededModifyPowerServerInstanceBindingList is
	// i_needed_modify_power_serverinstance_binding_list: the power needed to
	// modify b_serverinstance_binding_list.
	NeededModifyPowerServerInstanceBindingList = "i_needed_modify_power_serverinstance_binding_list"
	// NeededModifyPowerServerInstancePermissionList is
	// i_needed_modify_power_serverinstance_permission_list: the power needed to
	// modify b_serverinstance_permission_list.
	NeededModifyPowerServerInstancePermissionList = "i_needed_modify_power_serverinstance_permission_list"
	// NeededModifyPowerServerInstancePermissionFind is
	// i_needed_modify_power_serverinstance_permission_find: the power needed to
	// modify b_serverinstance_permission_find.
	NeededModifyPowerServerInstancePermissionFind = "i_needed_modify_power_serverinstance_permission_find"
	// NeededModifyPowerVirtualServerCreate is
	// i_needed_modify_power_virtualserver_create: the power needed to modify
	// b_virtualserver_create.
	NeededModifyPowerVirtualServerCreate = "i_needed_modify_power_virtualserver_create"
	// NeededModifyPowerVirtualServerDelete is
	// i_needed_modify_power_virtualserver_delete: the power needed to modify
	// b_virtualserver_delete.
	NeededModifyPowerVirtualServerDelete = "i_needed_modify_power_virtualserver_delete"
	// NeededModifyPowerVirtualServerStartAny is
	// i_needed_modify_power_virtualserver_start_any: the power needed to modify
	// b_virtualserver_start_any.
	NeededModifyPowerVirtualServerStartAny = "i_needed_modify_power_virtualserver_start_any"
	// NeededModifyPowerVirtualServerStopAny is
	// i_needed_modify_power_virtualserver_stop_any: the power needed to modify
	// b_virtualserver_stop_any.
	NeededModifyPowerVirtualServerStopAny = "i_needed_modify_power_virtualserver_stop_any"
	// NeededModifyPowerVirtualServerChangeMachineID is
	// i_needed_modify_power_virtualserver_change_machine_id: the power needed to
	// modify b_virtualserver_change_machine_id.
	NeededModifyPowerVirtualServerChangeMachineID = "i_needed_modify_power_virtualserver_change_machine_id"
	// NeededModifyPowerVirtualServerChangeTemplate is
	// i_needed_modify_power_virtualserver_change_template: the power needed to
	// modify b_virtualserver_change_template.
	NeededModifyPowerVirtualServerChangeTemplate = "i_needed_modify_power_virtualserver_change_template"
	// NeededModifyPowerServerQueryLogin is
	// i_needed_modify_power_serverquery_login: the power needed to modify
	// b_serverquery_login.
	NeededModifyPowerServerQueryLogin = "i_needed_modify_power_serverquery_login"
	// NeededModifyPowerServerQueryLoginCreate is
	// i_needed_modify_power_serverquery_login_create: the power needed to modify
	// b_serverquery_login_create.
	NeededModifyPowerServerQueryLoginCreate = "i_needed_modify_power_serverquery_login_create"
	// NeededModifyPowerServerQueryLoginDelete is
	// i_needed_modify_power_serverquery_login_delete: the power needed to modify
	// b_serverquery_login_delete.
	NeededModifyPowerServerQueryLoginDelete = "i_needed_modify_power_serverquery_login_delete"
	// NeededModifyPowerServerQueryLoginList is
	// i_needed_modify_power_serverquery_login_list: the power needed to modify
	// b_serverquery_login_list.
	NeededModifyPowerServerQueryLoginList = "i_needed_modify_power_serverquery_login_list"
	// NeededModifyPowerServerInstanceTextMessageSend is
	// i_needed_modify_power_serverinstance_textmessage_send: the power needed to
	// modify b_serverinstance_textmessage_send.
	NeededModifyPowerServerInstanceTextMessageSend = "i_needed_modify_power_serverinstance_textmessage_send"
	// NeededModifyPowerServerInstanceLogView is
	// i_needed_modify_power_serverinstance_log_view: the power needed to modify
	// b_serverinstance_log_view.
	NeededModifyPowerServerInstanceLogView = "i_needed_modify_power_serverinstance_log_view"
	// NeededModifyPowerServerInstanceLogAdd is
	// i_needed_modify_power_serverinstance_log_add: the power needed to modify
	// b_serverinstance_log_add.
	NeededModifyPowerServerInstanceLogAdd = "i_needed_modify_power_serverinstance_log_add"
	// NeededModifyPowerServerInstanceStop is
	// i_needed_modify_power_serverinstance_stop: the power needed to modify
	// b_serverinstance_stop.
	NeededModifyPowerServerInstanceStop = "i_needed_modify_power_serverinstance_stop"
	// NeededModifyPowerServerInstanceLicenseSignMessage is
	// i_needed_modify_power_serverinstance_licensesign_message: the power needed
	// to modify b_serverinstance_licensesign_message. TeamSpeak 6 only.
	NeededModifyPowerServerInstanceLicenseSignMessage = "i_needed_modify_power_serverinstance_licensesign_message"
	// NeededModifyPowerServerInstanceModifySettings is
	// i_needed_modify_power_serverinstance_modify_settings: the power needed to
	// modify b_serverinstance_modify_settings.
	NeededModifyPowerServerInstanceModifySettings = "i_needed_modify_power_serverinstance_modify_settings"
	// NeededModifyPowerServerInstanceModifyQueryGroup is
	// i_needed_modify_power_serverinstance_modify_querygroup: the power needed to
	// modify b_serverinstance_modify_querygroup.
	NeededModifyPowerServerInstanceModifyQueryGroup = "i_needed_modify_power_serverinstance_modify_querygroup"
	// NeededModifyPowerServerInstanceModifyTemplates is
	// i_needed_modify_power_serverinstance_modify_templates: the power needed to
	// modify b_serverinstance_modify_templates.
	NeededModifyPowerServerInstanceModifyTemplates = "i_needed_modify_power_serverinstance_modify_templates"
	// NeededModifyPowerVirtualServerSelect is
	// i_needed_modify_power_virtualserver_select: the power needed to modify
	// b_virtualserver_select.
	NeededModifyPowerVirtualServerSelect = "i_needed_modify_power_virtualserver_select"
	// NeededModifyPowerVirtualServerInfoView is
	// i_needed_modify_power_virtualserver_info_view: the power needed to modify
	// b_virtualserver_info_view.
	NeededModifyPowerVirtualServerInfoView = "i_needed_modify_power_virtualserver_info_view"
	// NeededModifyPowerVirtualServerConnectionInfoView is
	// i_needed_modify_power_virtualserver_connectioninfo_view: the power needed
	// to modify b_virtualserver_connectioninfo_view.
	NeededModifyPowerVirtualServerConnectionInfoView = "i_needed_modify_power_virtualserver_connectioninfo_view"
	// NeededModifyPowerVirtualServerChannelList is
	// i_needed_modify_power_virtualserver_channel_list: the power needed to
	// modify b_virtualserver_channel_list.
	NeededModifyPowerVirtualServerChannelList = "i_needed_modify_power_virtualserver_channel_list"
	// NeededModifyPowerVirtualServerChannelSearch is
	// i_needed_modify_power_virtualserver_channel_search: the power needed to
	// modify b_virtualserver_channel_search.
	NeededModifyPowerVirtualServerChannelSearch = "i_needed_modify_power_virtualserver_channel_search"
	// NeededModifyPowerVirtualServerClientList is
	// i_needed_modify_power_virtualserver_client_list: the power needed to modify
	// b_virtualserver_client_list.
	NeededModifyPowerVirtualServerClientList = "i_needed_modify_power_virtualserver_client_list"
	// NeededModifyPowerVirtualServerClientSearch is
	// i_needed_modify_power_virtualserver_client_search: the power needed to
	// modify b_virtualserver_client_search.
	NeededModifyPowerVirtualServerClientSearch = "i_needed_modify_power_virtualserver_client_search"
	// NeededModifyPowerVirtualServerClientDBList is
	// i_needed_modify_power_virtualserver_client_dblist: the power needed to
	// modify b_virtualserver_client_dblist.
	NeededModifyPowerVirtualServerClientDBList = "i_needed_modify_power_virtualserver_client_dblist"
	// NeededModifyPowerVirtualServerClientDBSearch is
	// i_needed_modify_power_virtualserver_client_dbsearch: the power needed to
	// modify b_virtualserver_client_dbsearch.
	NeededModifyPowerVirtualServerClientDBSearch = "i_needed_modify_power_virtualserver_client_dbsearch"
	// NeededModifyPowerVirtualServerClientDBInfo is
	// i_needed_modify_power_virtualserver_client_dbinfo: the power needed to
	// modify b_virtualserver_client_dbinfo.
	NeededModifyPowerVirtualServerClientDBInfo = "i_needed_modify_power_virtualserver_client_dbinfo"
	// NeededModifyPowerVirtualServerPermissionFind is
	// i_needed_modify_power_virtualserver_permission_find: the power needed to
	// modify b_virtualserver_permission_find.
	NeededModifyPowerVirtualServerPermissionFind = "i_needed_modify_power_virtualserver_permission_find"
	// NeededModifyPowerVirtualServerCustomSearch is
	// i_needed_modify_power_virtualserver_custom_search: the power needed to
	// modify b_virtualserver_custom_search.
	NeededModifyPowerVirtualServerCustomSearch = "i_needed_modify_power_virtualserver_custom_search"
	// NeededModifyPowerVirtualServerStart is
	// i_needed_modify_power_virtualserver_start: the power needed to modify
	// b_virtualserver_start.
	NeededModifyPowerVirtualServerStart = "i_needed_modify_power_virtualserver_start"
	// NeededModifyPowerVirtualServerStop is
	// i_needed_modify_power_virtualserver_stop: the power needed to modify
	// b_virtualserver_stop.
	NeededModifyPowerVirtualServerStop = "i_needed_modify_power_virtualserver_stop"
	// NeededModifyPowerVirtualServerTokenList is
	// i_needed_modify_power_virtualserver_token_list: the power needed to modify
	// b_virtualserver_token_list.
	NeededModifyPowerVirtualServerTokenList = "i_needed_modify_power_virtualserver_token_list"
	// NeededModifyPowerVirtualServerTokenAdd is
	// i_needed_modify_power_virtualserver_token_add: the power needed to modify
	// b_virtualserver_token_add.
	NeededModifyPowerVirtualServerTokenAdd = "i_needed_modify_power_virtualserver_token_add"
	// NeededModifyPowerVirtualServerTokenUse is
	// i_needed_modify_power_virtualserver_token_use: the power needed to modify
	// b_virtualserver_token_use.
	NeededModifyPowerVirtualServerTokenUse = "i_needed_modify_power_virtualserver_token_use"
	// NeededModifyPowerVirtualServerTokenDelete is
	// i_needed_modify_power_virtualserver_token_delete: the power needed to
	// modify b_virtualserver_token_delete.
	NeededModifyPowerVirtualServerTokenDelete = "i_needed_modify_power_virtualserver_token_delete"
	// NeededModifyPowerVirtualServerAPIKeyAdd is
	// i_needed_modify_power_virtualserver_apikey_add: the power needed to modify
	// b_virtualserver_apikey_add.
	NeededModifyPowerVirtualServerAPIKeyAdd = "i_needed_modify_power_virtualserver_apikey_add"
	// NeededModifyPowerVirtualServerAPIKeyManage is
	// i_needed_modify_power_virtualserver_apikey_manage: the power needed to
	// modify b_virtualserver_apikey_manage.
	NeededModifyPowerVirtualServerAPIKeyManage = "i_needed_modify_power_virtualserver_apikey_manage"
	// NeededModifyPowerVirtualServerLogView is
	// i_needed_modify_power_virtualserver_log_view: the power needed to modify
	// b_virtualserver_log_view.
	NeededModifyPowerVirtualServerLogView = "i_needed_modify_power_virtualserver_log_view"
	// NeededModifyPowerVirtualServerLogAdd is
	// i_needed_modify_power_virtualserver_log_add: the power needed to modify
	// b_virtualserver_log_add.
	NeededModifyPowerVirtualServerLogAdd = "i_needed_modify_power_virtualserver_log_add"
	// NeededModifyPowerVirtualServerJoinIgnorePassword is
	// i_needed_modify_power_virtualserver_join_ignore_password: the power needed
	// to modify b_virtualserver_join_ignore_password.
	NeededModifyPowerVirtualServerJoinIgnorePassword = "i_needed_modify_power_virtualserver_join_ignore_password"
	// NeededModifyPowerVirtualServerNotifyRegister is
	// i_needed_modify_power_virtualserver_notify_register: the power needed to
	// modify b_virtualserver_notify_register.
	NeededModifyPowerVirtualServerNotifyRegister = "i_needed_modify_power_virtualserver_notify_register"
	// NeededModifyPowerVirtualServerNotifyUnregister is
	// i_needed_modify_power_virtualserver_notify_unregister: the power needed to
	// modify b_virtualserver_notify_unregister.
	NeededModifyPowerVirtualServerNotifyUnregister = "i_needed_modify_power_virtualserver_notify_unregister"
	// NeededModifyPowerVirtualServerSnapshotCreate is
	// i_needed_modify_power_virtualserver_snapshot_create: the power needed to
	// modify b_virtualserver_snapshot_create.
	NeededModifyPowerVirtualServerSnapshotCreate = "i_needed_modify_power_virtualserver_snapshot_create"
	// NeededModifyPowerVirtualServerSnapshotDeploy is
	// i_needed_modify_power_virtualserver_snapshot_deploy: the power needed to
	// modify b_virtualserver_snapshot_deploy.
	NeededModifyPowerVirtualServerSnapshotDeploy = "i_needed_modify_power_virtualserver_snapshot_deploy"
	// NeededModifyPowerVirtualServerPermissionReset is
	// i_needed_modify_power_virtualserver_permission_reset: the power needed to
	// modify b_virtualserver_permission_reset.
	NeededModifyPowerVirtualServerPermissionReset = "i_needed_modify_power_virtualserver_permission_reset"
	// NeededModifyPowerVirtualServerCanonicalNameManage is
	// i_needed_modify_power_virtualserver_canonical_name_manage: the power needed
	// to modify b_virtualserver_canonical_name_manage. TeamSpeak 6 only.
	NeededModifyPowerVirtualServerCanonicalNameManage = "i_needed_modify_power_virtualserver_canonical_name_manage"
	// NeededModifyPowerVirtualServerModifyName is
	// i_needed_modify_power_virtualserver_modify_name: the power needed to modify
	// b_virtualserver_modify_name.
	NeededModifyPowerVirtualServerModifyName = "i_needed_modify_power_virtualserver_modify_name"
	// NeededModifyPowerVirtualServerModifyWelcomeMessage is
	// i_needed_modify_power_virtualserver_modify_welcomemessage: the power needed
	// to modify b_virtualserver_modify_welcomemessage.
	NeededModifyPowerVirtualServerModifyWelcomeMessage = "i_needed_modify_power_virtualserver_modify_welcomemessage"
	// NeededModifyPowerVirtualServerModifyMaxClients is
	// i_needed_modify_power_virtualserver_modify_maxclients: the power needed to
	// modify b_virtualserver_modify_maxclients.
	NeededModifyPowerVirtualServerModifyMaxClients = "i_needed_modify_power_virtualserver_modify_maxclients"
	// NeededModifyPowerVirtualServerModifyReservedSlots is
	// i_needed_modify_power_virtualserver_modify_reserved_slots: the power needed
	// to modify b_virtualserver_modify_reserved_slots.
	NeededModifyPowerVirtualServerModifyReservedSlots = "i_needed_modify_power_virtualserver_modify_reserved_slots"
	// NeededModifyPowerVirtualServerModifyPassword is
	// i_needed_modify_power_virtualserver_modify_password: the power needed to
	// modify b_virtualserver_modify_password.
	NeededModifyPowerVirtualServerModifyPassword = "i_needed_modify_power_virtualserver_modify_password"
	// NeededModifyPowerVirtualServerModifyDefaultServerGroup is
	// i_needed_modify_power_virtualserver_modify_default_servergroup: the power
	// needed to modify b_virtualserver_modify_default_servergroup.
	NeededModifyPowerVirtualServerModifyDefaultServerGroup = "i_needed_modify_power_virtualserver_modify_default_servergroup"
	// NeededModifyPowerVirtualServerModifyDefaultChannelGroup is
	// i_needed_modify_power_virtualserver_modify_default_channelgroup: the power
	// needed to modify b_virtualserver_modify_default_channelgroup.
	NeededModifyPowerVirtualServerModifyDefaultChannelGroup = "i_needed_modify_power_virtualserver_modify_default_channelgroup"
	// NeededModifyPowerVirtualServerModifyDefaultChannelAdminGroup is
	// i_needed_modify_power_virtualserver_modify_default_channeladmingroup: the
	// power needed to modify b_virtualserver_modify_default_channeladmingroup.
	NeededModifyPowerVirtualServerModifyDefaultChannelAdminGroup = "i_needed_modify_power_virtualserver_modify_default_channeladmingroup"
	// NeededModifyPowerVirtualServerModifyChannelForcedSilence is
	// i_needed_modify_power_virtualserver_modify_channel_forced_silence: the
	// power needed to modify b_virtualserver_modify_channel_forced_silence.
	NeededModifyPowerVirtualServerModifyChannelForcedSilence = "i_needed_modify_power_virtualserver_modify_channel_forced_silence"
	// NeededModifyPowerVirtualServerModifyComplain is
	// i_needed_modify_power_virtualserver_modify_complain: the power needed to
	// modify b_virtualserver_modify_complain.
	NeededModifyPowerVirtualServerModifyComplain = "i_needed_modify_power_virtualserver_modify_complain"
	// NeededModifyPowerVirtualServerModifyAntiflood is
	// i_needed_modify_power_virtualserver_modify_antiflood: the power needed to
	// modify b_virtualserver_modify_antiflood.
	NeededModifyPowerVirtualServerModifyAntiflood = "i_needed_modify_power_virtualserver_modify_antiflood"
	// NeededModifyPowerVirtualServerModifyFTSettings is
	// i_needed_modify_power_virtualserver_modify_ft_settings: the power needed to
	// modify b_virtualserver_modify_ft_settings.
	NeededModifyPowerVirtualServerModifyFTSettings = "i_needed_modify_power_virtualserver_modify_ft_settings"
	// NeededModifyPowerVirtualServerModifyFTQuotas is
	// i_needed_modify_power_virtualserver_modify_ft_quotas: the power needed to
	// modify b_virtualserver_modify_ft_quotas.
	NeededModifyPowerVirtualServerModifyFTQuotas = "i_needed_modify_power_virtualserver_modify_ft_quotas"
	// NeededModifyPowerVirtualServerModifyHostMessage is
	// i_needed_modify_power_virtualserver_modify_hostmessage: the power needed to
	// modify b_virtualserver_modify_hostmessage.
	NeededModifyPowerVirtualServerModifyHostMessage = "i_needed_modify_power_virtualserver_modify_hostmessage"
	// NeededModifyPowerVirtualServerModifyHostBanner is
	// i_needed_modify_power_virtualserver_modify_hostbanner: the power needed to
	// modify b_virtualserver_modify_hostbanner.
	NeededModifyPowerVirtualServerModifyHostBanner = "i_needed_modify_power_virtualserver_modify_hostbanner"
	// NeededModifyPowerVirtualServerModifyHostButton is
	// i_needed_modify_power_virtualserver_modify_hostbutton: the power needed to
	// modify b_virtualserver_modify_hostbutton.
	NeededModifyPowerVirtualServerModifyHostButton = "i_needed_modify_power_virtualserver_modify_hostbutton"
	// NeededModifyPowerVirtualServerModifyPort is
	// i_needed_modify_power_virtualserver_modify_port: the power needed to modify
	// b_virtualserver_modify_port.
	NeededModifyPowerVirtualServerModifyPort = "i_needed_modify_power_virtualserver_modify_port"
	// NeededModifyPowerVirtualServerModifyAutoStart is
	// i_needed_modify_power_virtualserver_modify_autostart: the power needed to
	// modify b_virtualserver_modify_autostart.
	NeededModifyPowerVirtualServerModifyAutoStart = "i_needed_modify_power_virtualserver_modify_autostart"
	// NeededModifyPowerVirtualServerModifyNeededIdentitySecurityLevel is
	// i_needed_modify_power_virtualserver_modify_needed_identity_security_level:
	// the power needed to modify
	// b_virtualserver_modify_needed_identity_security_level.
	NeededModifyPowerVirtualServerModifyNeededIdentitySecurityLevel = "i_needed_modify_power_virtualserver_modify_needed_identity_security_level"
	// NeededModifyPowerVirtualServerModifyPrioritySpeakerDimmModificator is
	// i_needed_modify_power_virtualserver_modify_priority_speaker_dimm_modificator:
	// the power needed to modify
	// b_virtualserver_modify_priority_speaker_dimm_modificator.
	NeededModifyPowerVirtualServerModifyPrioritySpeakerDimmModificator = "i_needed_modify_power_virtualserver_modify_priority_speaker_dimm_modificator"
	// NeededModifyPowerVirtualServerModifyLogSettings is
	// i_needed_modify_power_virtualserver_modify_log_settings: the power needed
	// to modify b_virtualserver_modify_log_settings.
	NeededModifyPowerVirtualServerModifyLogSettings = "i_needed_modify_power_virtualserver_modify_log_settings"
	// NeededModifyPowerVirtualServerModifyMinClientVersion is
	// i_needed_modify_power_virtualserver_modify_min_client_version: the power
	// needed to modify b_virtualserver_modify_min_client_version.
	NeededModifyPowerVirtualServerModifyMinClientVersion = "i_needed_modify_power_virtualserver_modify_min_client_version"
	// NeededModifyPowerVirtualServerModifyIconID is
	// i_needed_modify_power_virtualserver_modify_icon_id: the power needed to
	// modify b_virtualserver_modify_icon_id.
	NeededModifyPowerVirtualServerModifyIconID = "i_needed_modify_power_virtualserver_modify_icon_id"
	// NeededModifyPowerVirtualServerModifyWebList is
	// i_needed_modify_power_virtualserver_modify_weblist: the power needed to
	// modify b_virtualserver_modify_weblist.
	NeededModifyPowerVirtualServerModifyWebList = "i_needed_modify_power_virtualserver_modify_weblist"
	// NeededModifyPowerVirtualServerModifyCodecEncryptionMode is
	// i_needed_modify_power_virtualserver_modify_codec_encryption_mode: the power
	// needed to modify b_virtualserver_modify_codec_encryption_mode.
	NeededModifyPowerVirtualServerModifyCodecEncryptionMode = "i_needed_modify_power_virtualserver_modify_codec_encryption_mode"
	// NeededModifyPowerVirtualServerModifyTemporaryPasswords is
	// i_needed_modify_power_virtualserver_modify_temporary_passwords: the power
	// needed to modify b_virtualserver_modify_temporary_passwords.
	NeededModifyPowerVirtualServerModifyTemporaryPasswords = "i_needed_modify_power_virtualserver_modify_temporary_passwords"
	// NeededModifyPowerVirtualServerModifyTemporaryPasswordsOwn is
	// i_needed_modify_power_virtualserver_modify_temporary_passwords_own: the
	// power needed to modify b_virtualserver_modify_temporary_passwords_own.
	NeededModifyPowerVirtualServerModifyTemporaryPasswordsOwn = "i_needed_modify_power_virtualserver_modify_temporary_passwords_own"
	// NeededModifyPowerVirtualServerModifyChannelTempDeleteDelayDefault is
	// i_needed_modify_power_virtualserver_modify_channel_temp_delete_delay_default:
	// the power needed to modify
	// b_virtualserver_modify_channel_temp_delete_delay_default.
	NeededModifyPowerVirtualServerModifyChannelTempDeleteDelayDefault = "i_needed_modify_power_virtualserver_modify_channel_temp_delete_delay_default"
	// NeededModifyPowerVirtualServerModifyNickname is
	// i_needed_modify_power_virtualserver_modify_nickname: the power needed to
	// modify b_virtualserver_modify_nickname.
	NeededModifyPowerVirtualServerModifyNickname = "i_needed_modify_power_virtualserver_modify_nickname"
	// NeededModifyPowerVirtualServerModifyIntegrations is
	// i_needed_modify_power_virtualserver_modify_integrations: the power needed
	// to modify b_virtualserver_modify_integrations.
	NeededModifyPowerVirtualServerModifyIntegrations = "i_needed_modify_power_virtualserver_modify_integrations"
	// NeededModifyPowerVirtualServerModifyMyTSIDConnect is
	// i_needed_modify_power_virtualserver_modify_mytsid_connect: the power needed
	// to modify b_virtualserver_modify_mytsid_connect. TeamSpeak 6 only.
	NeededModifyPowerVirtualServerModifyMyTSIDConnect = "i_needed_modify_power_virtualserver_modify_mytsid_connect"
	// NeededModifyPowerChannelMinDepth is
	// i_needed_modify_power_channel_min_depth: the power needed to modify
	// i_channel_min_depth.
	NeededModifyPowerChannelMinDepth = "i_needed_modify_power_channel_min_depth"
	// NeededModifyPowerChannelMaxDepth is
	// i_needed_modify_power_channel_max_depth: the power needed to modify
	// i_channel_max_depth.
	NeededModifyPowerChannelMaxDepth = "i_needed_modify_power_channel_max_depth"
	// NeededModifyPowerChannelGroupInheritanceEnd is
	// i_needed_modify_power_channel_group_inheritance_end: the power needed to
	// modify b_channel_group_inheritance_end.
	NeededModifyPowerChannelGroupInheritanceEnd = "i_needed_modify_power_channel_group_inheritance_end"
	// NeededModifyPowerChannelPermissionModifyPower is
	// i_needed_modify_power_channel_permission_modify_power: the power needed to
	// modify i_channel_permission_modify_power.
	NeededModifyPowerChannelPermissionModifyPower = "i_needed_modify_power_channel_permission_modify_power"
	// NeededModifyPowerChannelNeededPermissionModifyPower is
	// i_needed_modify_power_channel_needed_permission_modify_power: the power
	// needed to modify i_channel_needed_permission_modify_power.
	NeededModifyPowerChannelNeededPermissionModifyPower = "i_needed_modify_power_channel_needed_permission_modify_power"
	// NeededModifyPowerChannelInfoView is
	// i_needed_modify_power_channel_info_view: the power needed to modify
	// b_channel_info_view.
	NeededModifyPowerChannelInfoView = "i_needed_modify_power_channel_info_view"
	// NeededModifyPowerChannelCreateChild is
	// i_needed_modify_power_channel_create_child: the power needed to modify
	// b_channel_create_child.
	NeededModifyPowerChannelCreateChild = "i_needed_modify_power_channel_create_child"
	// NeededModifyPowerChannelCreatePermanent is
	// i_needed_modify_power_channel_create_permanent: the power needed to modify
	// b_channel_create_permanent.
	NeededModifyPowerChannelCreatePermanent = "i_needed_modify_power_channel_create_permanent"
	// NeededModifyPowerChannelCreateSemiPermanent is
	// i_needed_modify_power_channel_create_semi_permanent: the power needed to
	// modify b_channel_create_semi_permanent.
	NeededModifyPowerChannelCreateSemiPermanent = "i_needed_modify_power_channel_create_semi_permanent"
	// NeededModifyPowerChannelCreateTemporary is
	// i_needed_modify_power_channel_create_temporary: the power needed to modify
	// b_channel_create_temporary.
	NeededModifyPowerChannelCreateTemporary = "i_needed_modify_power_channel_create_temporary"
	// NeededModifyPowerChannelCreateWithTopic is
	// i_needed_modify_power_channel_create_with_topic: the power needed to modify
	// b_channel_create_with_topic.
	NeededModifyPowerChannelCreateWithTopic = "i_needed_modify_power_channel_create_with_topic"
	// NeededModifyPowerChannelCreateWithDescription is
	// i_needed_modify_power_channel_create_with_description: the power needed to
	// modify b_channel_create_with_description.
	NeededModifyPowerChannelCreateWithDescription = "i_needed_modify_power_channel_create_with_description"
	// NeededModifyPowerChannelCreateWithPassword is
	// i_needed_modify_power_channel_create_with_password: the power needed to
	// modify b_channel_create_with_password.
	NeededModifyPowerChannelCreateWithPassword = "i_needed_modify_power_channel_create_with_password"
	// NeededModifyPowerChannelCreateWithBanner is
	// i_needed_modify_power_channel_create_with_banner: the power needed to
	// modify b_channel_create_with_banner.
	NeededModifyPowerChannelCreateWithBanner = "i_needed_modify_power_channel_create_with_banner"
	// NeededModifyPowerChannelCreateModifyWithCodecOpusVoice is
	// i_needed_modify_power_channel_create_modify_with_codec_opusvoice: the power
	// needed to modify b_channel_create_modify_with_codec_opusvoice.
	NeededModifyPowerChannelCreateModifyWithCodecOpusVoice = "i_needed_modify_power_channel_create_modify_with_codec_opusvoice"
	// NeededModifyPowerChannelCreateModifyWithCodecOpusMusic is
	// i_needed_modify_power_channel_create_modify_with_codec_opusmusic: the power
	// needed to modify b_channel_create_modify_with_codec_opusmusic.
	NeededModifyPowerChannelCreateModifyWithCodecOpusMusic = "i_needed_modify_power_channel_create_modify_with_codec_opusmusic"
	// NeededModifyPowerChannelCreateModifyWithCodecMaxQuality is
	// i_needed_modify_power_channel_create_modify_with_codec_maxquality: the
	// power needed to modify i_channel_create_modify_with_codec_maxquality.
	NeededModifyPowerChannelCreateModifyWithCodecMaxQuality = "i_needed_modify_power_channel_create_modify_with_codec_maxquality"
	// NeededModifyPowerChannelCreateModifyWithCodecLatencyFactorMin is
	// i_needed_modify_power_channel_create_modify_with_codec_latency_factor_min:
	// the power needed to modify
	// i_channel_create_modify_with_codec_latency_factor_min.
	NeededModifyPowerChannelCreateModifyWithCodecLatencyFactorMin = "i_needed_modify_power_channel_create_modify_with_codec_latency_factor_min"
	// NeededModifyPowerChannelCreateWithMaxClients is
	// i_needed_modify_power_channel_create_with_maxclients: the power needed to
	// modify b_channel_create_with_maxclients.
	NeededModifyPowerChannelCreateWithMaxClients = "i_needed_modify_power_channel_create_with_maxclients"
	// NeededModifyPowerChannelCreateWithMaxFamilyClients is
	// i_needed_modify_power_channel_create_with_maxfamilyclients: the power
	// needed to modify b_channel_create_with_maxfamilyclients.
	NeededModifyPowerChannelCreateWithMaxFamilyClients = "i_needed_modify_power_channel_create_with_maxfamilyclients"
	// NeededModifyPowerChannelCreateWithSortOrder is
	// i_needed_modify_power_channel_create_with_sortorder: the power needed to
	// modify b_channel_create_with_sortorder.
	NeededModifyPowerChannelCreateWithSortOrder = "i_needed_modify_power_channel_create_with_sortorder"
	// NeededModifyPowerChannelCreateWithDefault is
	// i_needed_modify_power_channel_create_with_default: the power needed to
	// modify b_channel_create_with_default.
	NeededModifyPowerChannelCreateWithDefault = "i_needed_modify_power_channel_create_with_default"
	// NeededModifyPowerChannelCreateWithNeededTalkPower is
	// i_needed_modify_power_channel_create_with_needed_talk_power: the power
	// needed to modify b_channel_create_with_needed_talk_power.
	NeededModifyPowerChannelCreateWithNeededTalkPower = "i_needed_modify_power_channel_create_with_needed_talk_power"
	// NeededModifyPowerChannelCreateModifyWithForcePassword is
	// i_needed_modify_power_channel_create_modify_with_force_password: the power
	// needed to modify b_channel_create_modify_with_force_password.
	NeededModifyPowerChannelCreateModifyWithForcePassword = "i_needed_modify_power_channel_create_modify_with_force_password"
	// NeededModifyPowerChannelCreateModifyWithTempDeleteDelay is
	// i_needed_modify_power_channel_create_modify_with_temp_delete_delay: the
	// power needed to modify i_channel_create_modify_with_temp_delete_delay.
	NeededModifyPowerChannelCreateModifyWithTempDeleteDelay = "i_needed_modify_power_channel_create_modify_with_temp_delete_delay"
	// NeededModifyPowerChannelModifyParent is
	// i_needed_modify_power_channel_modify_parent: the power needed to modify
	// b_channel_modify_parent.
	NeededModifyPowerChannelModifyParent = "i_needed_modify_power_channel_modify_parent"
	// NeededModifyPowerChannelModifyMakeDefault is
	// i_needed_modify_power_channel_modify_make_default: the power needed to
	// modify b_channel_modify_make_default.
	NeededModifyPowerChannelModifyMakeDefault = "i_needed_modify_power_channel_modify_make_default"
	// NeededModifyPowerChannelModifyMakePermanent is
	// i_needed_modify_power_channel_modify_make_permanent: the power needed to
	// modify b_channel_modify_make_permanent.
	NeededModifyPowerChannelModifyMakePermanent = "i_needed_modify_power_channel_modify_make_permanent"
	// NeededModifyPowerChannelModifyMakeSemiPermanent is
	// i_needed_modify_power_channel_modify_make_semi_permanent: the power needed
	// to modify b_channel_modify_make_semi_permanent.
	NeededModifyPowerChannelModifyMakeSemiPermanent = "i_needed_modify_power_channel_modify_make_semi_permanent"
	// NeededModifyPowerChannelModifyMakeTemporary is
	// i_needed_modify_power_channel_modify_make_temporary: the power needed to
	// modify b_channel_modify_make_temporary.
	NeededModifyPowerChannelModifyMakeTemporary = "i_needed_modify_power_channel_modify_make_temporary"
	// NeededModifyPowerChannelModifyName is
	// i_needed_modify_power_channel_modify_name: the power needed to modify
	// b_channel_modify_name.
	NeededModifyPowerChannelModifyName = "i_needed_modify_power_channel_modify_name"
	// NeededModifyPowerChannelModifyTopic is
	// i_needed_modify_power_channel_modify_topic: the power needed to modify
	// b_channel_modify_topic.
	NeededModifyPowerChannelModifyTopic = "i_needed_modify_power_channel_modify_topic"
	// NeededModifyPowerChannelModifyDescription is
	// i_needed_modify_power_channel_modify_description: the power needed to
	// modify b_channel_modify_description.
	NeededModifyPowerChannelModifyDescription = "i_needed_modify_power_channel_modify_description"
	// NeededModifyPowerChannelModifyPassword is
	// i_needed_modify_power_channel_modify_password: the power needed to modify
	// b_channel_modify_password.
	NeededModifyPowerChannelModifyPassword = "i_needed_modify_power_channel_modify_password"
	// NeededModifyPowerChannelModifyBanner is
	// i_needed_modify_power_channel_modify_banner: the power needed to modify
	// b_channel_modify_banner.
	NeededModifyPowerChannelModifyBanner = "i_needed_modify_power_channel_modify_banner"
	// NeededModifyPowerChannelModifyCodec is
	// i_needed_modify_power_channel_modify_codec: the power needed to modify
	// b_channel_modify_codec.
	NeededModifyPowerChannelModifyCodec = "i_needed_modify_power_channel_modify_codec"
	// NeededModifyPowerChannelModifyCodecQuality is
	// i_needed_modify_power_channel_modify_codec_quality: the power needed to
	// modify b_channel_modify_codec_quality.
	NeededModifyPowerChannelModifyCodecQuality = "i_needed_modify_power_channel_modify_codec_quality"
	// NeededModifyPowerChannelModifyCodecLatencyFactor is
	// i_needed_modify_power_channel_modify_codec_latency_factor: the power needed
	// to modify b_channel_modify_codec_latency_factor.
	NeededModifyPowerChannelModifyCodecLatencyFactor = "i_needed_modify_power_channel_modify_codec_latency_factor"
	// NeededModifyPowerChannelModifyMaxClients is
	// i_needed_modify_power_channel_modify_maxclients: the power needed to modify
	// b_channel_modify_maxclients.
	NeededModifyPowerChannelModifyMaxClients = "i_needed_modify_power_channel_modify_maxclients"
	// NeededModifyPowerChannelModifyMaxFamilyClients is
	// i_needed_modify_power_channel_modify_maxfamilyclients: the power needed to
	// modify b_channel_modify_maxfamilyclients.
	NeededModifyPowerChannelModifyMaxFamilyClients = "i_needed_modify_power_channel_modify_maxfamilyclients"
	// NeededModifyPowerChannelModifySortOrder is
	// i_needed_modify_power_channel_modify_sortorder: the power needed to modify
	// b_channel_modify_sortorder.
	NeededModifyPowerChannelModifySortOrder = "i_needed_modify_power_channel_modify_sortorder"
	// NeededModifyPowerChannelModifyNeededTalkPower is
	// i_needed_modify_power_channel_modify_needed_talk_power: the power needed to
	// modify b_channel_modify_needed_talk_power.
	NeededModifyPowerChannelModifyNeededTalkPower = "i_needed_modify_power_channel_modify_needed_talk_power"
	// NeededModifyPowerChannelModifyPower is
	// i_needed_modify_power_channel_modify_power: the power needed to modify
	// i_channel_modify_power.
	NeededModifyPowerChannelModifyPower = "i_needed_modify_power_channel_modify_power"
	// NeededModifyPowerChannelNeededModifyPower is
	// i_needed_modify_power_channel_needed_modify_power: the power needed to
	// modify i_channel_needed_modify_power.
	NeededModifyPowerChannelNeededModifyPower = "i_needed_modify_power_channel_needed_modify_power"
	// NeededModifyPowerChannelModifyMakeCodecEncrypted is
	// i_needed_modify_power_channel_modify_make_codec_encrypted: the power needed
	// to modify b_channel_modify_make_codec_encrypted.
	NeededModifyPowerChannelModifyMakeCodecEncrypted = "i_needed_modify_power_channel_modify_make_codec_encrypted"
	// NeededModifyPowerChannelModifyTempDeleteDelay is
	// i_needed_modify_power_channel_modify_temp_delete_delay: the power needed to
	// modify b_channel_modify_temp_delete_delay.
	NeededModifyPowerChannelModifyTempDeleteDelay = "i_needed_modify_power_channel_modify_temp_delete_delay"
	// NeededModifyPowerChannelModifyFTQuotas is
	// i_needed_modify_power_channel_modify_ft_quotas: the power needed to modify
	// b_channel_modify_ft_quotas. TeamSpeak 6 only.
	NeededModifyPowerChannelModifyFTQuotas = "i_needed_modify_power_channel_modify_ft_quotas"
	// NeededModifyPowerChannelDeletePermanent is
	// i_needed_modify_power_channel_delete_permanent: the power needed to modify
	// b_channel_delete_permanent.
	NeededModifyPowerChannelDeletePermanent = "i_needed_modify_power_channel_delete_permanent"
	// NeededModifyPowerChannelDeleteSemiPermanent is
	// i_needed_modify_power_channel_delete_semi_permanent: the power needed to
	// modify b_channel_delete_semi_permanent.
	NeededModifyPowerChannelDeleteSemiPermanent = "i_needed_modify_power_channel_delete_semi_permanent"
	// NeededModifyPowerChannelDeleteTemporary is
	// i_needed_modify_power_channel_delete_temporary: the power needed to modify
	// b_channel_delete_temporary.
	NeededModifyPowerChannelDeleteTemporary = "i_needed_modify_power_channel_delete_temporary"
	// NeededModifyPowerChannelDeleteFlagForce is
	// i_needed_modify_power_channel_delete_flag_force: the power needed to modify
	// b_channel_delete_flag_force.
	NeededModifyPowerChannelDeleteFlagForce = "i_needed_modify_power_channel_delete_flag_force"
	// NeededModifyPowerChannelDeletePower is
	// i_needed_modify_power_channel_delete_power: the power needed to modify
	// i_channel_delete_power.
	NeededModifyPowerChannelDeletePower = "i_needed_modify_power_channel_delete_power"
	// NeededModifyPowerChannelNeededDeletePower is
	// i_needed_modify_power_channel_needed_delete_power: the power needed to
	// modify i_channel_needed_delete_power.
	NeededModifyPowerChannelNeededDeletePower = "i_needed_modify_power_channel_needed_delete_power"
	// NeededModifyPowerChannelJoinPermanent is
	// i_needed_modify_power_channel_join_permanent: the power needed to modify
	// b_channel_join_permanent.
	NeededModifyPowerChannelJoinPermanent = "i_needed_modify_power_channel_join_permanent"
	// NeededModifyPowerChannelJoinSemiPermanent is
	// i_needed_modify_power_channel_join_semi_permanent: the power needed to
	// modify b_channel_join_semi_permanent.
	NeededModifyPowerChannelJoinSemiPermanent = "i_needed_modify_power_channel_join_semi_permanent"
	// NeededModifyPowerChannelJoinTemporary is
	// i_needed_modify_power_channel_join_temporary: the power needed to modify
	// b_channel_join_temporary.
	NeededModifyPowerChannelJoinTemporary = "i_needed_modify_power_channel_join_temporary"
	// NeededModifyPowerChannelJoinIgnorePassword is
	// i_needed_modify_power_channel_join_ignore_password: the power needed to
	// modify b_channel_join_ignore_password.
	NeededModifyPowerChannelJoinIgnorePassword = "i_needed_modify_power_channel_join_ignore_password"
	// NeededModifyPowerChannelJoinIgnoreMaxClients is
	// i_needed_modify_power_channel_join_ignore_maxclients: the power needed to
	// modify b_channel_join_ignore_maxclients.
	NeededModifyPowerChannelJoinIgnoreMaxClients = "i_needed_modify_power_channel_join_ignore_maxclients"
	// NeededModifyPowerChannelJoinPower is
	// i_needed_modify_power_channel_join_power: the power needed to modify
	// i_channel_join_power.
	NeededModifyPowerChannelJoinPower = "i_needed_modify_power_channel_join_power"
	// NeededModifyPowerChannelNeededJoinPower is
	// i_needed_modify_power_channel_needed_join_power: the power needed to modify
	// i_channel_needed_join_power.
	NeededModifyPowerChannelNeededJoinPower = "i_needed_modify_power_channel_needed_join_power"
	// NeededModifyPowerChannelSubscribePower is
	// i_needed_modify_power_channel_subscribe_power: the power needed to modify
	// i_channel_subscribe_power.
	NeededModifyPowerChannelSubscribePower = "i_needed_modify_power_channel_subscribe_power"
	// NeededModifyPowerChannelNeededSubscribePower is
	// i_needed_modify_power_channel_needed_subscribe_power: the power needed to
	// modify i_channel_needed_subscribe_power.
	NeededModifyPowerChannelNeededSubscribePower = "i_needed_modify_power_channel_needed_subscribe_power"
	// NeededModifyPowerChannelDescriptionViewPower is
	// i_needed_modify_power_channel_description_view_power: the power needed to
	// modify i_channel_description_view_power.
	NeededModifyPowerChannelDescriptionViewPower = "i_needed_modify_power_channel_description_view_power"
	// NeededModifyPowerChannelNeededDescriptionViewPower is
	// i_needed_modify_power_channel_needed_description_view_power: the power
	// needed to modify i_channel_needed_description_view_power.
	NeededModifyPowerChannelNeededDescriptionViewPower = "i_needed_modify_power_channel_needed_description_view_power"
	// NeededModifyPowerIconID is i_needed_modify_power_icon_id: the power needed
	// to modify i_icon_id.
	NeededModifyPowerIconID = "i_needed_modify_power_icon_id"
	// NeededModifyPowerMaxIconFileSize is
	// i_needed_modify_power_max_icon_filesize: the power needed to modify
	// i_max_icon_filesize.
	NeededModifyPowerMaxIconFileSize = "i_needed_modify_power_max_icon_filesize"
	// NeededModifyPowerIconManage is i_needed_modify_power_icon_manage: the power
	// needed to modify b_icon_manage.
	NeededModifyPowerIconManage = "i_needed_modify_power_icon_manage"
	// NeededModifyPowerGroupIsPermanent is
	// i_needed_modify_power_group_is_permanent: the power needed to modify
	// b_group_is_permanent.
	NeededModifyPowerGroupIsPermanent = "i_needed_modify_power_group_is_permanent"
	// NeededModifyPowerGroupAutoUpdateType is
	// i_needed_modify_power_group_auto_update_type: the power needed to modify
	// i_group_auto_update_type.
	NeededModifyPowerGroupAutoUpdateType = "i_needed_modify_power_group_auto_update_type"
	// NeededModifyPowerGroupAutoUpdateMaxValue is
	// i_needed_modify_power_group_auto_update_max_value: the power needed to
	// modify i_group_auto_update_max_value.
	NeededModifyPowerGroupAutoUpdateMaxValue = "i_needed_modify_power_group_auto_update_max_value"
	// NeededModifyPowerGroupSortID is i_needed_modify_power_group_sort_id: the
	// power needed to modify i_group_sort_id.
	NeededModifyPowerGroupSortID = "i_needed_modify_power_group_sort_id"
	// NeededModifyPowerGroupShowNameInTree is
	// i_needed_modify_power_group_show_name_in_tree: the power needed to modify
	// i_group_show_name_in_tree.
	NeededModifyPowerGroupShowNameInTree = "i_needed_modify_power_group_show_name_in_tree"
	// NeededModifyPowerVirtualServerServerGroupList is
	// i_needed_modify_power_virtualserver_servergroup_list: the power needed to
	// modify b_virtualserver_servergroup_list.
	NeededModifyPowerVirtualServerServerGroupList = "i_needed_modify_power_virtualserver_servergroup_list"
	// NeededModifyPowerVirtualServerServerGroupPermissionList is
	// i_needed_modify_power_virtualserver_servergroup_permission_list: the power
	// needed to modify b_virtualserver_servergroup_permission_list.
	NeededModifyPowerVirtualServerServerGroupPermissionList = "i_needed_modify_power_virtualserver_servergroup_permission_list"
	// NeededModifyPowerVirtualServerServerGroupClientList is
	// i_needed_modify_power_virtualserver_servergroup_client_list: the power
	// needed to modify b_virtualserver_servergroup_client_list.
	NeededModifyPowerVirtualServerServerGroupClientList = "i_needed_modify_power_virtualserver_servergroup_client_list"
	// NeededModifyPowerVirtualServerChannelGroupList is
	// i_needed_modify_power_virtualserver_channelgroup_list: the power needed to
	// modify b_virtualserver_channelgroup_list.
	NeededModifyPowerVirtualServerChannelGroupList = "i_needed_modify_power_virtualserver_channelgroup_list"
	// NeededModifyPowerVirtualServerChannelGroupPermissionList is
	// i_needed_modify_power_virtualserver_channelgroup_permission_list: the power
	// needed to modify b_virtualserver_channelgroup_permission_list.
	NeededModifyPowerVirtualServerChannelGroupPermissionList = "i_needed_modify_power_virtualserver_channelgroup_permission_list"
	// NeededModifyPowerVirtualServerChannelGroupClientList is
	// i_needed_modify_power_virtualserver_channelgroup_client_list: the power
	// needed to modify b_virtualserver_channelgroup_client_list.
	NeededModifyPowerVirtualServerChannelGroupClientList = "i_needed_modify_power_virtualserver_channelgroup_client_list"
	// NeededModifyPowerVirtualServerClientPermissionList is
	// i_needed_modify_power_virtualserver_client_permission_list: the power
	// needed to modify b_virtualserver_client_permission_list.
	NeededModifyPowerVirtualServerClientPermissionList = "i_needed_modify_power_virtualserver_client_permission_list"
	// NeededModifyPowerVirtualServerChannelPermissionList is
	// i_needed_modify_power_virtualserver_channel_permission_list: the power
	// needed to modify b_virtualserver_channel_permission_list.
	NeededModifyPowerVirtualServerChannelPermissionList = "i_needed_modify_power_virtualserver_channel_permission_list"
	// NeededModifyPowerVirtualServerChannelClientPermissionList is
	// i_needed_modify_power_virtualserver_channelclient_permission_list: the
	// power needed to modify b_virtualserver_channelclient_permission_list.
	NeededModifyPowerVirtualServerChannelClientPermissionList = "i_needed_modify_power_virtualserver_channelclient_permission_list"
	// NeededModifyPowerVirtualServerServerGroupCreate is
	// i_needed_modify_power_virtualserver_servergroup_create: the power needed to
	// modify b_virtualserver_servergroup_create.
	NeededModifyPowerVirtualServerServerGroupCreate = "i_needed_modify_power_virtualserver_servergroup_create"
	// NeededModifyPowerVirtualServerChannelGroupCreate is
	// i_needed_modify_power_virtualserver_channelgroup_create: the power needed
	// to modify b_virtualserver_channelgroup_create.
	NeededModifyPowerVirtualServerChannelGroupCreate = "i_needed_modify_power_virtualserver_channelgroup_create"
	// NeededModifyPowerGroupModifyPower is
	// i_needed_modify_power_group_modify_power: the power needed to modify
	// i_group_modify_power.
	NeededModifyPowerGroupModifyPower = "i_needed_modify_power_group_modify_power"
	// NeededModifyPowerGroupNeededModifyPower is
	// i_needed_modify_power_group_needed_modify_power: the power needed to modify
	// i_group_needed_modify_power.
	NeededModifyPowerGroupNeededModifyPower = "i_needed_modify_power_group_needed_modify_power"
	// NeededModifyPowerGroupMemberAddPower is
	// i_needed_modify_power_group_member_add_power: the power needed to modify
	// i_group_member_add_power.
	NeededModifyPowerGroupMemberAddPower = "i_needed_modify_power_group_member_add_power"
	// NeededModifyPowerGroupNeededMemberAddPower is
	// i_needed_modify_power_group_needed_member_add_power: the power needed to
	// modify i_group_needed_member_add_power.
	NeededModifyPowerGroupNeededMemberAddPower = "i_needed_modify_power_group_needed_member_add_power"
	// NeededModifyPowerGroupMemberRemovePower is
	// i_needed_modify_power_group_member_remove_power: the power needed to modify
	// i_group_member_remove_power.
	NeededModifyPowerGroupMemberRemovePower = "i_needed_modify_power_group_member_remove_power"
	// NeededModifyPowerGroupNeededMemberRemovePower is
	// i_needed_modify_power_group_needed_member_remove_power: the power needed to
	// modify i_group_needed_member_remove_power.
	NeededModifyPowerGroupNeededMemberRemovePower = "i_needed_modify_power_group_needed_member_remove_power"
	// NeededModifyPowerPermissionModifyPower is
	// i_needed_modify_power_permission_modify_power: the power needed to modify
	// i_permission_modify_power.
	NeededModifyPowerPermissionModifyPower = "i_needed_modify_power_permission_modify_power"
	// NeededModifyPowerPermissionModifyPowerIgnore is
	// i_needed_modify_power_permission_modify_power_ignore: the power needed to
	// modify b_permission_modify_power_ignore.
	NeededModifyPowerPermissionModifyPowerIgnore = "i_needed_modify_power_permission_modify_power_ignore"
	// NeededModifyPowerVirtualServerServerGroupDelete is
	// i_needed_modify_power_virtualserver_servergroup_delete: the power needed to
	// modify b_virtualserver_servergroup_delete.
	NeededModifyPowerVirtualServerServerGroupDelete = "i_needed_modify_power_virtualserver_servergroup_delete"
	// NeededModifyPowerVirtualServerChannelGroupDelete is
	// i_needed_modify_power_virtualserver_channelgroup_delete: the power needed
	// to modify b_virtualserver_channelgroup_delete.
	NeededModifyPowerVirtualServerChannelGroupDelete = "i_needed_modify_power_virtualserver_channelgroup_delete"
	// NeededModifyPowerClientPermissionModifyPower is
	// i_needed_modify_power_client_permission_modify_power: the power needed to
	// modify i_client_permission_modify_power.
	NeededModifyPowerClientPermissionModifyPower = "i_needed_modify_power_client_permission_modify_power"
	// NeededModifyPowerClientNeededPermissionModifyPower is
	// i_needed_modify_power_client_needed_permission_modify_power: the power
	// needed to modify i_client_needed_permission_modify_power.
	NeededModifyPowerClientNeededPermissionModifyPower = "i_needed_modify_power_client_needed_permission_modify_power"
	// NeededModifyPowerClientMaxClonesUID is
	// i_needed_modify_power_client_max_clones_uid: the power needed to modify
	// i_client_max_clones_uid.
	NeededModifyPowerClientMaxClonesUID = "i_needed_modify_power_client_max_clones_uid"
	// NeededModifyPowerClientMaxIdleTime is
	// i_needed_modify_power_client_max_idletime: the power needed to modify
	// i_client_max_idletime.
	NeededModifyPowerClientMaxIdleTime = "i_needed_modify_power_client_max_idletime"
	// NeededModifyPowerClientMaxAvatarFileSize is
	// i_needed_modify_power_client_max_avatar_filesize: the power needed to
	// modify i_client_max_avatar_filesize.
	NeededModifyPowerClientMaxAvatarFileSize = "i_needed_modify_power_client_max_avatar_filesize"
	// NeededModifyPowerClientMaxChannelSubscriptions is
	// i_needed_modify_power_client_max_channel_subscriptions: the power needed to
	// modify i_client_max_channel_subscriptions.
	NeededModifyPowerClientMaxChannelSubscriptions = "i_needed_modify_power_client_max_channel_subscriptions"
	// NeededModifyPowerClientIsPrioritySpeaker is
	// i_needed_modify_power_client_is_priority_speaker: the power needed to
	// modify b_client_is_priority_speaker.
	NeededModifyPowerClientIsPrioritySpeaker = "i_needed_modify_power_client_is_priority_speaker"
	// NeededModifyPowerClientSkipChannelGroupPermissions is
	// i_needed_modify_power_client_skip_channelgroup_permissions: the power
	// needed to modify b_client_skip_channelgroup_permissions.
	NeededModifyPowerClientSkipChannelGroupPermissions = "i_needed_modify_power_client_skip_channelgroup_permissions"
	// NeededModifyPowerClientForcePushToTalk is
	// i_needed_modify_power_client_force_push_to_talk: the power needed to modify
	// b_client_force_push_to_talk.
	NeededModifyPowerClientForcePushToTalk = "i_needed_modify_power_client_force_push_to_talk"
	// NeededModifyPowerClientIgnoreBans is
	// i_needed_modify_power_client_ignore_bans: the power needed to modify
	// b_client_ignore_bans.
	NeededModifyPowerClientIgnoreBans = "i_needed_modify_power_client_ignore_bans"
	// NeededModifyPowerClientIgnoreAntiflood is
	// i_needed_modify_power_client_ignore_antiflood: the power needed to modify
	// b_client_ignore_antiflood.
	NeededModifyPowerClientIgnoreAntiflood = "i_needed_modify_power_client_ignore_antiflood"
	// NeededModifyPowerClientUseReservedSlot is
	// i_needed_modify_power_client_use_reserved_slot: the power needed to modify
	// b_client_use_reserved_slot.
	NeededModifyPowerClientUseReservedSlot = "i_needed_modify_power_client_use_reserved_slot"
	// NeededModifyPowerClientUseChannelCommander is
	// i_needed_modify_power_client_use_channel_commander: the power needed to
	// modify b_client_use_channel_commander.
	NeededModifyPowerClientUseChannelCommander = "i_needed_modify_power_client_use_channel_commander"
	// NeededModifyPowerClientRequestTalker is
	// i_needed_modify_power_client_request_talker: the power needed to modify
	// b_client_request_talker.
	NeededModifyPowerClientRequestTalker = "i_needed_modify_power_client_request_talker"
	// NeededModifyPowerClientAvatarDeleteOther is
	// i_needed_modify_power_client_avatar_delete_other: the power needed to
	// modify b_client_avatar_delete_other.
	NeededModifyPowerClientAvatarDeleteOther = "i_needed_modify_power_client_avatar_delete_other"
	// NeededModifyPowerClientIsSticky is i_needed_modify_power_client_is_sticky:
	// the power needed to modify b_client_is_sticky.
	NeededModifyPowerClientIsSticky = "i_needed_modify_power_client_is_sticky"
	// NeededModifyPowerClientIgnoreSticky is
	// i_needed_modify_power_client_ignore_sticky: the power needed to modify
	// b_client_ignore_sticky.
	NeededModifyPowerClientIgnoreSticky = "i_needed_modify_power_client_ignore_sticky"
	// NeededModifyPowerClientInfoView is i_needed_modify_power_client_info_view:
	// the power needed to modify b_client_info_view.
	NeededModifyPowerClientInfoView = "i_needed_modify_power_client_info_view"
	// NeededModifyPowerClientPermissionOverviewView is
	// i_needed_modify_power_client_permissionoverview_view: the power needed to
	// modify b_client_permissionoverview_view.
	NeededModifyPowerClientPermissionOverviewView = "i_needed_modify_power_client_permissionoverview_view"
	// NeededModifyPowerClientPermissionOverviewOwn is
	// i_needed_modify_power_client_permissionoverview_own: the power needed to
	// modify b_client_permissionoverview_own.
	NeededModifyPowerClientPermissionOverviewOwn = "i_needed_modify_power_client_permissionoverview_own"
	// NeededModifyPowerClientRemoteAddressView is
	// i_needed_modify_power_client_remoteaddress_view: the power needed to modify
	// b_client_remoteaddress_view.
	NeededModifyPowerClientRemoteAddressView = "i_needed_modify_power_client_remoteaddress_view"
	// NeededModifyPowerClientServerQueryViewPower is
	// i_needed_modify_power_client_serverquery_view_power: the power needed to
	// modify i_client_serverquery_view_power.
	NeededModifyPowerClientServerQueryViewPower = "i_needed_modify_power_client_serverquery_view_power"
	// NeededModifyPowerClientNeededServerQueryViewPower is
	// i_needed_modify_power_client_needed_serverquery_view_power: the power
	// needed to modify i_client_needed_serverquery_view_power.
	NeededModifyPowerClientNeededServerQueryViewPower = "i_needed_modify_power_client_needed_serverquery_view_power"
	// NeededModifyPowerClientCustomInfoView is
	// i_needed_modify_power_client_custom_info_view: the power needed to modify
	// b_client_custom_info_view.
	NeededModifyPowerClientCustomInfoView = "i_needed_modify_power_client_custom_info_view"
	// NeededModifyPowerClientKickFromServerPower is
	// i_needed_modify_power_client_kick_from_server_power: the power needed to
	// modify i_client_kick_from_server_power.
	NeededModifyPowerClientKickFromServerPower = "i_needed_modify_power_client_kick_from_server_power"
	// NeededModifyPowerClientNeededKickFromServerPower is
	// i_needed_modify_power_client_needed_kick_from_server_power: the power
	// needed to modify i_client_needed_kick_from_server_power.
	NeededModifyPowerClientNeededKickFromServerPower = "i_needed_modify_power_client_needed_kick_from_server_power"
	// NeededModifyPowerClientKickFromChannelPower is
	// i_needed_modify_power_client_kick_from_channel_power: the power needed to
	// modify i_client_kick_from_channel_power.
	NeededModifyPowerClientKickFromChannelPower = "i_needed_modify_power_client_kick_from_channel_power"
	// NeededModifyPowerClientNeededKickFromChannelPower is
	// i_needed_modify_power_client_needed_kick_from_channel_power: the power
	// needed to modify i_client_needed_kick_from_channel_power.
	NeededModifyPowerClientNeededKickFromChannelPower = "i_needed_modify_power_client_needed_kick_from_channel_power"
	// NeededModifyPowerClientBanPower is i_needed_modify_power_client_ban_power:
	// the power needed to modify i_client_ban_power.
	NeededModifyPowerClientBanPower = "i_needed_modify_power_client_ban_power"
	// NeededModifyPowerClientNeededBanPower is
	// i_needed_modify_power_client_needed_ban_power: the power needed to modify
	// i_client_needed_ban_power.
	NeededModifyPowerClientNeededBanPower = "i_needed_modify_power_client_needed_ban_power"
	// NeededModifyPowerClientMovePower is
	// i_needed_modify_power_client_move_power: the power needed to modify
	// i_client_move_power.
	NeededModifyPowerClientMovePower = "i_needed_modify_power_client_move_power"
	// NeededModifyPowerClientNeededMovePower is
	// i_needed_modify_power_client_needed_move_power: the power needed to modify
	// i_client_needed_move_power.
	NeededModifyPowerClientNeededMovePower = "i_needed_modify_power_client_needed_move_power"
	// NeededModifyPowerClientComplainPower is
	// i_needed_modify_power_client_complain_power: the power needed to modify
	// i_client_complain_power.
	NeededModifyPowerClientComplainPower = "i_needed_modify_power_client_complain_power"
	// NeededModifyPowerClientNeededComplainPower is
	// i_needed_modify_power_client_needed_complain_power: the power needed to
	// modify i_client_needed_complain_power.
	NeededModifyPowerClientNeededComplainPower = "i_needed_modify_power_client_needed_complain_power"
	// NeededModifyPowerClientComplainList is
	// i_needed_modify_power_client_complain_list: the power needed to modify
	// b_client_complain_list.
	NeededModifyPowerClientComplainList = "i_needed_modify_power_client_complain_list"
	// NeededModifyPowerClientComplainDeleteOwn is
	// i_needed_modify_power_client_complain_delete_own: the power needed to
	// modify b_client_complain_delete_own.
	NeededModifyPowerClientComplainDeleteOwn = "i_needed_modify_power_client_complain_delete_own"
	// NeededModifyPowerClientComplainDelete is
	// i_needed_modify_power_client_complain_delete: the power needed to modify
	// b_client_complain_delete.
	NeededModifyPowerClientComplainDelete = "i_needed_modify_power_client_complain_delete"
	// NeededModifyPowerClientBanList is i_needed_modify_power_client_ban_list:
	// the power needed to modify b_client_ban_list.
	NeededModifyPowerClientBanList = "i_needed_modify_power_client_ban_list"
	// NeededModifyPowerClientBanCreate is
	// i_needed_modify_power_client_ban_create: the power needed to modify
	// b_client_ban_create.
	NeededModifyPowerClientBanCreate = "i_needed_modify_power_client_ban_create"
	// NeededModifyPowerClientBanDeleteOwn is
	// i_needed_modify_power_client_ban_delete_own: the power needed to modify
	// b_client_ban_delete_own.
	NeededModifyPowerClientBanDeleteOwn = "i_needed_modify_power_client_ban_delete_own"
	// NeededModifyPowerClientBanDelete is
	// i_needed_modify_power_client_ban_delete: the power needed to modify
	// b_client_ban_delete.
	NeededModifyPowerClientBanDelete = "i_needed_modify_power_client_ban_delete"
	// NeededModifyPowerClientBanMaxBanTime is
	// i_needed_modify_power_client_ban_max_bantime: the power needed to modify
	// i_client_ban_max_bantime.
	NeededModifyPowerClientBanMaxBanTime = "i_needed_modify_power_client_ban_max_bantime"
	// NeededModifyPowerChannelTextMessageDelete is
	// i_needed_modify_power_channel_textmessage_delete: the power needed to
	// modify b_channel_textmessage_delete. TeamSpeak 6 only.
	NeededModifyPowerChannelTextMessageDelete = "i_needed_modify_power_channel_textmessage_delete"
	// NeededModifyPowerClientPrivateTextMessagePower is
	// i_needed_modify_power_client_private_textmessage_power: the power needed to
	// modify i_client_private_textmessage_power.
	NeededModifyPowerClientPrivateTextMessagePower = "i_needed_modify_power_client_private_textmessage_power"
	// NeededModifyPowerClientNeededPrivateTextMessagePower is
	// i_needed_modify_power_client_needed_private_textmessage_power: the power
	// needed to modify i_client_needed_private_textmessage_power.
	NeededModifyPowerClientNeededPrivateTextMessagePower = "i_needed_modify_power_client_needed_private_textmessage_power"
	// NeededModifyPowerClientServerTextMessageSend is
	// i_needed_modify_power_client_server_textmessage_send: the power needed to
	// modify b_client_server_textmessage_send.
	NeededModifyPowerClientServerTextMessageSend = "i_needed_modify_power_client_server_textmessage_send"
	// NeededModifyPowerClientChannelTextMessageSend is
	// i_needed_modify_power_client_channel_textmessage_send: the power needed to
	// modify b_client_channel_textmessage_send.
	NeededModifyPowerClientChannelTextMessageSend = "i_needed_modify_power_client_channel_textmessage_send"
	// NeededModifyPowerClientOfflineTextMessageSend is
	// i_needed_modify_power_client_offline_textmessage_send: the power needed to
	// modify b_client_offline_textmessage_send.
	NeededModifyPowerClientOfflineTextMessageSend = "i_needed_modify_power_client_offline_textmessage_send"
	// NeededModifyPowerClientTalkPower is
	// i_needed_modify_power_client_talk_power: the power needed to modify
	// i_client_talk_power.
	NeededModifyPowerClientTalkPower = "i_needed_modify_power_client_talk_power"
	// NeededModifyPowerClientNeededTalkPower is
	// i_needed_modify_power_client_needed_talk_power: the power needed to modify
	// i_client_needed_talk_power.
	NeededModifyPowerClientNeededTalkPower = "i_needed_modify_power_client_needed_talk_power"
	// NeededModifyPowerClientPokePower is
	// i_needed_modify_power_client_poke_power: the power needed to modify
	// i_client_poke_power.
	NeededModifyPowerClientPokePower = "i_needed_modify_power_client_poke_power"
	// NeededModifyPowerClientNeededPokePower is
	// i_needed_modify_power_client_needed_poke_power: the power needed to modify
	// i_client_needed_poke_power.
	NeededModifyPowerClientNeededPokePower = "i_needed_modify_power_client_needed_poke_power"
	// NeededModifyPowerClientSetFlagTalker is
	// i_needed_modify_power_client_set_flag_talker: the power needed to modify
	// b_client_set_flag_talker.
	NeededModifyPowerClientSetFlagTalker = "i_needed_modify_power_client_set_flag_talker"
	// NeededModifyPowerClientWhisperPower is
	// i_needed_modify_power_client_whisper_power: the power needed to modify
	// i_client_whisper_power.
	NeededModifyPowerClientWhisperPower = "i_needed_modify_power_client_whisper_power"
	// NeededModifyPowerClientNeededWhisperPower is
	// i_needed_modify_power_client_needed_whisper_power: the power needed to
	// modify i_client_needed_whisper_power.
	NeededModifyPowerClientNeededWhisperPower = "i_needed_modify_power_client_needed_whisper_power"
	// NeededModifyPowerClientModifyDescription is
	// i_needed_modify_power_client_modify_description: the power needed to modify
	// b_client_modify_description.
	NeededModifyPowerClientModifyDescription = "i_needed_modify_power_client_modify_description"
	// NeededModifyPowerClientModifyOwnDescription is
	// i_needed_modify_power_client_modify_own_description: the power needed to
	// modify b_client_modify_own_description.
	NeededModifyPowerClientModifyOwnDescription = "i_needed_modify_power_client_modify_own_description"
	// NeededModifyPowerClientModifyDBProperties is
	// i_needed_modify_power_client_modify_dbproperties: the power needed to
	// modify b_client_modify_dbproperties.
	NeededModifyPowerClientModifyDBProperties = "i_needed_modify_power_client_modify_dbproperties"
	// NeededModifyPowerClientDeleteDBProperties is
	// i_needed_modify_power_client_delete_dbproperties: the power needed to
	// modify b_client_delete_dbproperties.
	NeededModifyPowerClientDeleteDBProperties = "i_needed_modify_power_client_delete_dbproperties"
	// NeededModifyPowerClientCreateModifyServerQueryLogin is
	// i_needed_modify_power_client_create_modify_serverquery_login: the power
	// needed to modify b_client_create_modify_serverquery_login.
	NeededModifyPowerClientCreateModifyServerQueryLogin = "i_needed_modify_power_client_create_modify_serverquery_login"
	// NeededModifyPowerFTIgnorePassword is
	// i_needed_modify_power_ft_ignore_password: the power needed to modify
	// b_ft_ignore_password.
	NeededModifyPowerFTIgnorePassword = "i_needed_modify_power_ft_ignore_password"
	// NeededModifyPowerFTTransferList is i_needed_modify_power_ft_transfer_list:
	// the power needed to modify b_ft_transfer_list.
	NeededModifyPowerFTTransferList = "i_needed_modify_power_ft_transfer_list"
	// NeededModifyPowerFTFileUploadPower is
	// i_needed_modify_power_ft_file_upload_power: the power needed to modify
	// i_ft_file_upload_power.
	NeededModifyPowerFTFileUploadPower = "i_needed_modify_power_ft_file_upload_power"
	// NeededModifyPowerFTNeededFileUploadPower is
	// i_needed_modify_power_ft_needed_file_upload_power: the power needed to
	// modify i_ft_needed_file_upload_power.
	NeededModifyPowerFTNeededFileUploadPower = "i_needed_modify_power_ft_needed_file_upload_power"
	// NeededModifyPowerFTFileDownloadPower is
	// i_needed_modify_power_ft_file_download_power: the power needed to modify
	// i_ft_file_download_power.
	NeededModifyPowerFTFileDownloadPower = "i_needed_modify_power_ft_file_download_power"
	// NeededModifyPowerFTNeededFileDownloadPower is
	// i_needed_modify_power_ft_needed_file_download_power: the power needed to
	// modify i_ft_needed_file_download_power.
	NeededModifyPowerFTNeededFileDownloadPower = "i_needed_modify_power_ft_needed_file_download_power"
	// NeededModifyPowerFTFileDeletePower is
	// i_needed_modify_power_ft_file_delete_power: the power needed to modify
	// i_ft_file_delete_power.
	NeededModifyPowerFTFileDeletePower = "i_needed_modify_power_ft_file_delete_power"
	// NeededModifyPowerFTNeededFileDeletePower is
	// i_needed_modify_power_ft_needed_file_delete_power: the power needed to
	// modify i_ft_needed_file_delete_power.
	NeededModifyPowerFTNeededFileDeletePower = "i_needed_modify_power_ft_needed_file_delete_power"
	// NeededModifyPowerFTFileRenamePower is
	// i_needed_modify_power_ft_file_rename_power: the power needed to modify
	// i_ft_file_rename_power.
	NeededModifyPowerFTFileRenamePower = "i_needed_modify_power_ft_file_rename_power"
	// NeededModifyPowerFTNeededFileRenamePower is
	// i_needed_modify_power_ft_needed_file_rename_power: the power needed to
	// modify i_ft_needed_file_rename_power.
	NeededModifyPowerFTNeededFileRenamePower = "i_needed_modify_power_ft_needed_file_rename_power"
	// NeededModifyPowerFTFileBrowsePower is
	// i_needed_modify_power_ft_file_browse_power: the power needed to modify
	// i_ft_file_browse_power.
	NeededModifyPowerFTFileBrowsePower = "i_needed_modify_power_ft_file_browse_power"
	// NeededModifyPowerFTNeededFileBrowsePower is
	// i_needed_modify_power_ft_needed_file_browse_power: the power needed to
	// modify i_ft_needed_file_browse_power.
	NeededModifyPowerFTNeededFileBrowsePower = "i_needed_modify_power_ft_needed_file_browse_power"
	// NeededModifyPowerFTDirectoryCreatePower is
	// i_needed_modify_power_ft_directory_create_power: the power needed to modify
	// i_ft_directory_create_power.
	NeededModifyPowerFTDirectoryCreatePower = "i_needed_modify_power_ft_directory_create_power"
	// NeededModifyPowerFTNeededDirectoryCreatePower is
	// i_needed_modify_power_ft_needed_directory_create_power: the power needed to
	// modify i_ft_needed_directory_create_power.
	NeededModifyPowerFTNeededDirectoryCreatePower = "i_needed_modify_power_ft_needed_directory_create_power"
	// NeededModifyPowerFTQuotaMBDownloadPerClient is
	// i_needed_modify_power_ft_quota_mb_download_per_client: the power needed to
	// modify i_ft_quota_mb_download_per_client.
	NeededModifyPowerFTQuotaMBDownloadPerClient = "i_needed_modify_power_ft_quota_mb_download_per_client"
	// NeededModifyPowerFTQuotaMBUploadPerClient is
	// i_needed_modify_power_ft_quota_mb_upload_per_client: the power needed to
	// modify i_ft_quota_mb_upload_per_client.
	NeededModifyPowerFTQuotaMBUploadPerClient = "i_needed_modify_power_ft_quota_mb_upload_per_client"
	// NeededModifyPowerFTStorageMBPerClient is
	// i_needed_modify_power_ft_storage_mb_per_client: the power needed to modify
	// i_ft_storage_mb_per_client. TeamSpeak 6 only.
	NeededModifyPowerFTStorageMBPerClient = "i_needed_modify_power_ft_storage_mb_per_client"
	// NeededModifyPowerFTMaxFileSizeMB is
	// i_needed_modify_power_ft_max_file_size_mb: the power needed to modify
	// i_ft_max_file_size_mb. TeamSpeak 6 only.
	NeededModifyPowerFTMaxFileSizeMB = "i_needed_modify_power_ft_max_file_size_mb"
)
