// Package perm names the permissions a TeamSpeak server checks, for
// teamspeak.PermissionByName:
//
//	c.AddChannelPermission(ctx, cid, teamspeak.PermissionByName(perm.ClientNeededTalkPower), 50)
//
// The constants are the names TeamSpeak 3.13 and 6 servers list, in the order
// they list them, measured with permissionlist; the seven marked TeamSpeak 6
// only are missing on TeamSpeak 3. A name starting b_ is a switch, granted or
// not; one starting i_ is a value, such as a power compared with a needed
// power. A server may know permissions this list does not, which is why
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
