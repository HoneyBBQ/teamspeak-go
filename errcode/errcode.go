// Package errcode names the error codes a TeamSpeak server reports.
//
// Each Code is also an error, and a teamspeak.ServerError unwraps to its code,
// so a caller matches a specific refusal with errors.Is:
//
//	if errors.Is(err, errcode.PermissionsClientInsufficient) { ... }
//
// The codes are the ones TeamSpeak 3 and 6 servers share.
package errcode

import "strconv"

// Code is a TeamSpeak server error code.
type Code uint32

// Error returns the server's own wording for the code.
func (c Code) Error() string {
	if msg, ok := messages[c]; ok {
		return msg
	}

	return "error " + strconv.FormatUint(uint64(c), 10)
}

// String is the same as Error.
func (c Code) String() string {
	return c.Error()
}

// The codes.
const (
	// OK is success: the server answers "error id=0 msg=ok".
	OK Code = 0x0000
	// Undefined is "undefined error".
	Undefined Code = 0x0001
	// NotImplemented is "not implemented".
	NotImplemented Code = 0x0002
	// OKNoUpdate has no known message.
	OKNoUpdate Code = 0x0003
	// DontNotify has no known message.
	DontNotify Code = 0x0004
	// LibTimeLimitReached is "library time limit reached".
	LibTimeLimitReached Code = 0x0005
	// CommandNotFound is "command not found".
	CommandNotFound Code = 0x0100
	// UnableToBindNetworkPort is "unable to bind network port".
	UnableToBindNetworkPort Code = 0x0101
	// NoNetworkPortAvailable is "no network port available".
	NoNetworkPortAvailable Code = 0x0102
	// ClientInvalidID is "invalid clientID".
	ClientInvalidID Code = 0x0200
	// ClientNicknameInUse is "nickname is already in use".
	ClientNicknameInUse Code = 0x0201
	// ClientInvalidErrorCode is "invalid error code".
	ClientInvalidErrorCode Code = 0x0202
	// ClientProtocolLimitReached is "max clients protocol limit reached".
	ClientProtocolLimitReached Code = 0x0203
	// ClientInvalidType is "invalid client type".
	ClientInvalidType Code = 0x0204
	// ClientAlreadySubscribed is "already subscribed".
	ClientAlreadySubscribed Code = 0x0205
	// ClientNotLoggedIn is "not logged in".
	ClientNotLoggedIn Code = 0x0206
	// ClientCouldNotValidateIdentity is "could not validate client identity".
	ClientCouldNotValidateIdentity Code = 0x0207
	// ClientInvalidPassword is "invalid loginname or password".
	ClientInvalidPassword Code = 0x0208
	// ClientTooManyClonesConnected is "too many clones already connected".
	ClientTooManyClonesConnected Code = 0x0209
	// ClientVersionOutdated is "client version outdated, please update".
	ClientVersionOutdated Code = 0x020a
	// ClientIsOnline is "client is online".
	ClientIsOnline Code = 0x020b
	// ClientIsFlooding is "client is flooding".
	ClientIsFlooding Code = 0x020c
	// ClientHacked is "client is modified".
	ClientHacked Code = 0x020d
	// ClientCannotVerifyNow is "can not verify client at this moment".
	ClientCannotVerifyNow Code = 0x020e
	// ClientLoginNotPermitted is "client is not permitted to log in".
	ClientLoginNotPermitted Code = 0x020f
	// ClientNotSubscribed is "client is not subscribed to the channel".
	ClientNotSubscribed Code = 0x0210
	// ChannelInvalidID is "invalid channelID".
	ChannelInvalidID Code = 0x0300
	// ChannelProtocolLimitReached is "max channels protocol limit reached".
	ChannelProtocolLimitReached Code = 0x0301
	// ChannelAlreadyIn is "already member of channel".
	ChannelAlreadyIn Code = 0x0302
	// ChannelNameInUse is "channel name is already in use".
	ChannelNameInUse Code = 0x0303
	// ChannelNotEmpty is "channel not empty".
	ChannelNotEmpty Code = 0x0304
	// ChannelCanNotDeleteDefault is "can not delete default channel".
	ChannelCanNotDeleteDefault Code = 0x0305
	// ChannelDefaultRequirePermanent is "default channel requires permanent".
	ChannelDefaultRequirePermanent Code = 0x0306
	// ChannelInvalidFlags is "invalid channel flags".
	ChannelInvalidFlags Code = 0x0307
	// ChannelParentNotPermanent is "permanent channel can not be child of non permanent channel".
	ChannelParentNotPermanent Code = 0x0308
	// ChannelMaxClientsReached is "channel maxclient reached".
	ChannelMaxClientsReached Code = 0x0309
	// ChannelMaxFamilyReached is "channel maxfamily reached".
	ChannelMaxFamilyReached Code = 0x030a
	// ChannelInvalidOrder is "invalid channel order".
	ChannelInvalidOrder Code = 0x030b
	// ChannelNoFileTransferSupported is "channel does not support filetransfers".
	ChannelNoFileTransferSupported Code = 0x030c
	// ChannelInvalidPassword is "invalid channel password".
	ChannelInvalidPassword Code = 0x030d
	// ChannelIsPrivateChannel is "channel is private channel".
	ChannelIsPrivateChannel Code = 0x030e
	// ChannelInvalidSecurityHash is "invalid security hash supplied by client".
	ChannelInvalidSecurityHash Code = 0x030f
	// ServerInvalidID is "invalid serverID".
	ServerInvalidID Code = 0x0400
	// ServerRunning is "server is running".
	ServerRunning Code = 0x0401
	// ServerIsShuttingDown is "server is shutting down".
	ServerIsShuttingDown Code = 0x0402
	// ServerMaxClientsReached is "server maxclient reached".
	ServerMaxClientsReached Code = 0x0403
	// ServerInvalidPassword is "invalid server password".
	ServerInvalidPassword Code = 0x0404
	// ServerDeploymentActive is "deployment active".
	ServerDeploymentActive Code = 0x0405
	// ServerUnableToStopOwnServer is "unable to stop own server in your connection class".
	ServerUnableToStopOwnServer Code = 0x0406
	// ServerIsVirtual is "server is virtual".
	ServerIsVirtual Code = 0x0407
	// ServerWrongMachineID is "server wrong machineID".
	ServerWrongMachineID Code = 0x0408
	// ServerIsNotRunning is "server is not running".
	ServerIsNotRunning Code = 0x0409
	// ServerIsBooting is "server is booting up".
	ServerIsBooting Code = 0x040a
	// ServerStatusInvalid is "server got an invalid status for this operation".
	ServerStatusInvalid Code = 0x040b
	// ServerModalQuit is "server modal quit".
	ServerModalQuit Code = 0x040c
	// ServerVersionOutdated is "server version is too old for command".
	ServerVersionOutdated Code = 0x040d
	// Database is "database error".
	Database Code = 0x0500
	// DatabaseEmptyResult is "database empty result set".
	DatabaseEmptyResult Code = 0x0501
	// DatabaseDuplicateEntry is "database duplicate entry".
	DatabaseDuplicateEntry Code = 0x0502
	// DatabaseNoModifications is "database no modifications".
	DatabaseNoModifications Code = 0x0503
	// DatabaseConstraint is "database invalid constraint".
	DatabaseConstraint Code = 0x0504
	// DatabaseReinvoke is "database reinvoke command".
	DatabaseReinvoke Code = 0x0505
	// ParameterQuote is "invalid quote".
	ParameterQuote Code = 0x0600
	// ParameterInvalidCount is "invalid parameter count".
	ParameterInvalidCount Code = 0x0601
	// ParameterInvalid is "invalid parameter".
	ParameterInvalid Code = 0x0602
	// ParameterNotFound is "parameter not found".
	ParameterNotFound Code = 0x0603
	// ParameterConvert is "convert error".
	ParameterConvert Code = 0x0604
	// ParameterInvalidSize is "invalid parameter size".
	ParameterInvalidSize Code = 0x0605
	// ParameterMissing is "missing required parameter".
	ParameterMissing Code = 0x0606
	// ParameterChecksum is "invalid checksum".
	ParameterChecksum Code = 0x0607
	// VsCritical is "virtual server got a critical error".
	VsCritical Code = 0x0700
	// ConnectionLost is "Connection lost".
	ConnectionLost Code = 0x0701
	// NotConnected is "not connected".
	NotConnected Code = 0x0702
	// NoCachedConnectionInfo is "no cached connection info".
	NoCachedConnectionInfo Code = 0x0703
	// CurrentlyNotPossible is "currently not possible".
	CurrentlyNotPossible Code = 0x0704
	// FailedConnectionInitialisation is "failed connection initialization".
	FailedConnectionInitialisation Code = 0x0705
	// CouldNotResolveHostname is "could not resolve hostname".
	CouldNotResolveHostname Code = 0x0706
	// InvalidServerConnectionHandlerID is "invalid server connection handler ID".
	InvalidServerConnectionHandlerID Code = 0x0707
	// CouldNotInitialiseInputManager is "could not initialize Input Manager".
	CouldNotInitialiseInputManager Code = 0x0708
	// ClientLibraryNotInitialised is "client library not initialized".
	ClientLibraryNotInitialised Code = 0x0709
	// ServerLibraryNotInitialised is "server library not initialized".
	ServerLibraryNotInitialised Code = 0x070a
	// WhisperTooManyTargets is "too many whisper targets".
	WhisperTooManyTargets Code = 0x070b
	// WhisperNoTargets is "no whisper targets found".
	WhisperNoTargets Code = 0x070c
	// FileInvalidName is "invalid file name".
	FileInvalidName Code = 0x0800
	// FileInvalidPermissions is "invalid file permissions".
	FileInvalidPermissions Code = 0x0801
	// FileAlreadyExists is "file already exists".
	FileAlreadyExists Code = 0x0802
	// FileNotFound is "file not found".
	FileNotFound Code = 0x0803
	// FileIOError is "file input/output error".
	FileIOError Code = 0x0804
	// FileInvalidTransferID is "invalid file transfer ID".
	FileInvalidTransferID Code = 0x0805
	// FileInvalidPath is "invalid file path".
	FileInvalidPath Code = 0x0806
	// FileNoFilesAvailable is "no files available".
	FileNoFilesAvailable Code = 0x0807
	// FileOverwriteExcludesResume is "overwrite excludes resume".
	FileOverwriteExcludesResume Code = 0x0808
	// FileInvalidSize is "invalid file size".
	FileInvalidSize Code = 0x0809
	// FileAlreadyInUse is "file already in use".
	FileAlreadyInUse Code = 0x080a
	// FileCouldNotOpenConnection is "could not open file transfer connection".
	FileCouldNotOpenConnection Code = 0x080b
	// FileNoSpaceLeftOnDevice is "no space left on device (disk full?)".
	FileNoSpaceLeftOnDevice Code = 0x080c
	// FileExceedsFileSystemMaximumSize is "file exceeds file system's maximum file size".
	FileExceedsFileSystemMaximumSize Code = 0x080d
	// FileTransferConnectionTimeout is "file transfer connection timeout".
	FileTransferConnectionTimeout Code = 0x080e
	// FileConnectionLost is "lost file transfer connection".
	FileConnectionLost Code = 0x080f
	// FileExceedsSuppliedSize is "file exceeds supplied file size".
	FileExceedsSuppliedSize Code = 0x0810
	// FileTransferComplete is "file transfer complete".
	FileTransferComplete Code = 0x0811
	// FileTransferCanceled is "file transfer canceled".
	FileTransferCanceled Code = 0x0812
	// FileTransferInterrupted is "file transfer interrupted".
	FileTransferInterrupted Code = 0x0813
	// FileTransferServerQuotaExceeded is "file transfer server quota exceeded".
	FileTransferServerQuotaExceeded Code = 0x0814
	// FileTransferClientQuotaExceeded is "file transfer client quota exceeded".
	FileTransferClientQuotaExceeded Code = 0x0815
	// FileTransferReset is "file transfer reset".
	FileTransferReset Code = 0x0816
	// FileTransferLimitReached is "file transfer limit reached".
	FileTransferLimitReached Code = 0x0817
	// SoundPreprocessorDisabled is "preprocessor disabled".
	SoundPreprocessorDisabled Code = 0x0900
	// SoundInternalPreprocessor is "internal preprocessor".
	SoundInternalPreprocessor Code = 0x0901
	// SoundInternalEncoder is "internal encoder".
	SoundInternalEncoder Code = 0x0902
	// SoundInternalPlayback is "internal playback".
	SoundInternalPlayback Code = 0x0903
	// SoundNoCaptureDeviceAvailable is "no capture device available".
	SoundNoCaptureDeviceAvailable Code = 0x0904
	// SoundNoPlaybackDeviceAvailable is "no playback device available".
	SoundNoPlaybackDeviceAvailable Code = 0x0905
	// SoundCouldNotOpenCaptureDevice is "could not open capture device".
	SoundCouldNotOpenCaptureDevice Code = 0x0906
	// SoundCouldNotOpenPlaybackDevice is "could not open playback device".
	SoundCouldNotOpenPlaybackDevice Code = 0x0907
	// SoundHandlerHasDevice is "ServerConnectionHandler has a device registered".
	SoundHandlerHasDevice Code = 0x0908
	// SoundInvalidCaptureDevice is "invalid capture device".
	SoundInvalidCaptureDevice Code = 0x0909
	// SoundInvalidPlaybackDevice is "invalid clayback device".
	SoundInvalidPlaybackDevice Code = 0x090a
	// SoundInvalidWave is "invalid wave file".
	SoundInvalidWave Code = 0x090b
	// SoundUnsupportedWave is "wave file type not supported".
	SoundUnsupportedWave Code = 0x090c
	// SoundOpenWave is "could not open wave file".
	SoundOpenWave Code = 0x090d
	// SoundInternalCapture is "internal capture".
	SoundInternalCapture Code = 0x090e
	// SoundDeviceInUse is "device still in use".
	SoundDeviceInUse Code = 0x090f
	// SoundDeviceAlreadyRegistered is "device already registered".
	SoundDeviceAlreadyRegistered Code = 0x0910
	// SoundUnknownDevice is "device not registered/known".
	SoundUnknownDevice Code = 0x0911
	// SoundUnsupportedFrequency is "unsupported frequency".
	SoundUnsupportedFrequency Code = 0x0912
	// SoundInvalidChannelCount is "invalid channel count".
	SoundInvalidChannelCount Code = 0x0913
	// SoundReadWave is "read error in wave".
	SoundReadWave Code = 0x0914
	// SoundNeedMoreData is "sound need more data".
	SoundNeedMoreData Code = 0x0915
	// SoundDeviceBusy is "sound device was busy".
	SoundDeviceBusy Code = 0x0916
	// SoundNoData is "there is no sound data for this period".
	SoundNoData Code = 0x0917
	// SoundChannelMaskMismatch is "Channelmask set bits count (speakers) is not the same as (count)".
	SoundChannelMaskMismatch Code = 0x0918
	// PermissionInvalidGroupID is "invalid group ID".
	PermissionInvalidGroupID Code = 0x0a00
	// PermissionDuplicateEntry is "duplicate entry".
	PermissionDuplicateEntry Code = 0x0a01
	// PermissionInvalidPermID is "invalid permission ID".
	PermissionInvalidPermID Code = 0x0a02
	// PermissionEmptyResult is "empty result set".
	PermissionEmptyResult Code = 0x0a03
	// PermissionDefaultGroupForbidden is "access to default group is forbidden".
	PermissionDefaultGroupForbidden Code = 0x0a04
	// PermissionInvalidSize is "invalid size".
	PermissionInvalidSize Code = 0x0a05
	// PermissionInvalidValue is "invalid value".
	PermissionInvalidValue Code = 0x0a06
	// PermissionsGroupNotEmpty is "group is not empty".
	PermissionsGroupNotEmpty Code = 0x0a07
	// PermissionsClientInsufficient is "insufficient client permissions".
	PermissionsClientInsufficient Code = 0x0a08
	// PermissionsInsufficientGroupPower is "insufficient group modify power".
	PermissionsInsufficientGroupPower Code = 0x0a09
	// PermissionsInsufficientPermissionPower is "insufficient permission modify power".
	PermissionsInsufficientPermissionPower Code = 0x0a0a
	// PermissionTemplateGroupIsUsed is "template group is currently used".
	PermissionTemplateGroupIsUsed Code = 0x0a0b
	// Permissions is "permission error".
	Permissions Code = 0x0a0c
	// AccountingVirtualServerLimitReached is "virtualserver limit reached".
	AccountingVirtualServerLimitReached Code = 0x0b00
	// AccountingSlotLimitReached is "max slot limit reached".
	AccountingSlotLimitReached Code = 0x0b01
	// AccountingLicenseFileNotFound is "license file not found".
	AccountingLicenseFileNotFound Code = 0x0b02
	// AccountingLicenseDateNotOK is "license date not ok".
	AccountingLicenseDateNotOK Code = 0x0b03
	// AccountingUnableToConnectToServer is "unable to connect to accounting server".
	AccountingUnableToConnectToServer Code = 0x0b04
	// AccountingUnknownError is "unknown accounting error".
	AccountingUnknownError Code = 0x0b05
	// AccountingServerError is "accounting server error".
	AccountingServerError Code = 0x0b06
	// AccountingInstanceLimitReached is "instance limit reached".
	AccountingInstanceLimitReached Code = 0x0b07
	// AccountingInstanceCheckError is "instance check error".
	AccountingInstanceCheckError Code = 0x0b08
	// AccountingLicenseFileInvalid is "license file invalid".
	AccountingLicenseFileInvalid Code = 0x0b09
	// AccountingRunningElsewhere is "virtualserver is running elsewhere".
	AccountingRunningElsewhere Code = 0x0b0a
	// AccountingInstanceDuplicated is "virtualserver running in same instance already".
	AccountingInstanceDuplicated Code = 0x0b0b
	// AccountingAlreadyStarted is "virtualserver already started".
	AccountingAlreadyStarted Code = 0x0b0c
	// AccountingNotStarted is "virtualserver not started".
	AccountingNotStarted Code = 0x0b0d
	// AccountingTooManyStarts has no known message.
	AccountingTooManyStarts Code = 0x0b0e
	// MessageInvalidID is "invalid message id".
	MessageInvalidID Code = 0x0c00
	// BanInvalidID is "invalid ban id".
	BanInvalidID Code = 0x0d00
	// ConnectFailedBanned is "connection failed, you are banned".
	ConnectFailedBanned Code = 0x0d01
	// RenameFailedBanned is "rename failed, new name is banned".
	RenameFailedBanned Code = 0x0d02
	// BanFlooding is "flood ban".
	BanFlooding Code = 0x0d03
	// TTSUnableToInitialize is "unable to initialize tts".
	TTSUnableToInitialize Code = 0x0e00
	// PrivilegeKeyInvalid is "invalid privilege key".
	PrivilegeKeyInvalid Code = 0x0f00
	// VoipPjsua has no known message.
	VoipPjsua Code = 0x1000
	// VoipAlreadyInitialized has no known message.
	VoipAlreadyInitialized Code = 0x1001
	// VoipTooManyAccounts has no known message.
	VoipTooManyAccounts Code = 0x1002
	// VoipInvalidAccount has no known message.
	VoipInvalidAccount Code = 0x1003
	// VoipInternalError has no known message.
	VoipInternalError Code = 0x1004
	// VoipInvalidConnectionID has no known message.
	VoipInvalidConnectionID Code = 0x1005
	// VoipCannotAnswerInitiatedCall has no known message.
	VoipCannotAnswerInitiatedCall Code = 0x1006
	// VoipNotInitialized has no known message.
	VoipNotInitialized Code = 0x1007
	// ProvisioningInvalidPassword is "invalid password".
	ProvisioningInvalidPassword Code = 0x1100
	// ProvisioningInvalidRequest is "invalid request".
	ProvisioningInvalidRequest Code = 0x1101
	// ProvisioningNoSlotsAvailable is "no(more) slots available".
	ProvisioningNoSlotsAvailable Code = 0x1102
	// ProvisioningPoolMissing is "pool missing".
	ProvisioningPoolMissing Code = 0x1103
	// ProvisioningPoolUnknown is "pool unknown".
	ProvisioningPoolUnknown Code = 0x1104
	// ProvisioningUnknownIPLocation is "unknown ip location(perhaps LAN ip?)".
	ProvisioningUnknownIPLocation Code = 0x1105
	// ProvisioningInternalTriesExceeded is "internal error(tried exceeded)".
	ProvisioningInternalTriesExceeded Code = 0x1106
	// ProvisioningTooManySlotsRequested is "too many slots requested".
	ProvisioningTooManySlotsRequested Code = 0x1107
	// ProvisioningTooManyReserved is "too many reserved".
	ProvisioningTooManyReserved Code = 0x1108
	// ProvisioningCouldNotConnect is "could not connect to provisioning server".
	ProvisioningCouldNotConnect Code = 0x1109
	// ProvisioningAuthServerNotConnected is "authentication server not connected".
	ProvisioningAuthServerNotConnected Code = 0x1110
	// ProvisioningAuthDataTooLarge is "authentication data too large".
	ProvisioningAuthDataTooLarge Code = 0x1111
	// ProvisioningAlreadyInitialized is "already initialized".
	ProvisioningAlreadyInitialized Code = 0x1112
	// ProvisioningNotInitialized is "not initialized".
	ProvisioningNotInitialized Code = 0x1113
	// ProvisioningConnecting is "already connecting".
	ProvisioningConnecting Code = 0x1114
	// ProvisioningAlreadyConnected is "already connected".
	ProvisioningAlreadyConnected Code = 0x1115
	// ProvisioningNotConnected has no known message.
	ProvisioningNotConnected Code = 0x1116
	// ProvisioningIOError is "io_error".
	ProvisioningIOError Code = 0x1117
	// ProvisioningInvalidTimeout has no known message.
	ProvisioningInvalidTimeout Code = 0x1118
	// ProvisioningTS3ServerNotFound has no known message.
	ProvisioningTS3ServerNotFound Code = 0x1119
	// ProvisioningNoPermission is "unknown permissionID".
	ProvisioningNoPermission Code = 0x111A
	// APIKeyOutOfScope is "out of scope": WebQuery refused a command outside the
	// scope of the api key that made the request, or outside the guest scope of
	// a request that carried none. The HTTP status is 401.
	APIKeyOutOfScope Code = 0x1400
	// APIKeyInvalid is "invalid apikey": WebQuery does not accept the api key
	// sent, or the key may not address the virtual server in the path. The HTTP
	// status is 401.
	APIKeyInvalid Code = 0x1402
	// APIKeyMissing is "missing apikey": the request carried no api key, or an
	// empty one, and the server offers no guest access. The HTTP status is 401.
	APIKeyMissing Code = 0x1404
)

var messages = map[Code]string{
	OK:                                     "ok",
	Undefined:                              "undefined error",
	NotImplemented:                         "not implemented",
	LibTimeLimitReached:                    "library time limit reached",
	CommandNotFound:                        "command not found",
	UnableToBindNetworkPort:                "unable to bind network port",
	NoNetworkPortAvailable:                 "no network port available",
	ClientInvalidID:                        "invalid clientID",
	ClientNicknameInUse:                    "nickname is already in use",
	ClientInvalidErrorCode:                 "invalid error code",
	ClientProtocolLimitReached:             "max clients protocol limit reached",
	ClientInvalidType:                      "invalid client type",
	ClientAlreadySubscribed:                "already subscribed",
	ClientNotLoggedIn:                      "not logged in",
	ClientCouldNotValidateIdentity:         "could not validate client identity",
	ClientInvalidPassword:                  "invalid loginname or password",
	ClientTooManyClonesConnected:           "too many clones already connected",
	ClientVersionOutdated:                  "client version outdated, please update",
	ClientIsOnline:                         "client is online",
	ClientIsFlooding:                       "client is flooding",
	ClientHacked:                           "client is modified",
	ClientCannotVerifyNow:                  "can not verify client at this moment",
	ClientLoginNotPermitted:                "client is not permitted to log in",
	ClientNotSubscribed:                    "client is not subscribed to the channel",
	ChannelInvalidID:                       "invalid channelID",
	ChannelProtocolLimitReached:            "max channels protocol limit reached",
	ChannelAlreadyIn:                       "already member of channel",
	ChannelNameInUse:                       "channel name is already in use",
	ChannelNotEmpty:                        "channel not empty",
	ChannelCanNotDeleteDefault:             "can not delete default channel",
	ChannelDefaultRequirePermanent:         "default channel requires permanent",
	ChannelInvalidFlags:                    "invalid channel flags",
	ChannelParentNotPermanent:              "permanent channel can not be child of non permanent channel",
	ChannelMaxClientsReached:               "channel maxclient reached",
	ChannelMaxFamilyReached:                "channel maxfamily reached",
	ChannelInvalidOrder:                    "invalid channel order",
	ChannelNoFileTransferSupported:         "channel does not support filetransfers",
	ChannelInvalidPassword:                 "invalid channel password",
	ChannelIsPrivateChannel:                "channel is private channel",
	ChannelInvalidSecurityHash:             "invalid security hash supplied by client",
	ServerInvalidID:                        "invalid serverID",
	ServerRunning:                          "server is running",
	ServerIsShuttingDown:                   "server is shutting down",
	ServerMaxClientsReached:                "server maxclient reached",
	ServerInvalidPassword:                  "invalid server password",
	ServerDeploymentActive:                 "deployment active",
	ServerUnableToStopOwnServer:            "unable to stop own server in your connection class",
	ServerIsVirtual:                        "server is virtual",
	ServerWrongMachineID:                   "server wrong machineID",
	ServerIsNotRunning:                     "server is not running",
	ServerIsBooting:                        "server is booting up",
	ServerStatusInvalid:                    "server got an invalid status for this operation",
	ServerModalQuit:                        "server modal quit",
	ServerVersionOutdated:                  "server version is too old for command",
	Database:                               "database error",
	DatabaseEmptyResult:                    "database empty result set",
	DatabaseDuplicateEntry:                 "database duplicate entry",
	DatabaseNoModifications:                "database no modifications",
	DatabaseConstraint:                     "database invalid constraint",
	DatabaseReinvoke:                       "database reinvoke command",
	ParameterQuote:                         "invalid quote",
	ParameterInvalidCount:                  "invalid parameter count",
	ParameterInvalid:                       "invalid parameter",
	ParameterNotFound:                      "parameter not found",
	ParameterConvert:                       "convert error",
	ParameterInvalidSize:                   "invalid parameter size",
	ParameterMissing:                       "missing required parameter",
	ParameterChecksum:                      "invalid checksum",
	VsCritical:                             "virtual server got a critical error",
	ConnectionLost:                         "Connection lost",
	NotConnected:                           "not connected",
	NoCachedConnectionInfo:                 "no cached connection info",
	CurrentlyNotPossible:                   "currently not possible",
	FailedConnectionInitialisation:         "failed connection initialization",
	CouldNotResolveHostname:                "could not resolve hostname",
	InvalidServerConnectionHandlerID:       "invalid server connection handler ID",
	CouldNotInitialiseInputManager:         "could not initialize Input Manager",
	ClientLibraryNotInitialised:            "client library not initialized",
	ServerLibraryNotInitialised:            "server library not initialized",
	WhisperTooManyTargets:                  "too many whisper targets",
	WhisperNoTargets:                       "no whisper targets found",
	FileInvalidName:                        "invalid file name",
	FileInvalidPermissions:                 "invalid file permissions",
	FileAlreadyExists:                      "file already exists",
	FileNotFound:                           "file not found",
	FileIOError:                            "file input/output error",
	FileInvalidTransferID:                  "invalid file transfer ID",
	FileInvalidPath:                        "invalid file path",
	FileNoFilesAvailable:                   "no files available",
	FileOverwriteExcludesResume:            "overwrite excludes resume",
	FileInvalidSize:                        "invalid file size",
	FileAlreadyInUse:                       "file already in use",
	FileCouldNotOpenConnection:             "could not open file transfer connection",
	FileNoSpaceLeftOnDevice:                "no space left on device (disk full?)",
	FileExceedsFileSystemMaximumSize:       "file exceeds file system's maximum file size",
	FileTransferConnectionTimeout:          "file transfer connection timeout",
	FileConnectionLost:                     "lost file transfer connection",
	FileExceedsSuppliedSize:                "file exceeds supplied file size",
	FileTransferComplete:                   "file transfer complete",
	FileTransferCanceled:                   "file transfer canceled",
	FileTransferInterrupted:                "file transfer interrupted",
	FileTransferServerQuotaExceeded:        "file transfer server quota exceeded",
	FileTransferClientQuotaExceeded:        "file transfer client quota exceeded",
	FileTransferReset:                      "file transfer reset",
	FileTransferLimitReached:               "file transfer limit reached",
	SoundPreprocessorDisabled:              "preprocessor disabled",
	SoundInternalPreprocessor:              "internal preprocessor",
	SoundInternalEncoder:                   "internal encoder",
	SoundInternalPlayback:                  "internal playback",
	SoundNoCaptureDeviceAvailable:          "no capture device available",
	SoundNoPlaybackDeviceAvailable:         "no playback device available",
	SoundCouldNotOpenCaptureDevice:         "could not open capture device",
	SoundCouldNotOpenPlaybackDevice:        "could not open playback device",
	SoundHandlerHasDevice:                  "ServerConnectionHandler has a device registered",
	SoundInvalidCaptureDevice:              "invalid capture device",
	SoundInvalidPlaybackDevice:             "invalid clayback device",
	SoundInvalidWave:                       "invalid wave file",
	SoundUnsupportedWave:                   "wave file type not supported",
	SoundOpenWave:                          "could not open wave file",
	SoundInternalCapture:                   "internal capture",
	SoundDeviceInUse:                       "device still in use",
	SoundDeviceAlreadyRegistered:           "device already registered",
	SoundUnknownDevice:                     "device not registered/known",
	SoundUnsupportedFrequency:              "unsupported frequency",
	SoundInvalidChannelCount:               "invalid channel count",
	SoundReadWave:                          "read error in wave",
	SoundNeedMoreData:                      "sound need more data",
	SoundDeviceBusy:                        "sound device was busy",
	SoundNoData:                            "there is no sound data for this period",
	SoundChannelMaskMismatch:               "Channelmask set bits count (speakers) is not the same as (count)",
	PermissionInvalidGroupID:               "invalid group ID",
	PermissionDuplicateEntry:               "duplicate entry",
	PermissionInvalidPermID:                "invalid permission ID",
	PermissionEmptyResult:                  "empty result set",
	PermissionDefaultGroupForbidden:        "access to default group is forbidden",
	PermissionInvalidSize:                  "invalid size",
	PermissionInvalidValue:                 "invalid value",
	PermissionsGroupNotEmpty:               "group is not empty",
	PermissionsClientInsufficient:          "insufficient client permissions",
	PermissionsInsufficientGroupPower:      "insufficient group modify power",
	PermissionsInsufficientPermissionPower: "insufficient permission modify power",
	PermissionTemplateGroupIsUsed:          "template group is currently used",
	Permissions:                            "permission error",
	AccountingVirtualServerLimitReached:    "virtualserver limit reached",
	AccountingSlotLimitReached:             "max slot limit reached",
	AccountingLicenseFileNotFound:          "license file not found",
	AccountingLicenseDateNotOK:             "license date not ok",
	AccountingUnableToConnectToServer:      "unable to connect to accounting server",
	AccountingUnknownError:                 "unknown accounting error",
	AccountingServerError:                  "accounting server error",
	AccountingInstanceLimitReached:         "instance limit reached",
	AccountingInstanceCheckError:           "instance check error",
	AccountingLicenseFileInvalid:           "license file invalid",
	AccountingRunningElsewhere:             "virtualserver is running elsewhere",
	AccountingInstanceDuplicated:           "virtualserver running in same instance already",
	AccountingAlreadyStarted:               "virtualserver already started",
	AccountingNotStarted:                   "virtualserver not started",
	MessageInvalidID:                       "invalid message id",
	BanInvalidID:                           "invalid ban id",
	ConnectFailedBanned:                    "connection failed, you are banned",
	RenameFailedBanned:                     "rename failed, new name is banned",
	BanFlooding:                            "flood ban",
	TTSUnableToInitialize:                  "unable to initialize tts",
	PrivilegeKeyInvalid:                    "invalid privilege key",
	ProvisioningInvalidPassword:            "invalid password",
	ProvisioningInvalidRequest:             "invalid request",
	ProvisioningNoSlotsAvailable:           "no(more) slots available",
	ProvisioningPoolMissing:                "pool missing",
	ProvisioningPoolUnknown:                "pool unknown",
	ProvisioningUnknownIPLocation:          "unknown ip location(perhaps LAN ip?)",
	ProvisioningInternalTriesExceeded:      "internal error(tried exceeded)",
	ProvisioningTooManySlotsRequested:      "too many slots requested",
	ProvisioningTooManyReserved:            "too many reserved",
	ProvisioningCouldNotConnect:            "could not connect to provisioning server",
	ProvisioningAuthServerNotConnected:     "authentication server not connected",
	ProvisioningAuthDataTooLarge:           "authentication data too large",
	ProvisioningAlreadyInitialized:         "already initialized",
	ProvisioningNotInitialized:             "not initialized",
	ProvisioningConnecting:                 "already connecting",
	ProvisioningAlreadyConnected:           "already connected",
	ProvisioningIOError:                    "io_error",
	ProvisioningNoPermission:               "unknown permissionID",
	APIKeyOutOfScope:                       "out of scope",
	APIKeyInvalid:                          "invalid apikey",
	APIKeyMissing:                          "missing apikey",
}
