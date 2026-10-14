package client

import (
	"context"
	"crypto/sha1" //nolint:gosec // SHA-1 used for TS3 HWID/UID format, not security
	"encoding/base64"
	"log/slog"
	"strconv"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/internal/crypto"
	"github.com/honeybbq/teamspeak-go/internal/handshake"
	"github.com/honeybbq/teamspeak-go/internal/identitykey"
	"github.com/honeybbq/teamspeak-go/internal/transport"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// handleHandshakeInitIV completes the legacy key exchange. Once a shared
// secret exists a repeat is ignored: replacing the keys mid-session would end
// it.
func (c *Client) handleHandshakeInitIV(h *transport.PacketHandler, cmd *wire.Command) {
	if h.TsCrypt.InitComplete() {
		c.logger.Debug("ignoring clientinitiv after the key exchange")

		return
	}
	c.logger.Info("received crypto negotiation")
	h.ReceivedFinalInitAck()

	err := h.TsCrypt.InitCrypto(cmd.Params["alpha"], cmd.Params["beta"], cmd.Params["omega"])
	if err != nil {
		c.failHandshake(h, err)

		return
	}

	c.logger.Info("crypto initialized, sending clientinit")
	c.traceHandshakeDone(h, cmd.Params["omega"])
	c.sendClientInit(h)
}

// handleHandshakeExpand2 completes the key exchange: it answers with clientek,
// checks the server's license chain and derives the shared secret. Once one
// exists a repeat is ignored.
func (c *Client) handleHandshakeExpand2(h *transport.PacketHandler, cmd *wire.Command) {
	if h.TsCrypt.InitComplete() {
		c.logger.Debug("ignoring initivexpand2 after the key exchange")

		return
	}
	c.logger.Info("received initivexpand2")
	h.ReceivedFinalInitAck()
	license := cmd.Params["l"]
	omega := cmd.Params["omega"]
	proof := cmd.Params["proof"]
	beta := cmd.Params["beta"]

	privateKey, err := c.sendClientEkPacket(h, beta)
	if err != nil {
		c.failHandshake(h, err)

		return
	}

	err = handshake.CryptoInit2(h.TsCrypt, license, omega, proof, beta, privateKey)
	if err != nil {
		c.failHandshake(h, err)

		return
	}
	c.traceHandshakeDone(h, omega)
	c.sendClientInit(h)
}

func (c *Client) sendClientEkPacket(h *transport.PacketHandler, beta string) ([]byte, error) {
	publicKey, privateKey, err := crypto.GenerateTemporaryKey()
	if err != nil {
		c.logger.Error("failed to generate temporary key", slog.Any("error", err))

		return nil, err
	}
	ekBase64 := base64.StdEncoding.EncodeToString(publicKey)

	clientProof, err := c.buildClientEkProof(h, publicKey, beta)
	if err != nil {
		return nil, err
	}
	clientEk := wire.BuildCommandOrdered("clientek", [][2]string{
		{"ek", ekBase64},
		{"proof", clientProof},
	})
	c.logger.Debug("sending clientek")
	err = h.SendPacket(byte(transport.PacketTypeCommand), []byte(clientEk), 0)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func (c *Client) buildClientEkProof(h *transport.PacketHandler, publicKey []byte, beta string) (string, error) {
	betaBytes, err := base64.StdEncoding.DecodeString(beta)
	if err != nil {
		c.logger.Error("failed to decode beta", slog.Any("error", err))

		return "", err
	}
	toSign := make([]byte, 86)
	copy(toSign, publicKey)
	if len(betaBytes) > 54 {
		betaBytes = betaBytes[:54]
	}
	copy(toSign[32:], betaBytes)
	sign, err := crypto.Sign(identitykey.PrivateKey(h.TsCrypt.Identity), toSign)
	if err != nil {
		c.logger.Error("failed to sign clientek proof", slog.Any("error", err))

		return "", err
	}

	return base64.StdEncoding.EncodeToString(sign), nil
}

// handleInitServer completes the connection. It does so only for the current
// handler's attempt still in progress: an initserver that arrives after
// Disconnect, or on a connection already replaced, must not bring the client
// back to connected.
func (c *Client) handleInitServer(h *transport.PacketHandler, cmd *wire.Command) {
	c.mu.Lock()
	if c.handler != h || c.status != StatusConnecting {
		c.mu.Unlock()
		c.logger.Debug("ignoring initserver outside a connection attempt")

		return
	}
	// The server sends initserver only once the shared secret exists. One
	// sealed with the public dummy key could come from anyone; accepting it
	// would report the client connected and send the next commands, channel
	// password hashes included, under that key.
	if !h.TsCrypt.InitComplete() {
		c.mu.Unlock()
		c.logger.Debug("ignoring initserver before crypto init")

		return
	}
	c.status = StatusConnected
	c.adoptClientIDLocked(h, cmd.Params)

	// initserver is the only place the server names itself, and it determines
	// how the server hashes our public key into client_unique_identifier:
	// SHA-1 on TS3, SHA-256 on TS6. Record the whole capability set so callers
	// do not have to re-derive it, or assume one server generation.
	c.capabilities = parseServerCapabilities(cmd.Params)
	if c.capabilities.Version != "" {
		c.uidAlgorithm = c.capabilities.UIDAlgorithm
	}

	// Decided under the lock, announced after it: the SessionStart hook runs
	// with no lock held, before Connect is released and before connected is
	// queued below.
	report := c.startSessionLocked(cmd.Params)
	selfID := c.clid
	c.mu.Unlock()

	c.logger.Info("connected to server", slog.Uint64("self_id", uint64(selfID)))
	report()

	// The handshake's own command: sent on h, the session it completes, not
	// through ExecNoWait, which would send on whatever session is current.
	go func() {
		updateCmd := wire.BuildCommand("clientupdate", map[string]string{
			"client_input_muted":  "0",
			"client_output_muted": "0",
		})
		if c.throttle.wait(context.Background()) == nil {
			_ = c.sendLine(h, updateCmd)
		}
	}()

	emit(c, &c.onConnected, "Connected", struct{}{})
}

// adoptClientIDLocked takes the client id initserver assigns, from aclid or
// clid, for the session h runs. The caller holds c.mu.
func (c *Client) adoptClientIDLocked(h *transport.PacketHandler, initserver map[string]string) {
	idStr, ok := initserver["aclid"]
	if !ok {
		idStr = initserver["clid"]
	}
	val, err := strconv.ParseUint(idStr, 10, 16)
	if err != nil {
		return
	}
	c.clid = teamspeak.ClientID(val)
	h.SetClientID(uint16(c.clid))
}

func (c *Client) sendClientInit(h *transport.PacketHandler) {
	cmd := c.buildClientInitCommand(h.TsCrypt)
	err := h.SendPacket(byte(transport.PacketTypeCommand), []byte(cmd), 0)
	if err != nil {
		c.logger.Warn("failed to send clientinit", slog.Any("error", err))
	}
}

func (c *Client) buildClientInitCommand(tc *crypto.Crypt) string {
	pubKeyBase64 := tc.Identity.PublicKey()
	// HWID matches TS3 client UID format: base64(SHA1(publicKeyBase64))
	hwidSum := sha1.Sum([]byte(pubKeyBase64)) //nolint:gosec
	hwid := base64.StdEncoding.EncodeToString(hwidSum[:])
	defaultChannelPassword := c.clientInitOptions.defaultChannelPasswordHash
	serverPassword := c.clientInitOptions.serverPasswordHash
	nickname, _ := c.describe()

	return wire.BuildCommandOrdered("clientinit", [][2]string{
		{"client_nickname", nickname},
		{"client_version", "3.?.? [Build: 5680278000]"},
		{"client_platform", "Windows"},
		{"client_input_hardware", "1"},
		{"client_output_hardware", "1"},
		{"client_default_channel", c.clientInitOptions.defaultChannel},
		{"client_default_channel_password", defaultChannelPassword},
		{"client_server_password", serverPassword},
		{"client_meta_data", ""},
		{"client_version_sign", "DX5NIYLvfJEUjuIbCidnoeozxIDRRkpq3I9vVMBmE9L2qnekOoBzSenkzsg2lC9CMv8K5hkEzhr2TYUYSwUXCg=="},
		{"client_key_offset", strconv.FormatUint(tc.Identity.Offset(), 10)},
		{"client_nickname_phonetic", ""},
		{"client_default_token", ""},
		{"hwid", hwid},
	})
}

func prepareClientPassword(password string) string {
	if password == "" {
		return ""
	}

	sum := sha1.Sum([]byte(password)) //nolint:gosec // TeamSpeak protocol requires base64(sha1(password))

	return base64.StdEncoding.EncodeToString(sum[:])
}
