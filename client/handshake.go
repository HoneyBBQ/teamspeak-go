package client

import (
	"context"
	"crypto/sha1" //nolint:gosec // SHA-1 used for TS3 HWID/UID format, not security
	"encoding/base64"
	"log/slog"
	"strconv"

	teamspeak "github.com/honeybbq/teamspeak-go"

	"github.com/honeybbq/teamspeak-go/commands"
	"github.com/honeybbq/teamspeak-go/internal/crypto"
	"github.com/honeybbq/teamspeak-go/internal/handshake"
	"github.com/honeybbq/teamspeak-go/internal/transport"
)

// handleHandshakeInitIV completes the legacy key exchange. Once a shared
// secret exists a repeat is ignored: replacing the keys mid-session would end
// it.
func (c *Client) handleHandshakeInitIV(h *transport.PacketHandler, cmd *commands.Command) {
	if h.TsCrypt.InitComplete() {
		c.logger.Debug("ignoring clientinitiv after the key exchange")

		return
	}
	c.logger.Info("received crypto negotiation")

	err := h.TsCrypt.InitCrypto(cmd.Params["alpha"], cmd.Params["beta"], cmd.Params["omega"])
	if err != nil {
		c.failHandshake(h, err)

		return
	}

	c.logger.Info("crypto initialized, sending clientinit")
	c.sendClientInit(h)
}

// handleHandshakeExpand2 completes the key exchange: it answers with clientek,
// checks the server's license chain and derives the shared secret. Once one
// exists a repeat is ignored.
func (c *Client) handleHandshakeExpand2(h *transport.PacketHandler, cmd *commands.Command) {
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
	clientEk := commands.BuildCommandOrdered("clientek", [][2]string{
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
	sign, err := crypto.Sign(h.TsCrypt.Identity.PrivateKey, toSign)
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
func (c *Client) handleInitServer(h *transport.PacketHandler, cmd *commands.Command) {
	c.mu.Lock()
	if c.handler != h || c.status != StatusConnecting {
		c.mu.Unlock()
		c.logger.Debug("ignoring initserver outside a connection attempt")

		return
	}
	c.status = StatusConnected

	idStr := ""
	if v, ok := cmd.Params["aclid"]; ok {
		idStr = v
	} else if v, ok := cmd.Params["clid"]; ok {
		idStr = v
	}

	if idStr != "" {
		val, err := strconv.ParseUint(idStr, 10, 16)
		if err == nil {
			c.clid = teamspeak.ClientID(val)
			h.SetClientID(uint16(c.clid))
		}
	}

	// initserver is the only place the server names itself, and it determines
	// how the server hashes our public key into client_unique_identifier:
	// SHA-1 on TS3, SHA-256 on TS6. Record the whole capability set so callers
	// do not have to re-derive it, or assume one server generation.
	c.capabilities = ParseServerCapabilities(cmd.Params)
	if c.capabilities.Version != "" {
		c.uidAlgorithm = c.capabilities.UIDAlgorithm
	}

	c.attempt.finish(nil)
	selfID := c.clid
	c.mu.Unlock()

	c.logger.Info("connected to server", slog.Uint64("self_id", uint64(selfID)))

	go func() {
		updateCmd := commands.BuildCommand("clientupdate", map[string]string{
			"client_input_muted":  "0",
			"client_output_muted": "0",
		})
		_ = c.ExecNoWait(context.Background(), updateCmd)
	}()

	emit(c, &c.onConnected, struct{}{})
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
	defaultChannelPassword := prepareClientPassword(c.clientInitOptions.defaultChannelPassword)
	serverPassword := prepareClientPassword(c.clientInitOptions.serverPassword)

	return commands.BuildCommandOrdered("clientinit", [][2]string{
		{"client_nickname", c.nickname},
		{"client_version", "3.?.? [Build: 5680278000]"},
		{"client_platform", "Windows"},
		{"client_input_hardware", "1"},
		{"client_output_hardware", "1"},
		{"client_default_channel", c.clientInitOptions.defaultChannel},
		{"client_default_channel_password", defaultChannelPassword},
		{"client_server_password", serverPassword},
		{"client_meta_data", ""},
		{"client_version_sign", "DX5NIYLvfJEUjuIbCidnoeozxIDRRkpq3I9vVMBmE9L2qnekOoBzSenkzsg2lC9CMv8K5hkEzhr2TYUYSwUXCg=="},
		{"client_key_offset", strconv.FormatUint(tc.Identity.Offset, 10)},
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
