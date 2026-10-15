package client

import (
	"errors"
	"testing"

	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/internal/wire"
	"github.com/honeybbq/teamspeak-go/versions"
)

func TestDefaultClientVersion_IsTheTablesEntry(t *testing.T) {
	if defaultClientVersion != versions.Windows_3_X_X_5680278000 {
		t.Errorf("default %+v differs from the table's %+v", defaultClientVersion, versions.Windows_3_X_X_5680278000)
	}
}

func TestBuildClientInitCommand_SendsTheDefaultVersion(t *testing.T) {
	c := newTestClient(t)

	cmd := wire.ParseCommand(c.buildClientInitCommand(c.handler.TsCrypt))
	if cmd == nil {
		t.Fatal("expected clientinit command")
	}
	v := versions.Windows_3_X_X_5680278000
	if cmd.Params["client_platform"] != v.Platform ||
		cmd.Params["client_version"] != v.Version ||
		cmd.Params["client_version_sign"] != v.Sign {
		t.Errorf("clientinit sent %v, want %+v", cmd.Params, v)
	}
}

func TestWithVersion_ClientInitSendsIt(t *testing.T) {
	v := versions.Windows_3_6_3_1701166057
	c := newTestClient(t, WithVersion(v))

	cmd := wire.ParseCommand(c.buildClientInitCommand(c.handler.TsCrypt))
	if cmd == nil {
		t.Fatal("expected clientinit command")
	}
	if cmd.Params["client_platform"] != v.Platform ||
		cmd.Params["client_version"] != v.Version ||
		cmd.Params["client_version_sign"] != v.Sign {
		t.Errorf("clientinit sent %v, want %+v", cmd.Params, v)
	}
}

func TestWithVersion_RejectsAMalformedVersion(t *testing.T) {
	id, err := identity.Parse(testClientIdentity)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	good := versions.Windows_3_6_3_1701166057
	cases := map[string]versions.ClientVersion{
		"zero value":       {},
		"no platform":      {Version: good.Version, Sign: good.Sign},
		"no version":       {Platform: good.Platform, Sign: good.Sign},
		"no sign":          {Platform: good.Platform, Version: good.Version},
		"not base64":       {Platform: good.Platform, Version: good.Version, Sign: "not base64!"},
		"too short a sign": {Platform: good.Platform, Version: good.Version, Sign: "AAAA"},
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := New(id, "localhost", "Bot", WithVersion(v))
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("New error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}
