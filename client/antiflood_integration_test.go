//go:build integration

package client_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/client"
	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/identity"
	"github.com/honeybbq/teamspeak-go/prop"
	"github.com/honeybbq/teamspeak-go/serverquery"
)

// The voice antiflood costs docs/flood-control.md states, measured: a client
// with no line middleware sends one command until the server answers 524, on a
// server whose command_block is first 200 and then 600 points. Nothing else
// changes between the two runs, so the commands the handshake itself costs
// cancel out, and the cost of one command is 400 divided by how many more of
// them the higher limit let through. tick_reduce is 1, so the points that wear
// off while a run lasts are a few at most.

var antifloodFields = []string{
	prop.VirtualServerAntiFloodPointsTickReduce,
	prop.VirtualServerAntiFloodPointsNeededCommandBlock,
	prop.VirtualServerAntiFloodPointsNeededIPBlock,
	prop.VirtualServerAntiFloodPointsNeededPluginBlock,
}

// unpacedClient connects a fresh identity with no line middleware.
func unpacedClient(t *testing.T) *client.Client {
	t.Helper()
	addr := requireTeamSpeakAddr(t)
	id, err := identity.Generate(t.Context(), 8)
	requireNoErr(t, err)
	c := newClient(t, id, addr, "antiflood", integrationClientOptions(nil)...)
	requireNoErr(t, connectWithRetries(t.Context(), t, c))
	t.Cleanup(func() { _ = c.Disconnect(context.Background()) })

	return c
}

// acceptedUntilBlocked sends line until the server refuses it as flooding and
// returns how many were accepted, with the refusal.
func acceptedUntilBlocked(t *testing.T, c *client.Client, line string) (int, error) {
	t.Helper()
	const limit = 2000
	for accepted := range limit {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		_, err := c.Exec(ctx, line)
		cancel()
		if err == nil {
			continue
		}
		if errors.Is(err, errcode.ClientIsFlooding) {
			return accepted, err
		}
		t.Fatalf("%q failed with something other than a flood refusal after %d: %v", line, accepted, err)
	}
	t.Fatalf("%q was never refused in %d tries", line, limit)

	return 0, nil
}

// antifloodCost is one command whose cost the test measures.
type antifloodCost struct {
	line func(c *client.Client) string
	name string
	want int
}

var antifloodCosts = []antifloodCost{
	{func(*client.Client) string { return "permget permsid=b_client_ignore_antiflood" }, "permget", 5},
	{func(*client.Client) string { return "channellist" }, "channellist", 5},
	{func(*client.Client) string { return "clientupdate client_away=0" }, "clientupdate", 15},
	{func(c *client.Client) string {
		return fmt.Sprintf("sendtextmessage targetmode=2 target=%d msg=x", c.ChannelID())
	}, "sendtextmessage", 15},
}

// setCommandBlock sets the limits the measurement runs under.
func setCommandBlock(t *testing.T, admin *serverquery.Client, block int) {
	t.Helper()
	requireNoErr(t, admin.EditServer(t.Context(), teamspeak.Properties{
		prop.VirtualServerAntiFloodPointsTickReduce:         "1",
		prop.VirtualServerAntiFloodPointsNeededIPBlock:      "65000",
		prop.VirtualServerAntiFloodPointsNeededCommandBlock: strconv.Itoa(block),
	}))
}

// restoreAntiflood reads the four settings now and puts them back at the end of
// the test, whatever happens.
func restoreAntiflood(t *testing.T, admin *serverquery.Client) {
	t.Helper()
	info, err := admin.GetServerInfo(t.Context())
	requireNoErr(t, err)
	original := teamspeak.Properties{}
	for _, field := range antifloodFields {
		original[field] = info[field]
		if original[field] == "" {
			t.Fatalf("the server does not report %s", field)
		}
	}
	t.Cleanup(func() {
		ctx, cancel := cleanupContext()
		defer cancel()
		err := admin.EditServer(ctx, original)
		if err != nil {
			t.Errorf("restoring the antiflood settings %v: %v", original, err)
		}
	})
}

func assertAntifloodFieldsReadable(t *testing.T) {
	t.Helper()
	c := unpacedClient(t)
	rows, err := c.Exec(t.Context(), "servergetvariables")
	requireNoErr(t, err)
	if len(rows) != 1 {
		t.Fatalf("servergetvariables returned %d rows", len(rows))
	}
	for _, field := range antifloodFields {
		_, err = strconv.Atoi(rows[0][field])
		if err != nil {
			t.Errorf("%s = %q, want a number", field, rows[0][field])
		}
	}
}

func assertCost(t *testing.T, admin *serverquery.Client, tc antifloodCost) {
	t.Helper()
	var accepted [2]int
	for i, block := range []int{200, 600} {
		setCommandBlock(t, admin, block)
		c := unpacedClient(t)
		var refusal error
		accepted[i], refusal = acceptedUntilBlocked(t, c, tc.line(c))
		// The refusal's own text names the wait.
		wait, ok := teamspeak.FloodWait(refusal)
		if !ok || wait <= 0 {
			t.Errorf("FloodWait(%v) = %v, %v, want the wait the server named", refusal, wait, ok)
		}
	}
	more := accepted[1] - accepted[0]
	if more <= 0 {
		t.Fatalf("limit 200 let %d through and 600 let %d: no difference to measure", accepted[0], accepted[1])
	}
	got := int(math.Round(400 / float64(more)))
	t.Logf("%s: %d accepted at 200, %d at 600, cost %.2f", tc.name, accepted[0], accepted[1], 400/float64(more))
	if got != tc.want {
		t.Errorf("%s cost %d points, want %d", tc.name, got, tc.want)
	}
}

func TestIntegration_VoiceAntifloodCostsAndThresholds(t *testing.T) {
	requireTeamSpeakAddr(t)
	admin := requireAdmin(t)
	restoreAntiflood(t, admin)

	t.Run("a fresh identity reads the four fields with servergetvariables", assertAntifloodFieldsReadable)

	t.Run("servergetvariables costs nothing at a limit of 200", func(t *testing.T) {
		setCommandBlock(t, admin, 200)
		c := unpacedClient(t)
		for i := range 400 {
			_, err := c.Exec(t.Context(), "servergetvariables")
			if err != nil {
				t.Fatalf("servergetvariables %d of 400 failed: %v", i+1, err)
			}
		}
	})

	for _, tc := range antifloodCosts {
		t.Run(tc.name+" costs "+strconv.Itoa(tc.want), func(t *testing.T) { assertCost(t, admin, tc) })
	}
}
