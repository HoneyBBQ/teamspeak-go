package notify_test

import (
	"fmt"
	"testing"

	"github.com/honeybbq/teamspeak-go/notify"
)

func Example() {
	name := "notifychanneledited"
	fmt.Println(name == notify.ChannelEdited)
	// Output: true
}

// The stream notifications are named after what the server sends.
func TestStreamNames(t *testing.T) {
	for want, got := range map[string]string{
		"notifystreamstarted":            notify.StreamStarted,
		"notifystreaminfo":               notify.StreamInfo,
		"notifystreamstopped":            notify.StreamStopped,
		"notifyjoinstreamrequest":        notify.JoinStreamRequest,
		"notifyrespondjoinstreamrequest": notify.RespondJoinStreamRequest,
		"notifystreamsignaling":          notify.StreamSignaling,
		"notifystreamclientjoined":       notify.StreamClientJoined,
		"notifystreamclientleft":         notify.StreamClientLeft,
	} {
		if got != want {
			t.Errorf("name = %q, want %q", got, want)
		}
	}
}
