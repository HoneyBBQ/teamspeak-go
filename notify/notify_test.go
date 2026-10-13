package notify_test

import (
	"fmt"

	"github.com/honeybbq/teamspeak-go/notify"
)

func Example() {
	name := "notifychanneledited"
	fmt.Println(name == notify.ChannelEdited)
	// Output: true
}
