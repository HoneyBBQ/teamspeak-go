package perm_test

import (
	"fmt"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/perm"
)

func Example() {
	p := teamspeak.PermissionByName(perm.ClientNeededTalkPower)
	fmt.Println(p.Name())
	// Output: i_client_needed_talk_power
}
