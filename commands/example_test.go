package commands_test

import (
	"fmt"

	"github.com/honeybbq/teamspeak-go/commands"
)

func Example() {
	line := commands.ServerGroupAddPerm + " sgid=7 permsid=" + commands.Escape("b_client_ban_create") + " permvalue=1"
	fmt.Println(line)
	// Output: servergroupaddperm sgid=7 permsid=b_client_ban_create permvalue=1
}
