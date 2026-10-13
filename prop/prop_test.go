package prop_test

import (
	"fmt"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/prop"
)

func Example() {
	info := teamspeak.Properties{"virtualserver_name": "My server"}
	fmt.Println(info[prop.VirtualServerName])
	// Output: My server
}
