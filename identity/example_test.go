package identity_test

import (
	"context"
	"fmt"
	"log"

	"github.com/honeybbq/teamspeak-go/identity"
)

// An identity is generated once and stored with Export: it is the client's
// account on every server, and the server knows the client by it.
func ExampleGenerate() {
	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(id.SecurityLevel() >= 8)
	// Output: true
}

// Parse reads back what Export wrote, so a stored identity is the same
// identity, with the same UID, on the next run.
func ExampleParse() {
	id, err := identity.Generate(context.Background(), 8)
	if err != nil {
		log.Fatal(err)
	}
	stored := id.Export() // Keep this as you would a password.

	loaded, err := identity.Parse(stored)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(loaded.UID(identity.UIDSHA1) == id.UID(identity.UIDSHA1))
	fmt.Println(loaded.Export() == stored)
	// Output:
	// true
	// true
}
