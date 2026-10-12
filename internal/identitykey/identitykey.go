// Package identitykey hands an identity's private key to the packages of this
// module that sign and agree keys with it, without exporting it from package
// identity.
//
// Package identity registers its accessor here when it is initialised; this
// package cannot import identity, which imports it, so the identity travels
// as any.
package identitykey

import "crypto/ecdsa"

var privateKeyOf func(id any) *ecdsa.PrivateKey

// Register installs the accessor. Package identity calls it from init.
func Register(accessor func(id any) *ecdsa.PrivateKey) {
	privateKeyOf = accessor
}

// PrivateKey returns id's private key, or nil for an identity without one or
// a value that is not an identity.
func PrivateKey(id any) *ecdsa.PrivateKey {
	if privateKeyOf == nil || id == nil {
		return nil
	}

	return privateKeyOf(id)
}
