// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacyrpc

// Options contains the required options for running the legacy RPC server.
type Options struct {
	Username string
	Password string

	MaxPOSTClients      int64
	MaxWebsocketClients int64

	// AllowedMethods is an opt-in, exact, case-sensitive method allowlist.
	// Nil preserves the legacy server behavior; a non-nil empty slice denies
	// every method. NewServer takes an immutable copy. Restricted HTTP requests
	// must be POSTs to / without a query or Origin header. WebSocket users must
	// also allow authenticate if they do not authenticate at the HTTP upgrade.
	AllowedMethods []string
}
