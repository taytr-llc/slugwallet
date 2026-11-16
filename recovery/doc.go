// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

// Package recovery implements the fixed Phase-A fixture recovery profile:
// English BIP39 24-word phrases, an empty additional BIP39 passphrase, standard
// BIP32 derivation, and bounded explicit account/gym metadata. It does not issue
// wallets, authenticate account owners, store entropy, expose secret RPCs, or
// transfer fighter ownership. The coin-zero and gym paths are fixture policy;
// they are not a production registration or a migration of legacy wallets.
//
// Export values and derived seeds are secret. Callers must protect their output
// and clear owned byte buffers. Go strings and runtime copies cannot be reliably
// erased. Public manifests alone do not prove recovery authority or chain state.
package recovery
