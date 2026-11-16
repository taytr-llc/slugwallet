// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

// Package recoveryvault provides encrypted retention for two published fixture
// wallets. It does not issue production wallets or configure a live provider.
package recoveryvault

import (
	"context"
	"errors"

	"github.com/taytr-llc/slug/prospectnode"
)

const (
	Version1          uint32 = 1
	MaxOperations     uint32 = 128
	MaxPayloadSize           = 4 + 32 + 4 + 65536
	MaxWrappedKeySize        = 8192
	MaxEnvelopeSize          = 196608
	MaxKeyReferences         = 8
)

type Purpose string

const (
	RecoveryPurpose Purpose = "recovery"
	GymPurpose      Purpose = "gym-signing"
)

var (
	ErrConfig   = errors.New("invalid fixture recovery vault configuration")
	ErrEnvelope = errors.New("recovery vault envelope unavailable")
)

// KeyWrapper is the trusted provider boundary. References come only from the
// pinned allowlist. Implementations must authenticate the exact AAD, honor
// context deadlines, bound their responses, and clear owned DEK copies. They
// must not log inputs or return raw provider details to a caller. No production
// implementation or default secret is supplied by this package.
type KeyWrapper interface {
	ID() string
	Wrap(ctx context.Context, keyRef string, dek [32]byte, aad []byte) ([]byte, error)
	Unwrap(ctx context.Context, keyRef string, blob, aad []byte) ([32]byte, error)
}

// Config pins public wrapping trust. Recovery and gym key references are
// disjoint, preventing an accidental shared purpose configuration.
type Config struct {
	Version                uint32              `json:"version"`
	WrapperID              string              `json:"wrapper_id"`
	RecoveryKeyRef         string              `json:"recovery_key_ref"`
	GymKeyRef              string              `json:"gym_key_ref"`
	AllowedRecoveryKeyRefs []string            `json:"allowed_recovery_key_refs"`
	AllowedGymKeyRefs      []string            `json:"allowed_gym_key_refs"`
	MaxOperations          uint32              `json:"max_operations"`
	Policy                 prospectnode.Policy `json:"policy"`
}

// Binding is permanent for a reservation, independently of resets or key
// wrapping changes. A session generation is authorization, not wallet identity.
type Binding struct {
	Version       uint32 `json:"version"`
	AuthorityID   string `json:"authority_id"`
	AccountID     string `json:"account_id"`
	PrincipalID   string `json:"principal_id"`
	ProvisionID   string `json:"provision_id"`
	Network       uint32 `json:"network"`
	Genesis       string `json:"genesis"`
	Profile       string `json:"profile"`
	RootPublicKey string `json:"root_public_key"`
	GymPublicKey  string `json:"gym_public_key"`
	GymID         string `json:"gym_id"`
}

// Envelope contains only authenticated ciphertext and public metadata. Encoded
// byte fields use canonical lowercase hex. Strings avoid mutable slice aliases
// in retained snapshots. There is deliberately no exported plaintext getter.
type Envelope struct {
	Version         uint32  `json:"version"`
	Binding         Binding `json:"binding"`
	Purpose         Purpose `json:"purpose"`
	ContentRevision uint64  `json:"content_revision"`
	ManifestHash    string  `json:"manifest_hash"`
	Nonce           string  `json:"nonce"`
	Ciphertext      string  `json:"ciphertext"`
	WrapperID       string  `json:"wrapper_id"`
	KeyRef          string  `json:"key_ref"`
	WrapRevision    uint64  `json:"wrap_revision"`
	WrappedKey      string  `json:"wrapped_key"`
}

// TargetRefs names an explicit pair of already trusted rotation targets. It
// does not permit an arbitrary provider/key reference supplied by a request.
type TargetRefs struct {
	Recovery string `json:"recovery"`
	Gym      string `json:"gym"`
}
