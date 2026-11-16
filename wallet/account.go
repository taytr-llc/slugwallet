// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package wallet

import (
	"context"
	"errors"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
)

// SignAccountChallenge authorizes only a typed enroll/recover challenge for the
// pinned account authority and this wallet's retained identity. The authority
// ID comes from trusted client configuration, never the challenge or webview.
// This is not a login/session/reset/hold authorization. The service must check
// current generation, issued challenge, expiry, fixture policy and capability
// both when initiating and when committing the action. No key or arbitrary
// digest/path is exposed. The lease covers bounded local wallet DB reads and
// signing, with no network, provider interaction or recovery-file export.
func (w *Wallet) SignAccountChallenge(ctx context.Context, expectedAuthorityID string,
	challenge gymaccount.EnrollmentChallenge) (gymaccount.Authorization, error) {
	var empty gymaccount.Authorization
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if wire.TestPoW {
		return empty, errors.New("account signing requires production PoW profile")
	}
	if challenge.AuthorityID != expectedAuthorityID {
		return empty, errors.New("account authority does not match pinned configuration")
	}
	if _, err := gymaccount.ChallengeDigest(challenge); err != nil {
		return empty, errors.New("invalid account challenge")
	}
	public, err := w.recoveryPublicManifest()
	if err != nil {
		return empty, err
	}
	if !accountChallengeMatches(challenge, public) {
		return empty, errors.New("account challenge does not match retained wallet")
	}
	if err := gymaccount.ValidateFixtureIdentity(public.RootPublicKey, public.GymPublicKey, public.GymID); err != nil {
		return empty, err
	}
	lease, err := w.holdUnlockContext(ctx)
	if err != nil {
		return empty, err
	}
	defer lease.release()
	entropy, retained, err := w.recoveryMaterial()
	defer clear(entropy[:])
	if err != nil {
		return empty, err
	}
	if !accountChallengeMatches(challenge, retained) {
		return empty, errors.New("retained wallet identity changed")
	}
	if err := lease.err(ctx); err != nil {
		return empty, err
	}
	key, err := deriveRecoveryGymKey(entropy, w.chainParams)
	if err != nil {
		return empty, errors.New("account signing key unavailable")
	}
	defer key.Zero()
	authorization, err := gymaccount.SignChallenge(challenge, key)
	if err != nil {
		return empty, errors.New("account authorization failed")
	}
	if err := lease.err(ctx); err != nil {
		return empty, err
	}
	return authorization, nil
}
func accountChallengeMatches(c gymaccount.EnrollmentChallenge, m recovery.Manifest) bool {
	return c.Network == m.Network && c.Genesis == m.Genesis && c.Profile == m.Profile && c.RootPublicKey == m.RootPublicKey && c.GymPublicKey == m.GymPublicKey && c.GymID == m.GymID
}
