// Copyright (c) 2026 The SLUG developers. ISC license.
package recoveryvault

import (
	"context"
	"encoding/hex"

	"github.com/taytr-llc/slug/btcec/v2/ecdsa"
	"github.com/taytr-llc/slug/fightertransfer"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/wallet"
)

// SignFighterTransfer signs only a concrete wallet owner's retained reviewed
// preparation. A parsed request or a caller-selected digest cannot mint that
// capability. The original account and parent View fence apply before opening
// the gym envelope and again before disclosure; no recovery envelope is opened.
func (h *HostedVault) SignFighterTransfer(ctx context.Context, token string, prepared *wallet.PreparedFighterTransfer, epoch EpochFence) (fightertransfer.Envelope, error) {
	var result fightertransfer.Envelope
	if prepared == nil {
		return result, ErrConflict
	}
	ctx, done, err := h.acquire(ctx)
	if err != nil {
		return result, err
	}
	defer done()
	if err = prepared.Check(ctx); err != nil {
		return result, err
	}
	pin, request := prepared.Pin(), prepared.AuthorizationRequest()
	a, r, err := h.snapshot(ctx, token, gymaccount.FighterTransfer, epoch)
	if err != nil {
		return result, err
	}
	if r.State != "enrolled" || r.Gym == nil ||
		pin.OwnerMode != "hosted" || pin.ManagerSchema != 14 ||
		pin.AccountAuthorityID != r.Binding.AuthorityID || pin.AccountID != r.Binding.AccountID ||
		pin.Network != r.Binding.Network || pin.Genesis != r.Binding.Genesis ||
		pin.WalletProfile != r.Binding.Profile || pin.RootPublicKey != r.Binding.RootPublicKey ||
		pin.GymPublicKey != r.Binding.GymPublicKey || pin.GymID != r.Binding.GymID ||
		request.Version != 1 || request.OwnershipPinID != pin.OwnershipPinID ||
		request.SenderGym != r.Binding.GymPublicKey {
		return result, ErrConflict
	}
	var expected fightertransfer.Expected
	decode := func(value string, out []byte) bool {
		if !canonicalHex(value, len(out)) {
			return false
		}
		raw, err := hex.DecodeString(value)
		if err != nil {
			return false
		}
		copy(out, raw)
		return true
	}
	if !decode(request.OwnershipPinID, result.Intent.PinID[:]) ||
		!decode(request.PriorStateID, result.Intent.PriorStateID[:]) ||
		!decode(request.RecipientGym, result.Intent.RecipientGym[:]) ||
		!decode(request.FundingDigest, result.Intent.FundingDigest[:]) ||
		!decode(request.SenderGym, expected.SenderGym[:]) {
		return fightertransfer.Envelope{}, ErrEnvelope
	}
	expected.PinID, expected.PriorStateID = result.Intent.PinID, result.Intent.PriorStateID
	digest, err := fightertransfer.AuthorizationDigest(result.Intent)
	if err != nil {
		return fightertransfer.Envelope{}, ErrEnvelope
	}
	if err = prepared.Check(ctx); err != nil {
		return fightertransfer.Envelope{}, err
	}
	raw, err := openEnvelope(ctx, h.core.wrapper, *r.Gym)
	if err != nil {
		return fightertransfer.Envelope{}, err
	}
	defer clear(raw)
	key, err := decodeGym(raw, r.Binding)
	if err != nil {
		return fightertransfer.Envelope{}, err
	}
	defer key.Zero()
	compact := ecdsa.SignCompact(key, digest[:], true)
	if len(compact) != 65 {
		return fightertransfer.Envelope{}, ErrEnvelope
	}
	copy(result.Signature[:], compact[1:])
	if err = fightertransfer.VerifyAuthorization(expected, result); err != nil {
		return fightertransfer.Envelope{}, ErrEnvelope
	}
	if err = prepared.Check(ctx); err != nil {
		return fightertransfer.Envelope{}, err
	}
	if err = h.disclose(ctx, token, gymaccount.FighterTransfer, epoch, a, r); err != nil {
		return fightertransfer.Envelope{}, err
	}
	return result, nil
}
