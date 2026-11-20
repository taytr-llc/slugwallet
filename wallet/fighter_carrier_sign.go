// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/btcec/v2"
	"github.com/taytr-llc/slug/btcec/v2/ecdsa"
	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slug/fightertransfer"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func carrierIntent(p fightercarrier.Preparation) (fightertransfer.Intent, error) {
	var v fightertransfer.Intent
	for _, pair := range []struct {
		text string
		out  []byte
	}{{p.Review.OwnershipPinID, v.PinID[:]}, {p.Review.PriorStateID, v.PriorStateID[:]}, {p.Review.RecipientGym, v.RecipientGym[:]}, {p.Review.FundingDigest, v.FundingDigest[:]}} {
		raw, e := hex.DecodeString(pair.text)
		if e != nil || len(raw) != len(pair.out) {
			return v, fightercarrier.ErrInvalid
		}
		copy(pair.out, raw)
	}
	_, e := fightertransfer.MarshalIntent(v)
	return v, e
}
func carrierExpected(pin fightercarrier.Pin, i fightertransfer.Intent) fightertransfer.Expected {
	v := fightertransfer.Expected{PinID: i.PinID, PriorStateID: i.PriorStateID}
	raw, _ := hex.DecodeString(pin.GymPublicKey)
	copy(v.SenderGym[:], raw)
	return v
}

// The caller already holds the wallet's unlock lease. Only a recorded owned
// native84 path is admitted; the returned key is an owned copy and must be zeroed.
func (o *FighterCarrierOwner) fundingKey(tx walletdb.ReadTx, branch, index uint32, script string) (*btcec.PrivateKey, error) {
	if branch > 1 || index >= 4096 {
		return nil, fightercarrier.ErrInvalid
	}
	raw, e := hex.DecodeString(script)
	if e != nil || len(raw) != 22 || raw[0] != 0 || raw[1] != 20 {
		return nil, fightercarrier.ErrCorrupt
	}
	paths := CandidateWithdrawals{wallet: o.wallet}
	b, n, e := paths.path(tx, raw)
	if e != nil || b != branch || n != index {
		return nil, fightercarrier.ErrCorrupt
	}
	a, e := address.NewAddressWitnessPubKeyHash(raw[2:], o.wallet.chainParams)
	if e != nil {
		return nil, e
	}
	ma, e := o.manager.Address(tx.ReadBucket(waddrmgrNamespaceKey), a)
	if e != nil {
		return nil, e
	}
	managed, ok := ma.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return nil, fightercarrier.ErrCorrupt
	}
	key, e := managed.PrivKey()
	if e != nil {
		return nil, e
	}
	if !bytes.Equal(address.Hash160(key.PubKey().SerializeCompressed()), raw[2:]) {
		key.Zero()
		return nil, fightercarrier.ErrCorrupt
	}
	return key, nil
}
func (o *FighterCarrierOwner) restoredEnvelope(ctx context.Context, tx walletdb.ReadTx, i fightertransfer.Intent) (fightertransfer.Envelope, error) {
	var none fightertransfer.Envelope
	if o.pin.OwnerMode != "restored" || o.manager.CarrierSchema() != 15 {
		return none, fightercarrier.ErrProfile
	}
	guard, e := o.manager.AuditRestoredCarrier(ctx, tx.ReadBucket(waddrmgrNamespaceKey))
	if e != nil {
		return none, e
	}
	if !restoredCarrierPinMatches(o.pin, guard) {
		return none, fightercarrier.ErrConflict
	}
	public, e := recovery.MarshalManifest(guard.OriginalManifest)
	if e != nil {
		return none, e
	}
	digest := sha256.Sum256(public)
	private, e := o.manager.RecoveryData(tx.ReadBucket(waddrmgrNamespaceKey), true)
	if e != nil {
		return none, e
	}
	defer clear(private)
	if len(private) != 68 || binary.LittleEndian.Uint32(private) != 1 || !bytes.Equal(private[36:], digest[:]) {
		return none, fightercarrier.ErrCorrupt
	}
	var entropy [32]byte
	copy(entropy[:], private[4:36])
	defer clear(entropy[:])
	if recovery.ValidateEntropyManifest(entropy, guard.OriginalManifest) != nil {
		return none, fightercarrier.ErrCorrupt
	}
	key, e := deriveRecoveryGymKey(entropy, o.wallet.chainParams)
	if e != nil {
		return none, e
	}
	defer key.Zero()
	if hex.EncodeToString(key.PubKey().SerializeCompressed()) != o.pin.GymPublicKey {
		return none, fightercarrier.ErrCorrupt
	}
	d, e := fightertransfer.AuthorizationDigest(i)
	if e != nil {
		return none, e
	}
	compact := ecdsa.SignCompact(key, d[:], true)
	if len(compact) != 65 {
		return none, fightercarrier.ErrCorrupt
	}
	result := fightertransfer.Envelope{Intent: i}
	copy(result.Signature[:], compact[1:])
	if e = fightertransfer.VerifyAuthorization(carrierExpected(o.pin, i), result); e != nil {
		return none, e
	}
	return result, ctx.Err()
}

// SignRestoredAuthorization is the reviewed new-transfer gym operation for a
// file-only restored owner. It is not a general arbitrary-digest signer.
func (o *FighterCarrierOwner) SignRestoredAuthorization(ctx context.Context, p *PreparedFighterTransfer) (fightertransfer.Envelope, error) {
	var result fightertransfer.Envelope
	if p == nil || p.owner != o || o.pin.OwnerMode != "restored" || p.preparation.Request.Kind != "transfer" {
		return result, fightercarrier.ErrInvalid
	}
	if e := p.Check(ctx); e != nil {
		return result, e
	}
	work, end, e := o.owner.acquire(ctx)
	if e != nil {
		return result, e
	}
	e = func() error {
		lease, e := o.wallet.holdUnlockContext(work)
		if e != nil {
			return e
		}
		defer lease.release()
		e = walletdb.View(o.wallet.db, func(tx walletdb.ReadTx) error {
			i, e := carrierIntent(p.preparation)
			if e != nil {
				return e
			}
			result, e = o.restoredEnvelope(work, tx, i)
			return e
		})
		if e != nil {
			return e
		}
		return lease.err(work)
	}()
	end()
	if e != nil {
		return fightertransfer.Envelope{}, e
	}
	if e = p.Check(ctx); e != nil {
		return fightertransfer.Envelope{}, e
	}
	return result, nil
}
func rawCarrierTransaction(tx *wire.MsgTx) (fightercarrier.RawTransaction, error) {
	var b bytes.Buffer
	if e := tx.Serialize(&b); e != nil {
		return fightercarrier.RawTransaction{}, e
	}
	raw := b.Bytes()
	return fightercarrier.RawTransaction{Raw: hex.EncodeToString(raw), TxID: tx.TxHash().String(), RawSHA256: carrierSHA(raw)}, nil
}

// Sign returns one complete scratch pair. The app journal is the only durable
// signed/dispatch authority; no transaction reaches the wallet rebroadcast queue.
func (o *FighterCarrierOwner) Sign(ctx context.Context, p *PreparedFighterTransfer, envelope fightertransfer.Envelope) (CarrierSignedPackage, error) {
	var result fightercarrier.SignedPackage
	if p == nil || p.owner != o {
		return result, fightercarrier.ErrInvalid
	}
	if e := p.Check(ctx); e != nil {
		return result, e
	}
	intent, e := carrierIntent(p.preparation)
	if e != nil || intent != envelope.Intent {
		return result, fightercarrier.ErrConflict
	}
	if e = fightertransfer.VerifyAuthorization(carrierExpected(o.pin, intent), envelope); e != nil {
		return result, e
	}
	work, end, e := o.owner.acquire(ctx)
	if e != nil {
		return result, e
	}
	e = func() error {
		lease, e := o.wallet.holdUnlockContext(work)
		if e != nil {
			return e
		}
		defer lease.release()
		e = walletdb.View(o.wallet.db, func(tx walletdb.ReadTx) error {
			if e = o.validatePreparedInputs(work, tx, p.preparation); e != nil {
				return e
			}
			if e = o.auditExclusions(work, tx); e != nil {
				return e
			}
			state, e := readCarrierWalletState(work, tx, o.journal.Identity().JournalID, &o.pin)
			if e != nil {
				return e
			}
			found := false
			for _, r := range state.records {
				if r.RequestID == p.preparation.Request.RequestID && r.State == "prepared" && r.PreparationDigest == p.digest {
					found = true
				}
			}
			if !found {
				return fightercarrier.ErrConflict
			}
			funding := p.preparation.NewFunding
			if funding == nil {
				result, e = o.signRecovery(tx, p, envelope)
				if e != nil {
					return e
				}
				return lease.err(work)
			}
			result, e = o.signNewFunding(work, tx, p.preparation, envelope, lease)
			if e != nil {
				return e
			}
			return lease.err(work)
		})
		if e != nil {
			return e
		}
		return lease.err(work)
	}()
	end()
	if e != nil {
		return fightercarrier.SignedPackage{}, e
	}
	if e = p.Check(ctx); e != nil {
		return fightercarrier.SignedPackage{}, e
	}
	return result, nil
}

// SignRecovery uses only the previously reconstructed committed authorization;
// a caller cannot substitute an envelope, path, funding tuple or return output.
func (o *FighterCarrierOwner) SignRecovery(ctx context.Context, p *PreparedFighterTransfer) (CarrierSignedPackage, error) {
	if p == nil || p.owner != o || p.preparation.RecoveryFunding == nil {
		return CarrierSignedPackage{}, fightercarrier.ErrInvalid
	}
	i, e := carrierIntent(p.preparation)
	if e != nil {
		return CarrierSignedPackage{}, e
	}
	env := fightertransfer.Envelope{Intent: i}
	raw, e := hex.DecodeString(p.preparation.RecoveryFunding.GymAuthorization)
	if e != nil || len(raw) != 64 {
		return CarrierSignedPackage{}, fightercarrier.ErrCorrupt
	}
	copy(env.Signature[:], raw)
	return o.Sign(ctx, p, env)
}

func (o *FighterCarrierOwner) signRecovery(tx walletdb.ReadTx, p *PreparedFighterTransfer, env fightertransfer.Envelope) (fightercarrier.SignedPackage, error) {
	var none fightercarrier.SignedPackage
	r := p.preparation.RecoveryFunding
	if r == nil || o.pin.OwnerMode != "restored" || hex.EncodeToString(env.Signature[:]) != r.GymAuthorization {
		return none, fightercarrier.ErrConflict
	}
	pub, e := hex.DecodeString(r.FundingPublicKey)
	if e != nil {
		return none, e
	}
	script := append([]byte{0, 20}, address.Hash160(pub)...)
	key, e := o.fundingKey(tx, r.FundingBranch, r.FundingIndex, hex.EncodeToString(script))
	if e != nil {
		return none, e
	}
	defer key.Zero()
	if !bytes.Equal(key.PubKey().SerializeCompressed(), pub) {
		return none, fightercarrier.ErrConflict
	}
	var funding [33]byte
	copy(funding[:], pub)
	redeem, e := fightertransfer.RedeemScript(env, funding)
	if e != nil {
		return none, e
	}
	op, e := carrierOutpoint(r.CommitTxID, 0)
	if e != nil {
		return none, e
	}
	spend := wire.NewMsgTx(1)
	spend.AddTxIn(wire.NewTxIn(&op, nil, nil))
	returned, e := hex.DecodeString(r.ReturnPath.Script)
	if e != nil {
		return none, e
	}
	spend.AddTxOut(wire.NewTxOut(490000, returned))
	kind := "refund"
	if p.preparation.Request.Kind == "recover_reveal" {
		kind = "reveal"
		locator, e := fightertransfer.RevealLocator(env.Intent)
		if e != nil {
			return none, e
		}
		spend.AddTxOut(wire.NewTxOut(0, locator))
	} else if p.preparation.Request.Kind != "recover_refund" {
		return none, fightercarrier.ErrInvalid
	}
	sig, e := txscript.RawTxInSignature(spend, 0, redeem, txscript.SigHashAll, key)
	if e != nil {
		return none, e
	}
	spend.TxIn[0].SignatureScript, e = txscript.NewScriptBuilder().AddData(sig).AddData(redeem).Script()
	if e != nil {
		return none, e
	}
	commitRaw, e := hex.DecodeString(r.CommitRaw)
	if e != nil {
		return none, e
	}
	result := fightercarrier.SignedPackage{Version: 1, ReviewDigest: p.preparation.ReviewDigest, TransferID: r.TransferID, GymAuthorization: r.GymAuthorization, Commit: fightercarrier.RawTransaction{Raw: r.CommitRaw, TxID: r.CommitTxID, RawSHA256: carrierSHA(commitRaw)}, SpendKind: kind}
	result.Spend, e = rawCarrierTransaction(spend)
	if e != nil {
		return none, e
	}
	if e = fightercarrier.ValidateSignedPackage(result, p.preparation, o.pin); e != nil {
		return none, e
	}
	return result, nil
}

// signNewFunding is a private cryptographic leaf. The public Sign method
// checks the concrete preparation, current coins and exact owner exclusions
// before calling it and rechecks authority before returning its scratch bytes.
func (o *FighterCarrierOwner) signNewFunding(work context.Context, tx walletdb.ReadTx, p fightercarrier.Preparation, envelope fightertransfer.Envelope, lease unlockLease) (fightercarrier.SignedPackage, error) {
	var none fightercarrier.SignedPackage
	if e := fightercarrier.ValidatePreparation(p, o.pin, o.binding); e != nil {
		return none, e
	}
	funding := p.NewFunding
	if funding == nil {
		return none, fightercarrier.ErrInvalid
	}
	intent, e := carrierIntent(p)
	if e != nil || intent != envelope.Intent {
		return none, fightercarrier.ErrConflict
	}
	if e = fightertransfer.VerifyAuthorization(carrierExpected(o.pin, intent), envelope); e != nil {
		return none, e
	}
	first := funding.Inputs[0]
	key, e := o.fundingKey(tx, first.Branch, first.Index, first.Script)
	if e != nil {
		return none, e
	}
	defer key.Zero()
	var pub [33]byte
	copy(pub[:], key.PubKey().SerializeCompressed())
	redeem, e := fightertransfer.RedeemScript(envelope, pub)
	if e != nil {
		return none, e
	}
	scriptAddress, e := address.NewAddressScriptHash(redeem, o.wallet.chainParams)
	if e != nil {
		return none, e
	}
	escrow, e := txscript.PayToAddrScript(scriptAddress)
	if e != nil {
		return none, e
	}
	locator, e := fightertransfer.CommitLocator(intent)
	if e != nil {
		return none, e
	}
	returnScript, _ := hex.DecodeString(funding.ReturnPath.Script)
	commit := wire.NewMsgTx(1)
	fetch := txscript.NewMultiPrevOutFetcher(nil)
	for _, in := range funding.Inputs {
		op, e := carrierOutpoint(in.TxID, in.OutputIndex)
		if e != nil {
			return none, e
		}
		commit.AddTxIn(wire.NewTxIn(&op, nil, nil))
		script, _ := hex.DecodeString(in.Script)
		fetch.AddPrevOut(op, wire.NewTxOut(in.Atoms, script))
	}
	commit.AddTxOut(wire.NewTxOut(500000, escrow))
	commit.AddTxOut(wire.NewTxOut(0, locator))
	commit.AddTxOut(wire.NewTxOut(funding.CommitChangeAtoms, returnScript))
	hashes := txscript.NewTxSigHashes(commit, fetch)
	for n, in := range funding.Inputs {
		if e = lease.err(work); e != nil {
			return none, e
		}
		signer, e := o.fundingKey(tx, in.Branch, in.Index, in.Script)
		if e != nil {
			return none, e
		}
		script, _ := hex.DecodeString(in.Script)
		commit.TxIn[n].Witness, e = txscript.WitnessSignature(commit, hashes, n, in.Atoms, script, txscript.SigHashAll, signer, true)
		signer.Zero()
		if e != nil {
			return none, e
		}
	}
	spend := wire.NewMsgTx(1)
	op := wire.OutPoint{Hash: commit.TxHash(), Index: 0}
	spend.AddTxIn(wire.NewTxIn(&op, nil, nil))
	spend.AddTxOut(wire.NewTxOut(490000, returnScript))
	reveal, e := fightertransfer.RevealLocator(intent)
	if e != nil {
		return none, e
	}
	spend.AddTxOut(wire.NewTxOut(0, reveal))
	signature, e := txscript.RawTxInSignature(spend, 0, redeem, txscript.SigHashAll, key)
	if e != nil {
		return none, e
	}
	spend.TxIn[0].SignatureScript, e = txscript.NewScriptBuilder().AddData(signature).AddData(redeem).Script()
	if e != nil {
		return none, e
	}
	result := fightercarrier.SignedPackage{Version: 1, ReviewDigest: p.ReviewDigest, TransferID: p.Review.TransferID, GymAuthorization: hex.EncodeToString(envelope.Signature[:]), SpendKind: "reveal"}
	result.Commit, e = rawCarrierTransaction(commit)
	if e != nil {
		return none, e
	}
	result.Spend, e = rawCarrierTransaction(spend)
	if e != nil {
		return none, e
	}
	if e = fightercarrier.ValidateSignedPackage(result, p, o.pin); e != nil {
		return none, e
	}
	if e = lease.err(work); e != nil {
		return none, e
	}
	return result, nil
}
