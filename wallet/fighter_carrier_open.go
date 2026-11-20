// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"

	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func (a *HostedAllocator2) CreateFighterCarrier(ctx context.Context, j *fightercarrier.Journal) (*FighterCarrierOwner, error) {
	return a.openFighterCarrier(ctx, j, true)
}
func (a *HostedAllocator2) OpenFighterCarrier(ctx context.Context, j *fightercarrier.Journal) (*FighterCarrierOwner, error) {
	return a.openFighterCarrier(ctx, j, false)
}
func (a *HostedAllocator2) openFighterCarrier(ctx context.Context, j *fightercarrier.Journal, bind bool) (*FighterCarrierOwner, error) {
	if a == nil || j == nil || ctx == nil {
		return nil, fightercarrier.ErrInvalid
	}
	if wire.TestPoW {
		return nil, fightercarrier.ErrProfile
	}
	pin, e := allocationCarrierPin2(a.inventory.binding)
	if e != nil {
		return nil, e
	}
	identity := j.Identity()
	if identity.Pin != pin || identity.JournalID != a.inventory.binding.CarrierJournalID {
		return nil, fightercarrier.ErrConflict
	}
	return openFighterCarrier(ctx, a.wallet, j, a, waddrmgr.RestoredCarrierGuard{}, bind)
}
func (w *Wallet) OpenRestoredFighterCarrier(ctx context.Context, j *fightercarrier.Journal, guard waddrmgr.RestoredCarrierGuard) (*FighterCarrierOwner, error) {
	if ctx == nil || j == nil || w == nil {
		return nil, fightercarrier.ErrInvalid
	}
	if wire.TestPoW || w.Manager.CarrierSchema() != 15 {
		return nil, fightercarrier.ErrProfile
	}
	if j.Identity().JournalID != guard.CarrierJournalID || !restoredCarrierPinMatches(j.Identity().Pin, guard) {
		return nil, fightercarrier.ErrConflict
	}
	return openFighterCarrier(ctx, w, j, nil, guard, false)
}
func openFighterCarrier(ctx context.Context, w *Wallet, j *fightercarrier.Journal, a *HostedAllocator2, guard waddrmgr.RestoredCarrierGuard, bind bool) (out *FighterCarrierOwner, err error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if !w.ownActivityAlive() || !w.fighterCarrierMu.TryLock() {
		return nil, fightercarrier.ErrBusy
	}
	defer func() {
		if err != nil {
			w.fighterCarrierMu.Unlock()
		}
	}()
	o := &FighterCarrierOwner{owner: newAllocationLife(), wallet: w, manager: w.Manager, journal: j, pin: j.Identity().Pin, binding: j.BindingID(), allocated: a, restored: guard}
	defer func() {
		if err != nil {
			o.owner.cancel()
		}
	}()
	if a != nil {
		if e := a.check(ctx, gymaccount.View); e != nil {
			return nil, e
		}
	}
	owner, e := j.TryAcquire(ctx)
	if e != nil {
		return nil, e
	}
	defer owner.Close()
	snapshot, e := owner.Snapshot()
	if e != nil {
		return nil, e
	}
	check := func(tx walletdb.ReadTx) error {
		if a != nil {
			if _, e := a.auditPair(ctx, tx); e != nil {
				return e
			}
		} else {
			g, e := w.Manager.AuditRestoredCarrier(ctx, tx.ReadBucket(waddrmgrNamespaceKey))
			if e != nil {
				return e
			}
			x, _ := waddrmgr.MarshalRestoredCarrierGuard(g)
			y, _ := waddrmgr.MarshalRestoredCarrierGuard(guard)
			if string(x) != string(y) {
				return fightercarrier.ErrConflict
			}
		}
		return nil
	}
	if bind {
		if snapshot.Count != 0 {
			return nil, fightercarrier.ErrConflict
		}
		err = hostedWalletWrite(ctx, w, func() { o.poisoned.Store(true) }, func(tx walletdb.ReadWriteTx) error {
			if e := check(tx); e != nil {
				return e
			}
			s, e := readCarrierWalletState(ctx, tx, j.Identity().JournalID, nil)
			if e != nil {
				return e
			}
			if s.meta.State != "unbound" {
				return fightercarrier.ErrConflict
			}
			s.meta.State = "ready"
			s.meta.BindingID = o.binding
			raw, _ := json.Marshal(o.pin)
			s.meta.IdentitySHA256 = carrierSHA(raw)
			raw, _ = json.Marshal(s.meta)
			return tx.ReadWriteBucket(carrierWalletNamespace).Put(carrierMetaKey, raw)
		})
	} else {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			if e := check(tx); e != nil {
				return e
			}
			_, e := readCarrierWalletState(ctx, tx, j.Identity().JournalID, &o.pin)
			return e
		})
	}
	if err != nil {
		return nil, err
	}
	// Both directions are checked before any new selection. Signed/app-to-wallet
	// mirroring is explicit through Reconcile; a crash gap remains reserved.
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		s, e := readCarrierWalletState(ctx, tx, j.Identity().JournalID, &o.pin)
		if e != nil {
			return e
		}
		if e = o.auditExclusions(ctx, tx); e != nil {
			return e
		}
		for _, r := range s.records {
			app, e := owner.Lookup(r.RequestID)
			if e != nil || app.Request != r.Preparation.Request {
				return fightercarrier.ErrCorrupt
			}
			if app.Preparation != nil && app.PreparationDigest != r.PreparationDigest {
				return fightercarrier.ErrCorrupt
			}
			if (r.State == "retained" || r.State == "complete") && (app.SignedPackageDigest != r.SignedPackageDigest || app.SignedPackage == nil || app.SignedPackage.Commit.TxID != r.CommitTxID || app.SignedPackage.Spend.TxID != r.SpendTxID) {
				return fightercarrier.ErrCorrupt
			}
		}
		for after := uint32(0); after < snapshot.Count; {
			rows, e := owner.List(after, 8)
			if e != nil {
				return e
			}
			if len(rows) == 0 {
				return fightercarrier.ErrCorrupt
			}
			for _, app := range rows {
				found := false
				for _, r := range s.records {
					if r.RequestID == app.RequestID {
						found = true
						break
					}
				}
				if app.Preparation != nil && !found {
					return fightercarrier.ErrCorrupt
				}
			}
			after += uint32(len(rows))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if a != nil {
		if e = a.check(ctx, gymaccount.View); e != nil {
			return nil, e
		}
	}
	return o, nil
}
func (o *FighterCarrierOwner) Close() error {
	if o == nil {
		return nil
	}
	first, e := o.owner.startClose()
	if !first {
		return e
	}
	o.owner.active.Wait()
	if o.poisoned.Load() {
		o.wallet.hostedAllocationTainted.Store(true)
		e = fightercarrier.ErrPoisoned
	}
	o.wallet.fighterCarrierMu.Unlock()
	return o.owner.finishClose(e)
}

func (a *HostedAllocator2) auditFinancialAllocations2(ctx context.Context, tx walletdb.ReadTx, linked map[string]waddrmgr.HostedAllocationRecord2) error {
	pin, e := allocationCarrierPin2(a.inventory.binding)
	if e != nil {
		return e
	}
	j := a.inventory.binding.CarrierJournalID
	var meta carrierWalletMeta
	ns := tx.ReadBucket(carrierWalletNamespace)
	if ns == nil || carrierDecode(ns.Get(carrierMetaKey), 2048, &meta) != nil {
		return fightercarrier.ErrCorrupt
	}
	var expected *fightercarrier.Pin
	if meta.State == "ready" {
		expected = &pin
	}
	s, e := readCarrierWalletState(ctx, tx, j, expected)
	if e != nil {
		return e
	}
	seen := map[string]bool{}
	for _, r := range s.records {
		key := "carrier_return:" + r.RequestID
		link, ok := linked[key]
		if !ok || link.Outcome != "consumed" || link.ConsumerBindingID != r.BindingID || link.PreparationDigest != r.PreparationDigest || r.Preparation.NewFunding == nil {
			return fightercarrier.ErrCorrupt
		}
		p := r.Preparation.NewFunding
		if p.AllocationID != link.AllocationID || p.ReservationDigest != link.ReservationDigest || p.ReturnPath.Address != link.Address || p.ReturnPath.Script != link.Script || p.ReturnPath.Index != link.SelectedIndex || p.ReturnPath.Branch != link.Branch {
			return fightercarrier.ErrCorrupt
		}
		seen[key] = true
	}
	if ns = tx.ReadBucket(withdrawalNamespace); ns != nil {
		ops := ns.NestedReadBucket(withdrawalOperations)
		if ops == nil {
			return fightercarrier.ErrCorrupt
		}
		count := 0
		e = ops.ForEach(func(k, v []byte) error {
			count++
			if count > 128 || len(k) != 32 {
				return fightercarrier.ErrCorrupt
			}
			var r CandidateWithdrawalRecord
			if withdrawalDecode(v, 32768, &r) != nil {
				return fightercarrier.ErrCorrupt
			}
			key := "withdrawal_change:" + hex.EncodeToString(k)
			link, ok := linked[key]
			digest, e := CandidateWithdrawalDraftDigest(r.Draft)
			if e != nil || !ok || link.Outcome != "consumed" || link.ConsumerBindingID != r.Draft.BindingID || link.PreparationDigest != digest || r.DraftDigest != digest || r.Draft.Change.Address != link.Address || r.Draft.Change.Script != link.Script || r.Draft.Change.Index != link.SelectedIndex {
				return fightercarrier.ErrCorrupt
			}
			seen[key] = true
			return nil
		})
		if e != nil {
			return e
		}
	}
	for key, link := range linked {
		if link.Outcome == "consumed" && !seen[key] || link.Outcome == "burned" && seen[key] {
			return fightercarrier.ErrCorrupt
		}
	}
	return auditPurposeExclusions(ctx, tx, pin, j, a.inventory.binding.WithdrawalJournalID)
}
