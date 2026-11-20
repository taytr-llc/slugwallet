// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slug/fighterownership"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func (o *FighterCarrierOwner) requireIntent(ctx context.Context, request fightercarrier.Request) error {
	owner, e := o.journal.TryAcquire(ctx)
	if e != nil {
		return e
	}
	defer owner.Close()
	r, e := owner.Lookup(request.RequestID)
	if e != nil {
		return e
	}
	if r.Request != request || r.Stage != "intent" || r.Preparation != nil {
		return fightercarrier.ErrConflict
	}
	return nil
}
func (o *FighterCarrierOwner) Prepare(ctx context.Context, plan *CarrierFundingPlan, public *fighterownership.PreparedTransfer) (*PreparedFighterTransfer, error) {
	if o == nil || plan == nil || plan.funding == nil || plan.funding.owner != o || public == nil {
		return nil, fightercarrier.ErrInvalid
	}
	work, end, e := o.owner.acquire(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	if e = o.authorize(work); e != nil {
		return nil, e
	}
	f := plan.funding
	if f.public != nil && f.public != public {
		return nil, fightercarrier.ErrConflict
	}
	f.public = public
	if _, e = f.intent(); e != nil {
		return nil, e
	}
	if e = public.Check(work); e != nil {
		return nil, e
	}
	if e = o.requireIntent(work, f.request); e != nil {
		return nil, e
	}
	var prepared fightercarrier.Preparation
	if o.allocated != nil {
		request, e := f.request2()
		if e != nil {
			return nil, e
		}
		p, e := o.allocated.planCarrier(work, f.request.RequestID, request, f)
		if e != nil {
			return nil, e
		}
		reservation, e := o.allocated.Reserve(work, p)
		if e != nil {
			return nil, e
		}
		receipt, e := o.allocated.Consume(work, reservation)
		if e != nil {
			return nil, e
		}
		ack, e := o.allocated.Acknowledge(work, receipt)
		if e != nil {
			return nil, e
		}
		done, e := o.allocated.Finalize(work, ack)
		if e != nil {
			return nil, e
		}
		if done.carrier == nil {
			return nil, fightercarrier.ErrCorrupt
		}
		prepared = cloneCarrierPreparation(*done.carrier)
	} else {
		if !o.wallet.newAddrMtx.TryLock() {
			return nil, fightercarrier.ErrBusy
		}
		defer o.wallet.newAddrMtx.Unlock()
		var p *waddrmgr.RestoredCarrierPlan
		var r waddrmgr.HostedAllocationRange
		var before [8]uint32
		e = walletdb.View(o.wallet.db, func(tx walletdb.ReadTx) error {
			if e := o.validateCarrierInputs(work, tx, f.inputs, "", ""); e != nil {
				return e
			}
			var e error
			p, r, before, e = o.manager.PlanRestoredCarrier(work, tx.ReadBucket(waddrmgrNamespaceKey))
			return e
		})
		if e != nil {
			return nil, e
		}
		after := before
		after[5] = r.EndIndex
		allocated := &fightercarrier.RestoredAllocation{StartIndex: r.StartIndex, EndIndex: r.EndIndex, SelectedIndex: r.SelectedIndex, InvalidIndices: append([]uint32{}, r.InvalidIndices...), CursorsBefore: append([]uint32(nil), before[:]...), CursorsAfter: append([]uint32(nil), after[:]...)}
		prepared, e = f.preparation(fightercarrier.ReturnPath{Address: r.Address, Script: r.Script, Branch: 1, Index: r.SelectedIndex}, "", allocated)
		if e != nil {
			return nil, e
		}
		e = hostedWalletWrite(work, o.wallet, func() { o.poisoned.Store(true) }, func(tx walletdb.ReadWriteTx) error {
			if e := o.validateCarrierInputs(work, tx, f.inputs, "", ""); e != nil {
				return e
			}
			if e := o.manager.ConsumeRestoredCarrier(work, tx.ReadWriteBucket(waddrmgrNamespaceKey), p); e != nil {
				return e
			}
			return o.commitPreparation(work, tx, prepared)
		})
		if e != nil {
			return nil, e
		}
		if e = o.watch(work, r.Address); e != nil {
			return nil, e
		}
	}
	if e = public.Check(work); e != nil {
		return nil, e
	}
	if e = o.authorize(work); e != nil {
		return nil, e
	}
	digest, e := fightercarrier.PreparationDigest(prepared)
	if e != nil {
		return nil, e
	}
	return &PreparedFighterTransfer{owner: o, preparation: prepared, digest: digest, public: public}, nil
}

// ResumePrepared preserves a committed preparation. It never selects new coins
// or recreates a lost unconsumed hosted plan. A fresh public predecessor
// capability must bind the same tuple and economically reviewed request.
func (o *FighterCarrierOwner) ResumePrepared(ctx context.Context, id string, public *fighterownership.PreparedTransfer) (*PreparedFighterTransfer, error) {
	if !withdrawalHex(id, 32, true) || public == nil {
		return nil, fightercarrier.ErrInvalid
	}
	work, end, e := o.owner.acquire(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	if e = o.authorize(work); e != nil {
		return nil, e
	}
	if e = public.Check(work); e != nil {
		return nil, e
	}
	var p fightercarrier.Preparation
	var digest string
	e = walletdb.View(o.wallet.db, func(tx walletdb.ReadTx) error {
		s, e := readCarrierWalletState(work, tx, o.journal.Identity().JournalID, &o.pin)
		if e != nil {
			return e
		}
		for _, r := range s.records {
			if r.RequestID != id {
				continue
			}
			if r.State != "prepared" || r.Preparation.NewFunding == nil {
				return fightercarrier.ErrConflict
			}
			p = cloneCarrierPreparation(r.Preparation)
			digest = r.PreparationDigest
			f := &preparedCarrierFunding{owner: o, request: p.Request, inputs: p.NewFunding.Inputs, total: p.NewFunding.TotalInputAtoms, public: public}
			if _, e = f.intent(); e != nil {
				return e
			}
			if e = o.auditExclusions(work, tx); e != nil {
				return e
			}
			return o.validatePreparedInputs(work, tx, p)
		}
		return fightercarrier.ErrNotFound
	})
	if e != nil {
		return nil, e
	}
	if o.allocated != nil {
		ack, e := o.allocated.Resolve(work, id)
		if e != nil {
			return nil, e
		}
		done, e := o.allocated.Finalize(work, ack)
		if e != nil {
			return nil, e
		}
		if done.carrier == nil {
			return nil, fightercarrier.ErrCorrupt
		}
		d, e := fightercarrier.PreparationDigest(*done.carrier)
		if e != nil || d != digest {
			return nil, fightercarrier.ErrConflict
		}
	} else if e = o.watch(work, p.NewFunding.ReturnPath.Address); e != nil {
		return nil, e
	}
	if e = o.authorize(work); e != nil {
		return nil, e
	}
	return &PreparedFighterTransfer{owner: o, preparation: p, digest: digest, public: public}, nil
}

func (o *FighterCarrierOwner) watch(ctx context.Context, encoded string) error {
	parsed, e := address.DecodeAddress(encoded, o.wallet.chainParams)
	if e != nil || parsed.EncodeAddress() != encoded {
		return fightercarrier.ErrCorrupt
	}
	client, e := o.wallet.requireChainClient()
	if e != nil {
		return e
	}
	backend := allocationWatchClient(client)
	if backend == nil || backend.Client == nil || backend.Disconnected() {
		return fightercarrier.ErrConflict
	}
	work, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	joined := make(chan struct{})
	stop := context.AfterFunc(work, func() { backend.Client.Shutdown(); close(joined) })
	e = backend.NotifyReceived([]address.Address{parsed})
	if !stop() {
		<-joined
	}
	if e != nil || work.Err() != nil {
		o.poisoned.Store(true)
		o.wallet.hostedAllocationTainted.Store(true)
		return errors.Join(fightercarrier.ErrOutcomeUnknown, e, work.Err())
	}
	return nil
}

// Reconcile accepts only a live lease from the exact retained concrete app
// journal. A DTO, expired lease or another journal cannot release reservations.
func (o *FighterCarrierOwner) Reconcile(ctx context.Context, proof *fightercarrier.Reconciliation) error {
	if o == nil || proof == nil || !o.journal.OwnsReconciliation(proof) {
		return fightercarrier.ErrUnauthorized
	}
	if e := proof.Check(); e != nil {
		return e
	}
	work, end, e := o.owner.acquire(ctx)
	if e != nil {
		return e
	}
	defer end()
	capability := gymaccount.View
	if proof.Kind() == "abandoned" {
		capability = gymaccount.FighterTransfer
	} else if proof.Kind() != "retained" && proof.Kind() != "complete" {
		return fightercarrier.ErrConflict
	}
	// Both original-session fences are outside the wallet transaction. A signed
	// journal permits bookkeeping under View; releasing unsigned inputs still
	// requires the original FighterTransfer capability.
	check := func() error {
		if e := o.alive(); e != nil {
			return e
		}
		if e := proof.Check(); e != nil {
			return e
		}
		if o.allocated != nil {
			return o.allocated.check(work, capability)
		}
		return work.Err()
	}
	if e = check(); e != nil {
		return e
	}
	poison := func() {
		o.poisoned.Store(true)
		o.wallet.hostedAllocationTainted.Store(true)
		if o.allocated != nil {
			o.allocated.poisoned.Store(true)
		}
	}
	e = hostedWalletWrite(work, o.wallet, poison, func(tx walletdb.ReadWriteTx) error {
		if e := proof.Check(); e != nil {
			return e
		}
		j, w := o.carrierIDs()
		s, e := readCarrierWalletState(work, tx, j, &o.pin)
		if e != nil {
			return e
		}
		if e = o.auditExclusions(work, tx); e != nil {
			return e
		}
		for _, old := range s.records {
			if old.RequestID != proof.RequestID() {
				continue
			}
			if old.PreparationDigest != proof.PreparationDigest() {
				return fightercarrier.ErrConflict
			}
			r := old
			target := proof.Kind()
			if target != "retained" && target != "complete" && target != "abandoned" {
				return fightercarrier.ErrConflict
			}
			if old.State == target {
				if target == "abandoned" || old.SignedPackageDigest == proof.SignedPackageDigest() && old.CommitTxID == proof.CommitTxID() && old.SpendTxID == proof.SpendTxID() {
					return proof.Check()
				}
				return fightercarrier.ErrConflict
			}
			if target == "abandoned" {
				if old.State != "prepared" {
					return fightercarrier.ErrConflict
				}
				if e = removePreparedPurposeExclusions(work, tx, o.pin.ManagerSchema, j, w, "carrier", old.RequestID, o.binding, old.PreparationDigest); e != nil {
					return e
				}
			} else {
				if old.State != "prepared" && old.State != "retained" {
					return fightercarrier.ErrConflict
				}
				if old.State == "retained" && (old.SignedPackageDigest != proof.SignedPackageDigest() || old.CommitTxID != proof.CommitTxID() || old.SpendTxID != proof.SpendTxID()) {
					return fightercarrier.ErrConflict
				}
				r.SignedPackageDigest = proof.SignedPackageDigest()
				r.CommitTxID = proof.CommitTxID()
				r.SpendTxID = proof.SpendTxID()
				ops := make([]wire.OutPoint, 0, 17)
				if r.Preparation.NewFunding != nil {
					for _, in := range r.Preparation.NewFunding.Inputs {
						op, e := carrierOutpoint(in.TxID, in.OutputIndex)
						if e != nil {
							return e
						}
						ops = append(ops, op)
					}
				}
				op, e := carrierOutpoint(r.CommitTxID, 0)
				if e != nil {
					return e
				}
				ops = append(ops, op)
				if e = putPurposeExclusions(work, tx, o.pin.ManagerSchema, j, w, purposeExclusion{1, "carrier", r.RequestID, o.binding, r.PreparationDigest, "retained"}, ops); e != nil {
					return e
				}
			}
			r.State = target
			if e = fightercarrier.ValidateWalletRecord(r, o.pin, o.binding); e != nil {
				return e
			}
			raw, e := json.Marshal(r)
			if e != nil || len(raw) > fightercarrier.MaxWalletRecordBytes {
				return fightercarrier.ErrCapacity
			}
			ns := tx.ReadWriteBucket(carrierWalletNamespace)
			key, _ := hex.DecodeString(r.RequestID)
			if e = ns.NestedReadWriteBucket(carrierRecordsKey).Put(key, raw); e != nil {
				return e
			}
			if target == "complete" || target == "abandoned" {
				s.meta.ActiveRequestID = ""
			}
			raw, _ = json.Marshal(s.meta)
			if e = ns.Put(carrierMetaKey, raw); e != nil {
				return e
			}
			return proof.Check()
		}
		return fightercarrier.ErrNotFound
	})
	if e != nil {
		if o.poisoned.Load() {
			return errors.Join(fightercarrier.ErrOutcomeUnknown, e)
		}
		return e
	}
	if e = check(); e != nil {
		// The committed reservation state remains authoritative. Losing the
		// original owner before acknowledgment requires a full reopen; it never
		// undoes the database commit or substitutes a newer account session.
		poison()
		return errors.Join(fightercarrier.ErrOutcomeUnknown, e)
	}
	return nil
}
