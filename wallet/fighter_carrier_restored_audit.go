// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"encoding/hex"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/fightercarrier"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// Opening a historical owner checks stored range/path identity, not whether
// its formerly authorized coins remain unspent. Current action checks use the
// retained ownership/node capability separately.
func auditRestoredCarrierRows(ctx context.Context, tx walletdb.ReadTx, manager *waddrmgr.Manager, params *chaincfg.Params, pin fightercarrier.Pin, journal string) error {
	ns := tx.ReadBucket(waddrmgrNamespaceKey)
	g, e := manager.AuditRestoredCarrier(ctx, ns)
	if e != nil {
		return e
	}
	if !restoredCarrierPinMatches(pin, g) {
		return fightercarrier.ErrCorrupt
	}
	state, e := readCarrierWalletState(ctx, tx, journal, &pin)
	if e != nil {
		return e
	}
	// This private, non-live reader is never returned or used as a signing
	// capability. It shares only the exact public path validation leaves.
	reader := &FighterCarrierOwner{manager: manager, wallet: &Wallet{Manager: manager, chainParams: params}, pin: pin, binding: state.meta.BindingID}
	paths := CandidateWithdrawals{wallet: reader.wallet}
	cursors := g.ActivationCursors
	for _, row := range state.records {
		if e = ctx.Err(); e != nil {
			return e
		}
		p := row.Preparation
		if p.RecoveryFunding != nil {
			if e = reader.validateRecoveryPaths(ctx, tx, p); e != nil {
				return e
			}
			continue
		}
		if p.NewFunding == nil || p.RestoredAllocation == nil {
			return fightercarrier.ErrCorrupt
		}
		a := p.RestoredAllocation
		for n, c := range cursors {
			if a.CursorsBefore[n] != c {
				return fightercarrier.ErrCorrupt
			}
			cursors[n] = a.CursorsAfter[n]
		}
		r := waddrmgr.HostedAllocationRange{Purpose: 84, Branch: 1, StartIndex: a.StartIndex, EndIndex: a.EndIndex, SelectedIndex: a.SelectedIndex, InvalidIndices: a.InvalidIndices, Address: p.NewFunding.ReturnPath.Address, Script: p.NewFunding.ReturnPath.Script}
		if e = manager.CheckRestoredCarrierRange(ctx, ns, r); e != nil {
			return e
		}
		for _, in := range p.NewFunding.Inputs {
			script, _ := hex.DecodeString(in.Script)
			branch, index, e := paths.path(tx, script)
			if e != nil || branch != in.Branch || index != in.Index {
				return fightercarrier.ErrCorrupt
			}
		}
	}
	m, e := manager.ReadRestoredCarrierManifest(ctx, ns)
	if e != nil {
		return e
	}
	for n, a := range m.Accounts {
		if a.NextExternal != cursors[2*n] || a.NextInternal != cursors[2*n+1] {
			return fightercarrier.ErrCorrupt
		}
	}
	return ctx.Err()
}
