// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/gymauth"
	"github.com/taytr-llc/slug/prospect"
	"github.com/taytr-llc/slug/prospectnode"
	"github.com/taytr-llc/slug/prospectworker"
	"github.com/taytr-llc/slugwallet/recovery"
)

func (a *HostedAllocator2) CapturePublicRecovery(ctx context.Context) (recovery.Manifest, error) {
	work, end, e := a.acquire(ctx)
	if e != nil {
		return recovery.Manifest{}, e
	}
	defer end()
	if e = a.check(work, gymaccount.View); e != nil {
		return recovery.Manifest{}, e
	}
	out, e := a.wallet.hostedAllocationPublic2(work)
	if e != nil {
		return recovery.Manifest{}, e
	}
	if e = a.check(work, gymaccount.View); e != nil {
		return recovery.Manifest{}, e
	}
	return out, nil
}
func (a *HostedAllocator2) CaptureOwnActivity(ctx context.Context) (OwnActivitySnapshot, error) {
	work, end, e := a.acquire(ctx)
	if e != nil {
		return OwnActivitySnapshot{}, e
	}
	defer end()
	if e = a.check(work, gymaccount.View); e != nil {
		return OwnActivitySnapshot{}, e
	}
	out, e := a.wallet.hostedAllocationActivity2(work)
	if e != nil {
		return OwnActivitySnapshot{}, e
	}
	if e = a.check(work, gymaccount.View); e != nil {
		return OwnActivitySnapshot{}, e
	}
	return out, nil
}
func (a *HostedAllocator2) GymIdentity(ctx context.Context) (GymIdentity, error) {
	work, end, e := a.acquire(ctx)
	if e != nil {
		return GymIdentity{}, e
	}
	defer end()
	if e = a.check(work, gymaccount.View); e != nil {
		return GymIdentity{}, e
	}
	out, e := a.wallet.hostedAllocationGymIdentity2(work)
	if e != nil {
		return GymIdentity{}, e
	}
	if e = a.check(work, gymaccount.View); e != nil {
		return GymIdentity{}, e
	}
	return out, nil
}

// ProspectSigner preserves the policy-specific signing surface. It captures the
// attachment's original login session, with no token supplier or renewal path.
func (a *HostedAllocator2) ProspectSigner(ctx context.Context, policy prospectnode.Policy) (prospectworker.Signer, error) {
	work, end, e := a.acquire(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	if e = a.check(work, gymaccount.View); e != nil {
		return nil, e
	}
	signer, e := a.wallet.hostedAllocationProspectSigner2(work, policy)
	if e != nil {
		return nil, e
	}
	if e = a.check(work, gymaccount.View); e != nil {
		return nil, e
	}
	return func(ctx context.Context, c prospect.Context, p prospect.Proof) (gymauth.Authorization, error) {
		work, end, e := a.acquire(ctx)
		if e != nil {
			return gymauth.Authorization{}, e
		}
		defer end()
		if e = a.check(work, gymaccount.View); e != nil {
			return gymauth.Authorization{}, e
		}
		auth, e := signer(work, c, p)
		if e != nil {
			return gymauth.Authorization{}, e
		}
		if e = a.check(work, gymaccount.View); e != nil {
			return gymauth.Authorization{}, e
		}
		return auth, nil
	}, nil
}

// LookupReceiveAllocation is a read-only exact-ID presence check. It performs no
// local reconciliation, acknowledgement, derivation, watch, or disclosure.
func (a *HostedAllocator2) LookupReceiveAllocation(ctx context.Context, id string) error {
	if !withdrawalHex(id, 32, true) {
		return ErrAllocationInvalid
	}
	work, end, e := a.acquire(ctx)
	if e != nil {
		return e
	}
	defer end()
	if e = a.check(work, gymaccount.View); e != nil {
		return e
	}
	row, ok := a.inventory.rows[id]
	var result error
	if !ok {
		result = ErrAllocationNotFound
	} else if row.Reservation.Request.Kind != "receive" {
		result = ErrAllocationConflict
	}
	if e = a.check(work, gymaccount.View); e != nil {
		return e
	}
	return result
}
