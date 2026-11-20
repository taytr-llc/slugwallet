// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/recovery"
)

const (
	HostedAllocationMaxRecords        = 1024
	HostedAllocationMaxBytes          = 4194304
	HostedAllocationMaxAttempts       = 128
	HostedAllocationMaxIndex          = 4096
	allocationRowMax                  = 4096
	allocationBatchMax                = 12288
	allocationMarkerName              = "SLUG-HOSTED-ALLOCATION-INVENTORY.json"
	allocationApplication             = "slug-hosted-allocation-inventory"
	allocationMaxTime           int64 = 253402300799999
)

var (
	ErrAllocationInvalid        = errors.New("invalid hosted allocation")
	ErrAllocationProfile        = errors.New("unsupported hosted allocation profile")
	ErrAllocationBusy           = errors.New("hosted allocation busy")
	ErrAllocationClosed         = errors.New("hosted allocation closed")
	ErrAllocationNotFound       = errors.New("hosted allocation not found")
	ErrAllocationConflict       = errors.New("hosted allocation conflict")
	ErrAllocationCapacity       = errors.New("hosted allocation capacity")
	ErrAllocationUnavailable    = errors.New("hosted allocation unavailable")
	ErrAllocationCorrupt        = errors.New("hosted allocation corrupt")
	ErrAllocationStorage        = errors.New("hosted allocation storage failed")
	ErrAllocationOutcomeUnknown = errors.New("hosted allocation outcome unknown")
	ErrAllocationPoisoned       = errors.New("hosted allocation poisoned")
	ErrAllocationCleanup        = errors.New("hosted allocation cleanup failed")
	ErrAllocationResumeRequired = errors.New("hosted allocation resume required")
)

// HostedAllocationEpochFence retains the original parent view. The inventory
// independently checks the concrete account authority; this is not an authority
// callback or a replacement session-token slot.
type HostedAllocationEpochFence func(context.Context, func(check func() error) error) error

// AllocationBinding is public immutable setup data, never an allocation proof.
type AllocationBinding struct {
	Version         uint32            `json:"version"`
	InventoryID     string            `json:"inventory_id"`
	AuthorityID     string            `json:"authority_id"`
	AccountID       string            `json:"account_id"`
	PrincipalID     string            `json:"principal_id"`
	ProvisionID     string            `json:"provision_id"`
	HostedVaultID   string            `json:"hosted_vault_id"`
	RetentionID     string            `json:"retention_id"`
	WalletOwnerID   string            `json:"wallet_owner_id"`
	SourceBindingID string            `json:"source_binding_id"`
	ManagerSchema   uint32            `json:"manager_schema"`
	MaxAllocations  uint32            `json:"max_allocations"`
	MaxBytes        uint32            `json:"max_bytes"`
	MaxPlanAttempts uint32            `json:"max_plan_attempts"`
	MaxBranchIndex  uint32            `json:"max_branch_index"`
	InitialManifest recovery.Manifest `json:"initial_manifest"`
}

type AllocationRequest struct {
	Version             uint32 `json:"version"`
	Kind                string `json:"kind"`
	ConsumerID          string `json:"consumer_id"`
	Purpose             uint32 `json:"purpose"`
	Branch              uint32 `json:"branch"`
	WithdrawalBindingID string `json:"withdrawal_binding_id"`
	Recipient           string `json:"recipient"`
	RecipientScript     string `json:"recipient_script"`
	AmountAtoms         int64  `json:"amount_atoms"`
	FeeRateAtomsPerKB   int64  `json:"fee_rate_atoms_per_kb"`
	FeeCeilingAtoms     int64  `json:"fee_ceiling_atoms"`
	MinConfirmations    uint32 `json:"min_confirmations"`
	InputPurpose        uint32 `json:"input_purpose"`
	ChangePurpose       uint32 `json:"change_purpose"`
	Account             uint32 `json:"account"`
	TxVersion           int32  `json:"tx_version"`
	InputSequence       uint32 `json:"input_sequence"`
	LockTime            uint32 `json:"lock_time"`
	SighashType         uint32 `json:"sighash_type"`
}

// These bytes are private storage values. Only the concrete allocator mints
// AllocationReservation and AllocationReceipt capabilities from their state.
type allocationReservationValue struct {
	Version        uint32            `json:"version"`
	Sequence       uint32            `json:"sequence"`
	AllocationID   string            `json:"allocation_id"`
	BindingID      string            `json:"binding_id"`
	Request        AllocationRequest `json:"request"`
	Purpose        uint32            `json:"purpose"`
	Branch         uint32            `json:"branch"`
	StartIndex     uint32            `json:"start_index"`
	EndIndex       uint32            `json:"end_index"`
	SelectedIndex  uint32            `json:"selected_index"`
	InvalidIndices []uint32          `json:"invalid_indices"`
	Address        string            `json:"address"`
	Script         string            `json:"script"`
	ReservedAtMS   int64             `json:"reserved_at_ms"`
}
type allocationRow struct {
	Reservation        allocationReservationValue `json:"reservation"`
	ReservationDigest  string                     `json:"reservation_digest"`
	Phase              string                     `json:"phase"`
	CompletedAtMS      int64                      `json:"completed_at_ms"`
	WalletRecordDigest string                     `json:"wallet_record_digest"`
	DraftDigest        string                     `json:"draft_digest"`
}
type allocationMarker struct {
	Application string            `json:"application"`
	Version     uint32            `json:"version"`
	InventoryID string            `json:"inventory_id"`
	Binding     AllocationBinding `json:"binding"`
}
type allocationMetadata struct {
	Version            uint32    `json:"version"`
	MarkerSHA256       string    `json:"marker_sha256"`
	Revision           uint32    `json:"revision"`
	Allocations        uint32    `json:"allocations"`
	ClockHighWaterMS   int64     `json:"clock_high_water_ms"`
	ActiveAllocationID string    `json:"active_allocation_id"`
	Cursors            [8]uint32 `json:"cursors"`
}

// AllocationInventoryStatus contains no undisclosed address or financial plan.
type AllocationInventoryStatus struct {
	Revision         uint32
	Allocations      uint32
	PendingReceiveID string
	IssuedReceiveID  string
	ObservedAtMS     int64
}

type HostedAllocationInventory struct {
	owner         allocationLife
	accounts      *gymaccount.Store
	binding       AllocationBinding
	bindingID     string
	path          string
	marker        allocationMarker
	db            *leveldb.DB
	meta          allocationMetadata
	rows          map[string]allocationRow
	order         []string
	bytes         int
	poisoned      atomic.Bool
	revision      atomic.Uint32
	writeBatch    func(*leveldb.Batch, *opt.WriteOptions) error
	now           func() time.Time
	attachmentsMu sync.Mutex
	attachments   map[*HostedAllocator]bool
	leasesMu      sync.Mutex
	leases        map[*HostedRecoveryHeadLease]bool
}

// Each operation registers its real joined lifetime before acquiring the gate.
// A retained handle is not active work and cannot prevent Close indefinitely.
type allocationLife struct {
	mu       sync.Mutex
	life     context.Context
	cancel   context.CancelFunc
	active   sync.WaitGroup
	gate     chan struct{}
	closing  atomic.Bool
	closed   chan struct{}
	closeErr error
}

func newAllocationLife() allocationLife {
	ctx, cancel := context.WithCancel(context.Background())
	return allocationLife{life: ctx, cancel: cancel, gate: make(chan struct{}, 1), closed: make(chan struct{})}
}
func (l *allocationLife) acquire(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, ErrAllocationInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	l.mu.Lock()
	if l.closing.Load() {
		l.mu.Unlock()
		return nil, nil, ErrAllocationClosed
	}
	l.active.Add(1)
	l.mu.Unlock()
	child, cancel := context.WithTimeout(ctx, 30*time.Second)
	stop := context.AfterFunc(l.life, cancel)
	done := func() { stop(); cancel(); l.active.Done() }
	select {
	case l.gate <- struct{}{}:
	default:
		done()
		return nil, nil, ErrAllocationBusy
	}
	if err := child.Err(); err != nil {
		<-l.gate
		done()
		return nil, nil, err
	}
	return child, func() { <-l.gate; done() }, nil
}
func (l *allocationLife) startClose() (bool, error) {
	l.mu.Lock()
	if l.closing.Load() {
		ch := l.closed
		l.mu.Unlock()
		<-ch
		return false, l.closeErr
	}
	l.closing.Store(true)
	l.cancel()
	l.mu.Unlock()
	return true, nil
}
func (l *allocationLife) finishClose(err error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closeErr = err
	close(l.closed)
	return err
}
func cloneAllocationBinding(b AllocationBinding) AllocationBinding {
	b.InitialManifest.Accounts = append([]recovery.Account(nil), b.InitialManifest.Accounts...)
	return b
}
func cloneAllocationRow(r allocationRow) allocationRow {
	r.Reservation.InvalidIndices = append([]uint32{}, r.Reservation.InvalidIndices...)
	return r
}
