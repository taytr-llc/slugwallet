// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/recovery"
	"sync"
	"sync/atomic"
	"time"
)

// AllocationBinding2 is public immutable setup data, never an allocation proof.
type AllocationBinding2 struct {
	Version             uint32            `json:"version"`
	InventoryID         string            `json:"inventory_id"`
	AuthorityID         string            `json:"authority_id"`
	AccountID           string            `json:"account_id"`
	PrincipalID         string            `json:"principal_id"`
	ProvisionID         string            `json:"provision_id"`
	HostedVaultID       string            `json:"hosted_vault_id"`
	RetentionID         string            `json:"retention_id"`
	WalletOwnerID       string            `json:"wallet_owner_id"`
	SourceBindingID     string            `json:"source_binding_id"`
	OwnershipPinID      string            `json:"ownership_pin_id"`
	CarrierJournalID    string            `json:"carrier_journal_id"`
	WithdrawalJournalID string            `json:"withdrawal_journal_id"`
	ManagerSchema       uint32            `json:"manager_schema"`
	MaxAllocations      uint32            `json:"max_allocations"`
	MaxBytes            uint32            `json:"max_bytes"`
	MaxPlanAttempts     uint32            `json:"max_plan_attempts"`
	MaxBranchIndex      uint32            `json:"max_branch_index"`
	InitialManifest     recovery.Manifest `json:"initial_manifest"`
}

type AllocationRequest2 struct {
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
	CarrierBindingID    string `json:"carrier_binding_id"`
	OwnershipPinID      string `json:"ownership_pin_id"`
	PriorStateID        string `json:"prior_state_id"`
	RecipientGym        string `json:"recipient_gym"`
	FundingDigest       string `json:"funding_digest"`
	EscrowAtoms         int64  `json:"escrow_atoms"`
	CommitFeeAtoms      int64  `json:"commit_fee_atoms"`
	SpendFeeAtoms       int64  `json:"spend_fee_atoms"`
	MinChangeAtoms      int64  `json:"min_change_atoms"`
}

// These bytes are private storage values. Only the concrete allocator mints
// AllocationReservation2 and AllocationReceipt2 capabilities from their state.
type allocationReservationValue2 struct {
	Version        uint32             `json:"version"`
	Sequence       uint32             `json:"sequence"`
	AllocationID   string             `json:"allocation_id"`
	BindingID      string             `json:"binding_id"`
	Request        AllocationRequest2 `json:"request"`
	Purpose        uint32             `json:"purpose"`
	Branch         uint32             `json:"branch"`
	StartIndex     uint32             `json:"start_index"`
	EndIndex       uint32             `json:"end_index"`
	SelectedIndex  uint32             `json:"selected_index"`
	InvalidIndices []uint32           `json:"invalid_indices"`
	Address        string             `json:"address"`
	Script         string             `json:"script"`
	ReservedAtMS   int64              `json:"reserved_at_ms"`
}
type allocationRow2 struct {
	Reservation        allocationReservationValue2 `json:"reservation"`
	ReservationDigest  string                      `json:"reservation_digest"`
	Phase              string                      `json:"phase"`
	CompletedAtMS      int64                       `json:"completed_at_ms"`
	WalletRecordDigest string                      `json:"wallet_record_digest"`
	PreparationDigest  string                      `json:"preparation_digest"`
}
type allocationMarker2 struct {
	Application string             `json:"application"`
	Version     uint32             `json:"version"`
	InventoryID string             `json:"inventory_id"`
	Binding     AllocationBinding2 `json:"binding"`
}
type allocationMetadata2 struct {
	Version            uint32    `json:"version"`
	MarkerSHA256       string    `json:"marker_sha256"`
	Revision           uint32    `json:"revision"`
	Allocations        uint32    `json:"allocations"`
	ClockHighWaterMS   int64     `json:"clock_high_water_ms"`
	ActiveAllocationID string    `json:"active_allocation_id"`
	Cursors            [8]uint32 `json:"cursors"`
}

type HostedAllocationInventory2 struct {
	owner         allocationLife
	accounts      *gymaccount.Store
	binding       AllocationBinding2
	bindingID     string
	path          string
	marker        allocationMarker2
	db            *leveldb.DB
	meta          allocationMetadata2
	rows          map[string]allocationRow2
	order         []string
	bytes         int
	poisoned      atomic.Bool
	revision      atomic.Uint32
	writeBatch    func(*leveldb.Batch, *opt.WriteOptions) error
	now           func() time.Time
	attachmentsMu sync.Mutex
	attachments   map[*HostedAllocator2]bool
	leasesMu      sync.Mutex
	leases        map[*HostedRecoveryHeadLease2]bool
}

func cloneAllocationBinding2(b AllocationBinding2) AllocationBinding2 {
	b.InitialManifest.Accounts = append([]recovery.Account(nil), b.InitialManifest.Accounts...)
	return b
}
func cloneAllocationRow2(r allocationRow2) allocationRow2 {
	r.Reservation.InvalidIndices = append([]uint32{}, r.Reservation.InvalidIndices...)
	return r
}

const allocationMarkerName2 = "SLUG-HOSTED-TRANSFER-ALLOCATION.json"
const allocationApplication2 = "slug-hosted-transfer-allocation-inventory"
const allocationRowMax2 = 8192
const allocationBatchMax2 = 24576
