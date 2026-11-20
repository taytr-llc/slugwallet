// Copyright (c) 2026 The SLUG developers. ISC license.
package waddrmgr

import (
	"encoding/json"

	"github.com/taytr-llc/slugwallet/recovery"
)

const HostedTransferManagerVersion uint32 = 14
const RestoredCarrierManagerVersion uint32 = 15
const HostedAllocationNamespace2 = "slug-hosted-allocation-v2"

var hostedAllocationGuardKey2 = []byte("hostedallocationguardv2")
var restoredCarrierGuardKey = []byte("restoredcarrierguard")

type HostedAllocationGuard2 struct {
	Version               uint32 `json:"version"`
	State                 string `json:"state"`
	InventoryID           string `json:"inventory_id"`
	AuthorityID           string `json:"authority_id"`
	AccountID             string `json:"account_id"`
	WalletOwnerID         string `json:"wallet_owner_id"`
	SourceBindingID       string `json:"source_binding_id"`
	OwnershipPinID        string `json:"ownership_pin_id"`
	CarrierJournalID      string `json:"carrier_journal_id"`
	WithdrawalJournalID   string `json:"withdrawal_journal_id"`
	InitialManifestSHA256 string `json:"initial_manifest_sha256"`
	BindingID             string `json:"binding_id"`
}
type HostedAllocationMeta2 struct {
	Version           uint32    `json:"version"`
	GuardSHA256       string    `json:"guard_sha256"`
	CompletedSequence uint32    `json:"completed_sequence"`
	Cursors           [8]uint32 `json:"cursors"`
}
type HostedAllocationRecord2 struct {
	Version           uint32    `json:"version"`
	InventoryID       string    `json:"inventory_id"`
	BindingID         string    `json:"binding_id"`
	Sequence          uint32    `json:"sequence"`
	AllocationID      string    `json:"allocation_id"`
	ReservationDigest string    `json:"reservation_digest"`
	RequestDigest     string    `json:"request_digest"`
	Outcome           string    `json:"outcome"`
	Purpose           uint32    `json:"purpose"`
	Branch            uint32    `json:"branch"`
	StartIndex        uint32    `json:"start_index"`
	EndIndex          uint32    `json:"end_index"`
	SelectedIndex     uint32    `json:"selected_index"`
	InvalidIndices    []uint32  `json:"invalid_indices"`
	Address           string    `json:"address"`
	Script            string    `json:"script"`
	CursorsBefore     [8]uint32 `json:"cursors_before"`
	CursorsAfter      [8]uint32 `json:"cursors_after"`
	ConsumerKind      string    `json:"consumer_kind"`
	ConsumerBindingID string    `json:"consumer_binding_id"`
	ConsumerID        string    `json:"consumer_id"`
	PreparationDigest string    `json:"preparation_digest"`
}
type HostedAllocationState2 struct {
	Guard        HostedAllocationGuard2
	Meta         HostedAllocationMeta2
	Records      []HostedAllocationRecord2
	LogicalBytes uint64
}
type HostedAllocationPlan2 struct {
	manager   *Manager
	guard     HostedAllocationGuard2
	sequence  uint32
	before    [8]uint32
	candidate HostedAllocationRange
}
type RestoredCarrierGuard struct {
	Version                uint32            `json:"version"`
	State                  string            `json:"state"`
	ManagerSchema          uint32            `json:"manager_schema"`
	WalletOwnerID          string            `json:"wallet_owner_id"`
	CarrierJournalID       string            `json:"carrier_journal_id"`
	OwnershipPinID         string            `json:"ownership_pin_id"`
	OriginalManifestSHA256 string            `json:"original_manifest_sha256"`
	OriginalManifest       recovery.Manifest `json:"original_manifest"`
	ActivationTipHash      string            `json:"activation_tip_hash"`
	ActivationTipHeight    int32             `json:"activation_tip_height"`
	ActivationCursors      [8]uint32         `json:"activation_cursors"`
}

func validHostedGuard2(g HostedAllocationGuard2) bool {
	if g.Version != 2 || !hostedHex(g.InventoryID, true) || !hostedHex(g.AuthorityID, true) || !hostedHex(g.AccountID, true) || !hostedHex(g.WalletOwnerID, true) || !hostedHex(g.SourceBindingID, true) || !hostedHex(g.OwnershipPinID, true) || !hostedHex(g.CarrierJournalID, true) || !hostedHex(g.WithdrawalJournalID, true) || !hostedHex(g.InitialManifestSHA256, false) {
		return false
	}
	return g.State == "locked" && g.BindingID == "" || g.State == "bound" && hostedHex(g.BindingID, false)
}
func HostedAllocationGuardDigest2(g HostedAllocationGuard2) (string, error) {
	if !validHostedGuard2(g) {
		return "", ErrHostedAllocationInvalid
	}
	raw, e := json.Marshal(g)
	if e != nil || len(raw) > 2048 {
		return "", ErrHostedAllocationCapacity
	}
	return hostedHash("SLUG hosted allocation wallet guard\x00v2\x00", raw), nil
}

// The common range is a private implementation representation, never a v1
// serialized record or an old allocation authority.
func rangeRecord2(r HostedAllocationRecord2) HostedAllocationRecord {
	return HostedAllocationRecord{Purpose: r.Purpose, Branch: r.Branch, StartIndex: r.StartIndex, EndIndex: r.EndIndex, SelectedIndex: r.SelectedIndex, InvalidIndices: r.InvalidIndices, Address: r.Address, Script: r.Script}
}
func validHostedRecord2(r HostedAllocationRecord2) bool {
	if r.Version != 2 || !hostedHex(r.InventoryID, true) || !hostedHex(r.BindingID, false) || r.Sequence == 0 || r.Sequence > 1024 || !hostedHex(r.AllocationID, true) || !hostedHex(r.ReservationDigest, false) || !hostedHex(r.RequestDigest, false) || r.Outcome != "consumed" && r.Outcome != "burned" || r.Purpose != 84 || r.Branch > 1 || r.EndIndex > 4096 || r.StartIndex >= r.EndIndex || r.EndIndex-r.StartIndex > 128 || r.SelectedIndex != r.EndIndex-1 || r.InvalidIndices == nil || len(r.InvalidIndices) != int(r.SelectedIndex-r.StartIndex) || len(r.Address) == 0 || len(r.Address) > 90 || len(r.Script) != 44 || r.ConsumerID != r.AllocationID {
		return false
	}
	// Reuse the v1 structural range validation through a private synthetic DTO;
	// no bytes, kind, identity, digest or authority is translated or persisted.
	base := rangeRecord2(r)
	base.Version = 1
	base.InventoryID = r.InventoryID
	base.BindingID = r.BindingID
	base.Sequence = r.Sequence
	base.AllocationID = r.AllocationID
	base.ReservationDigest = r.ReservationDigest
	base.RequestDigest = r.RequestDigest
	base.Outcome = r.Outcome
	base.CursorsBefore = r.CursorsBefore
	base.CursorsAfter = r.CursorsAfter
	if r.Branch == 1 {
		base.WithdrawalBindingID = r.ConsumerBindingID
		base.WithdrawalOperationID = r.ConsumerID
		base.DraftDigest = r.PreparationDigest
	}
	if !validHostedRecord(base) {
		return false
	}
	switch r.ConsumerKind {
	case "pool_recipient":
		return r.Sequence == 1 && r.StartIndex == 0 && r.SelectedIndex == 0 && r.Branch == 0 && r.ConsumerBindingID == "" && r.PreparationDigest == ""
	case "receive":
		return r.Sequence > 1 && r.StartIndex >= 1 && r.Branch == 0 && r.ConsumerBindingID == "" && r.PreparationDigest == ""
	case "withdrawal_change", "carrier_return":
		return r.Sequence > 1 && r.Branch == 1 && hostedHex(r.ConsumerBindingID, false) && (r.Outcome == "burned" && r.PreparationDigest == "" || r.Outcome == "consumed" && hostedHex(r.PreparationDigest, false))
	}
	return false
}
func HostedAllocationRecordDigest2(r HostedAllocationRecord2) (string, error) {
	if !validHostedRecord2(r) {
		return "", ErrHostedAllocationInvalid
	}
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > 8192 {
		return "", ErrHostedAllocationCapacity
	}
	return hostedHash("SLUG hosted allocation wallet record\x00v2\x00", raw), nil
}
func MarshalHostedAllocationGuard2(g HostedAllocationGuard2) ([]byte, error) {
	if _, e := HostedAllocationGuardDigest2(g); e != nil {
		return nil, e
	}
	return json.Marshal(g)
}
func ParseHostedAllocationGuard2(raw []byte) (HostedAllocationGuard2, error) {
	var g HostedAllocationGuard2
	if carrierGuardDecode(raw, 2048, &g) != nil || !validHostedGuard2(g) {
		return g, ErrHostedAllocationCorrupt
	}
	return g, nil
}
func MarshalHostedAllocationRecord2(r HostedAllocationRecord2) ([]byte, error) {
	if _, e := HostedAllocationRecordDigest2(r); e != nil {
		return nil, e
	}
	return json.Marshal(r)
}
func ParseHostedAllocationRecord2(raw []byte) (HostedAllocationRecord2, error) {
	var r HostedAllocationRecord2
	if carrierGuardDecode(raw, 8192, &r) != nil || !validHostedRecord2(r) {
		return r, ErrHostedAllocationCorrupt
	}
	return r, nil
}
func RestoredCarrierGuardDigest(g RestoredCarrierGuard) (string, error) {
	if g.Version != 1 || g.State != "ready" || g.ManagerSchema != 15 || !hostedHex(g.WalletOwnerID, true) || !hostedHex(g.CarrierJournalID, true) || !hostedHex(g.OwnershipPinID, true) || !hostedHex(g.OriginalManifestSHA256, false) || !hostedHex(g.ActivationTipHash, true) || g.ActivationTipHeight < 0 {
		return "", ErrHostedAllocationInvalid
	}
	raw, e := recovery.MarshalManifest(g.OriginalManifest)
	if e != nil || hostedHash("", raw) != g.OriginalManifestSHA256 {
		return "", ErrHostedAllocationInvalid
	}
	for i, a := range g.OriginalManifest.Accounts {
		if g.ActivationCursors[2*i] < a.NextExternal || g.ActivationCursors[2*i+1] < a.NextInternal {
			return "", ErrHostedAllocationInvalid
		}
	}
	for _, n := range g.ActivationCursors {
		if n > 4096 {
			return "", ErrHostedAllocationInvalid
		}
	}
	raw, e = json.Marshal(g)
	if e != nil || len(raw) > 8192 {
		return "", ErrHostedAllocationCapacity
	}
	return hostedHash("SLUG restored carrier wallet guard\x00v1\x00", raw), nil
}
