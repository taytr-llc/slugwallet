// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"

	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/recovery"
)

func allocationHash(domain string, v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", ErrAllocationInvalid
	}
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}
func allocationDomain(kind string, v any) (string, error) {
	return allocationHash("SLUG hosted allocation "+kind+"\x00v1\x00", v)
}
func allocationCanonical(raw []byte, v any, limit int) error {
	if len(raw) == 0 || len(raw) > limit || json.Unmarshal(raw, v) != nil {
		return ErrAllocationCorrupt
	}
	encoded, err := json.Marshal(v)
	if err != nil || !bytes.Equal(raw, encoded) {
		return ErrAllocationCorrupt
	}
	return nil
}
func validAllocationBinding(b AllocationBinding) error {
	if b.Version != 1 || b.ManagerSchema != 13 || b.MaxAllocations != HostedAllocationMaxRecords || b.MaxBytes != HostedAllocationMaxBytes || b.MaxPlanAttempts != HostedAllocationMaxAttempts || b.MaxBranchIndex != HostedAllocationMaxIndex {
		return ErrAllocationInvalid
	}
	for _, id := range []string{b.InventoryID, b.AuthorityID, b.AccountID, b.PrincipalID, b.ProvisionID, b.HostedVaultID, b.RetentionID, b.WalletOwnerID, b.SourceBindingID} {
		if !withdrawalHex(id, 32, true) {
			return ErrAllocationInvalid
		}
	}
	m := b.InitialManifest
	if recovery.ValidateManifest(m) != nil || !reflect.DeepEqual(m.Accounts, recovery.DefaultAccounts()) {
		return ErrAllocationProfile
	}
	matched := false
	for _, name := range []string{"zero256", "incrementing256"} {
		id, err := gymaccount.FixtureIdentity(name)
		if err == nil && id.Network == m.Network && id.Genesis == m.Genesis && id.Profile == m.Profile && id.RootPublicKey == m.RootPublicKey && id.GymPublicKey == m.GymPublicKey && id.GymID == m.GymID {
			matched = true
		}
	}
	if !matched {
		return ErrAllocationProfile
	}
	raw, _ := json.Marshal(b)
	if len(raw) > 8192 {
		return ErrAllocationCapacity
	}
	return nil
}

// AllocationBindingID commits only public bytes. It grants no live authority.
func AllocationBindingID(b AllocationBinding) (string, error) {
	if err := validAllocationBinding(b); err != nil {
		return "", err
	}
	return allocationDomain("binding", b)
}
func AllocationRequestDigest(r AllocationRequest, allocationID string) (string, error) {
	if err := validateAllocationRequest(r, allocationID); err != nil {
		return "", err
	}
	return allocationDomain("request", r)
}
func validateAllocationRequest(r AllocationRequest, id string) error {
	if r.Version != 1 || !withdrawalHex(id, 32, true) || !withdrawalHex(r.ConsumerID, 32, true) || r.Purpose != 84 {
		return ErrAllocationInvalid
	}
	switch r.Kind {
	case "pool_recipient", "receive":
		expected := AllocationRequest{Version: 1, Kind: r.Kind, ConsumerID: id, Purpose: 84}
		if r != expected {
			return ErrAllocationInvalid
		}
	case "withdrawal_change":
		if !withdrawalHex(r.WithdrawalBindingID, 32, true) || r.Branch != 1 || r.FeeRateAtomsPerKB != 1000 || r.FeeCeilingAtoms != 100000 || r.MinConfirmations != 1 || r.InputPurpose != 84 || r.ChangePurpose != 84 || r.Account != 0 || r.TxVersion != 1 || r.InputSequence != 4294967295 || r.LockTime != 0 || r.SighashType != 1 {
			return ErrAllocationInvalid
		}
		script, err := validateWithdrawalRequest(CandidateWithdrawalRequest{Version: 1, OperationID: r.ConsumerID, Recipient: r.Recipient, AmountAtoms: r.AmountAtoms})
		if err != nil || hex.EncodeToString(script) != r.RecipientScript {
			return ErrAllocationInvalid
		}
	default:
		return ErrAllocationInvalid
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > 2048 {
		return ErrAllocationCapacity
	}
	return nil
}
func validateAllocationReservation(r allocationReservationValue, bindingID string) error {
	if r.Version != 1 || r.Sequence < 1 || r.Sequence > HostedAllocationMaxRecords || r.BindingID != bindingID || validateAllocationRequest(r.Request, r.AllocationID) != nil || r.Purpose != r.Request.Purpose || r.Branch != r.Request.Branch || r.StartIndex >= r.EndIndex || r.EndIndex > HostedAllocationMaxIndex || r.EndIndex-r.StartIndex > HostedAllocationMaxAttempts || r.SelectedIndex != r.EndIndex-1 || r.InvalidIndices == nil || len(r.InvalidIndices) != int(r.SelectedIndex-r.StartIndex) || r.ReservedAtMS < 1 || r.ReservedAtMS > allocationMaxTime {
		return ErrAllocationCorrupt
	}
	for n, index := range r.InvalidIndices {
		if index != r.StartIndex+uint32(n) {
			return ErrAllocationCorrupt
		}
	}
	script, err := withdrawalRecipient(r.Address)
	if err != nil || len(script) != 22 || script[0] != 0 || script[1] != 20 || r.Script != hex.EncodeToString(script) {
		return ErrAllocationCorrupt
	}
	if r.Request.Kind == "pool_recipient" {
		if r.Sequence != 1 || r.StartIndex != 0 || r.SelectedIndex != 0 {
			return ErrAllocationCorrupt
		}
	} else if r.Sequence == 1 || r.Request.Kind == "receive" && r.StartIndex < 1 {
		return ErrAllocationCorrupt
	}
	return nil
}
func validateAllocationRow(r allocationRow, bindingID string) error {
	if err := validateAllocationReservation(r.Reservation, bindingID); err != nil {
		return err
	}
	digest, err := allocationDomain("reservation", r.Reservation)
	if err != nil || digest != r.ReservationDigest {
		return ErrAllocationCorrupt
	}
	switch r.Phase {
	case "reserved":
		if r.CompletedAtMS != 0 || r.WalletRecordDigest != "" || r.DraftDigest != "" {
			return ErrAllocationCorrupt
		}
	case "consumed", "burned":
		if r.CompletedAtMS < r.Reservation.ReservedAtMS || r.CompletedAtMS > allocationMaxTime || !withdrawalHex(r.WalletRecordDigest, 32, false) {
			return ErrAllocationCorrupt
		}
		if r.Phase == "consumed" && r.Reservation.Request.Kind == "withdrawal_change" {
			if !withdrawalHex(r.DraftDigest, 32, false) {
				return ErrAllocationCorrupt
			}
		} else if r.DraftDigest != "" {
			return ErrAllocationCorrupt
		}
	default:
		return ErrAllocationCorrupt
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > allocationRowMax {
		return ErrAllocationCapacity
	}
	return nil
}

func allocationManifest(b AllocationBinding, cursors [8]uint32) (recovery.Manifest, error) {
	m := cloneAllocationBinding(b).InitialManifest
	for n := range cursors {
		if cursors[n] > HostedAllocationMaxIndex || (n != 4 && n != 5) && cursors[n] != 0 {
			return recovery.Manifest{}, ErrAllocationCorrupt
		}
	}
	for n := range m.Accounts {
		m.Accounts[n].NextExternal = cursors[2*n]
		m.Accounts[n].NextInternal = cursors[2*n+1]
	}
	if err := recovery.ValidateManifest(m); err != nil {
		return recovery.Manifest{}, ErrAllocationCorrupt
	}
	return m, nil
}
