// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"

	"github.com/taytr-llc/slug/btcec/v2"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/recovery"
)

func allocationDomain2(kind string, v any) (string, error) {
	return allocationHash("SLUG hosted allocation "+kind+"\x00v2\x00", v)
}
func allocationMarkerHash2(m allocationMarker2) (string, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return "", ErrAllocationInvalid
	}
	h := sha256.Sum256(append(raw, '\n'))
	return hex.EncodeToString(h[:]), nil
}
func validAllocationBinding2(b AllocationBinding2) error {
	if b.Version != 2 || b.ManagerSchema != 14 || b.MaxAllocations != HostedAllocationMaxRecords || b.MaxBytes != HostedAllocationMaxBytes || b.MaxPlanAttempts != HostedAllocationMaxAttempts || b.MaxBranchIndex != HostedAllocationMaxIndex {
		return ErrAllocationInvalid
	}
	for _, id := range []string{b.InventoryID, b.AuthorityID, b.AccountID, b.PrincipalID, b.ProvisionID, b.HostedVaultID, b.RetentionID, b.WalletOwnerID, b.SourceBindingID, b.OwnershipPinID, b.CarrierJournalID, b.WithdrawalJournalID} {
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

// AllocationBindingID2 commits only public bytes. It grants no live authority.
func AllocationBindingID2(b AllocationBinding2) (string, error) {
	if err := validAllocationBinding2(b); err != nil {
		return "", err
	}
	return allocationDomain2("binding", b)
}
func AllocationRequestDigest2(r AllocationRequest2, allocationID string) (string, error) {
	if err := validateAllocationRequest2(r, allocationID); err != nil {
		return "", err
	}
	return allocationDomain2("request", r)
}
func validateAllocationRequest2(r AllocationRequest2, id string) error {
	if r.Version != 2 || !withdrawalHex(id, 32, true) || !withdrawalHex(r.ConsumerID, 32, true) || r.Purpose != 84 {
		return ErrAllocationInvalid
	}
	switch r.Kind {
	case "pool_recipient", "receive":
		expected := AllocationRequest2{Version: 2, Kind: r.Kind, ConsumerID: id, Purpose: 84}
		if r != expected {
			return ErrAllocationInvalid
		}
	case "withdrawal_change":
		if r.ConsumerID != id || r.CarrierBindingID != "" || r.OwnershipPinID != "" || r.PriorStateID != "" || r.RecipientGym != "" || r.FundingDigest != "" || r.EscrowAtoms != 0 || r.CommitFeeAtoms != 0 || r.SpendFeeAtoms != 0 || r.MinChangeAtoms != 0 {
			return ErrAllocationInvalid
		}
		if !withdrawalHex(r.WithdrawalBindingID, 32, true) || r.Branch != 1 || r.FeeRateAtomsPerKB != 1000 || r.FeeCeilingAtoms != 100000 || r.MinConfirmations != 1 || r.InputPurpose != 84 || r.ChangePurpose != 84 || r.Account != 0 || r.TxVersion != 1 || r.InputSequence != 4294967295 || r.LockTime != 0 || r.SighashType != 1 {
			return ErrAllocationInvalid
		}
		script, err := validateWithdrawalRequest(CandidateWithdrawalRequest{Version: 1, OperationID: r.ConsumerID, Recipient: r.Recipient, AmountAtoms: r.AmountAtoms})
		if err != nil || hex.EncodeToString(script) != r.RecipientScript {
			return ErrAllocationInvalid
		}
	case "carrier_return":
		if r.ConsumerID != id || r.WithdrawalBindingID != "" || r.Recipient != "" || r.RecipientScript != "" || r.AmountAtoms != 0 || r.FeeRateAtomsPerKB != 0 || r.FeeCeilingAtoms != 0 || r.Branch != 1 || r.MinConfirmations != 1 || r.InputPurpose != 84 || r.ChangePurpose != 84 || r.Account != 0 || r.TxVersion != 1 || r.InputSequence != 4294967295 || r.LockTime != 0 || r.SighashType != 1 || r.EscrowAtoms != 500000 || r.CommitFeeAtoms != 10000 || r.SpendFeeAtoms != 10000 || r.MinChangeAtoms != 1000 {
			return ErrAllocationInvalid
		}
		for _, value := range []string{r.CarrierBindingID, r.OwnershipPinID, r.PriorStateID, r.FundingDigest} {
			if !withdrawalHex(value, 32, true) {
				return ErrAllocationInvalid
			}
		}
		if !withdrawalHex(r.RecipientGym, 33, true) {
			return ErrAllocationInvalid
		}
		key, _ := hex.DecodeString(r.RecipientGym)
		pub, err := btcec.ParsePubKey(key)
		if err != nil || !bytes.Equal(pub.SerializeCompressed(), key) {
			return ErrAllocationInvalid
		}
	default:
		return ErrAllocationInvalid
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > 4096 {
		return ErrAllocationCapacity
	}
	return nil
}
func validateAllocationReservation2(r allocationReservationValue2, bindingID string) error {
	if r.Version != 2 || r.Sequence < 1 || r.Sequence > HostedAllocationMaxRecords || r.BindingID != bindingID || validateAllocationRequest2(r.Request, r.AllocationID) != nil || r.Purpose != r.Request.Purpose || r.Branch != r.Request.Branch || r.StartIndex >= r.EndIndex || r.EndIndex > HostedAllocationMaxIndex || r.EndIndex-r.StartIndex > HostedAllocationMaxAttempts || r.SelectedIndex != r.EndIndex-1 || r.InvalidIndices == nil || len(r.InvalidIndices) != int(r.SelectedIndex-r.StartIndex) || r.ReservedAtMS < 1 || r.ReservedAtMS > allocationMaxTime {
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
func validateAllocationRow2(r allocationRow2, bindingID string) error {
	if err := validateAllocationReservation2(r.Reservation, bindingID); err != nil {
		return err
	}
	digest, err := allocationDomain2("reservation", r.Reservation)
	if err != nil || digest != r.ReservationDigest {
		return ErrAllocationCorrupt
	}
	switch r.Phase {
	case "reserved":
		if r.CompletedAtMS != 0 || r.WalletRecordDigest != "" || r.PreparationDigest != "" {
			return ErrAllocationCorrupt
		}
	case "consumed", "burned":
		if r.CompletedAtMS < r.Reservation.ReservedAtMS || r.CompletedAtMS > allocationMaxTime || !withdrawalHex(r.WalletRecordDigest, 32, false) {
			return ErrAllocationCorrupt
		}
		if r.Phase == "consumed" && (r.Reservation.Request.Kind == "withdrawal_change" || r.Reservation.Request.Kind == "carrier_return") {
			if !withdrawalHex(r.PreparationDigest, 32, false) {
				return ErrAllocationCorrupt
			}
		} else if r.PreparationDigest != "" {
			return ErrAllocationCorrupt
		}
	default:
		return ErrAllocationCorrupt
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > allocationRowMax2 {
		return ErrAllocationCapacity
	}
	return nil
}

// Bound hostile structure before decoding a typed allocation DTO. Every row is
// at most 8192 bytes; token/string/array/depth limits are independent of that cap.
func allocationCanonical2(raw []byte, out any, limit int) error {
	if len(raw) == 0 || len(raw) > limit {
		return ErrAllocationCorrupt
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	tokens := 0
	walk = func(depth int) error {
		if depth > 16 || tokens >= 4096 {
			return ErrAllocationCorrupt
		}
		tokens++
		tok, err := d.Token()
		if err != nil {
			return ErrAllocationCorrupt
		}
		switch v := tok.(type) {
		case string:
			if len(v) > 2048 {
				return ErrAllocationCorrupt
			}
		case json.Number:
			if len(v) > 20 {
				return ErrAllocationCorrupt
			}
			for n, c := range v {
				if (c < '0' || c > '9') && (n != 0 || c != '-') {
					return ErrAllocationCorrupt
				}
			}
		case nil:
			return ErrAllocationCorrupt
		case json.Delim:
			if v != '{' && v != '[' {
				return ErrAllocationCorrupt
			}
			count := 0
			seen := map[string]bool{}
			for d.More() {
				count++
				if count > 128 {
					return ErrAllocationCorrupt
				}
				if v == '{' {
					key, e := d.Token()
					if e != nil {
						return ErrAllocationCorrupt
					}
					k, ok := key.(string)
					if !ok || len(k) > 64 || seen[k] {
						return ErrAllocationCorrupt
					}
					seen[k] = true
				}
				if e := walk(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || v == '{' && end != json.Delim('}') || v == '[' && end != json.Delim(']') {
				return ErrAllocationCorrupt
			}
		}
		return nil
	}
	if walk(0) != nil {
		return ErrAllocationCorrupt
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrAllocationCorrupt
	}
	return allocationCanonical(raw, out, limit)
}

func allocationManifest2(b AllocationBinding2, cursors [8]uint32) (recovery.Manifest, error) {
	m := cloneAllocationBinding2(b).InitialManifest
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
