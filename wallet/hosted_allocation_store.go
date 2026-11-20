// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
)

func CreateHostedAllocationInventory(ctx context.Context, path string, accounts *gymaccount.Store, binding AllocationBinding) (*HostedAllocationInventory, error) {
	return openAllocationInventory(ctx, path, accounts, binding, "create")
}

// ResumeHostedAllocationInventory is only for the owner's retained setup intent
// while its wallet is still locked/zero and no READY exists. It accepts only an
// absent or exact empty namespace. Established inventories always use Open.
func ResumeHostedAllocationInventory(ctx context.Context, path string, accounts *gymaccount.Store, binding AllocationBinding) (*HostedAllocationInventory, error) {
	return openAllocationInventory(ctx, path, accounts, binding, "resume")
}
func OpenHostedAllocationInventory(ctx context.Context, path string, accounts *gymaccount.Store, binding AllocationBinding) (*HostedAllocationInventory, error) {
	return openAllocationInventory(ctx, path, accounts, binding, "open")
}

// AllocationCleanupError retains uncertain construction cleanup. Its Close
// never turns an earlier failed close into a later success.
type AllocationCleanupError struct {
	cause error
	owner *HostedAllocationInventory
}

func (e *AllocationCleanupError) Error() string {
	return "hosted allocation construction cleanup failed"
}
func (e *AllocationCleanupError) Unwrap() error { return errors.Join(ErrAllocationCleanup, e.cause) }
func (e *AllocationCleanupError) Close() error {
	if e == nil {
		return nil
	}
	return errors.Join(e.cause, e.owner.Close())
}

func allocationRegular(path string, dir bool) bool {
	st, e := os.Lstat(path)
	return e == nil && st.Mode()&os.ModeSymlink == 0 && (dir && st.IsDir() || !dir && st.Mode().IsRegular())
}
func allocationPath(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 2048 {
		return "", ErrAllocationInvalid
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(path))
	if e != nil {
		return "", ErrAllocationStorage
	}
	path = filepath.Join(parent, filepath.Base(path))
	if st, e := os.Lstat(path); e == nil && (!st.IsDir() || st.Mode()&os.ModeSymlink != 0) {
		return "", ErrAllocationCorrupt
	} else if e != nil && !os.IsNotExist(e) {
		return "", ErrAllocationStorage
	}
	return path, nil
}
func allocationDirectoryEntries(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return ErrAllocationStorage
	}
	entries, re := f.Readdirnames(3)
	ce := f.Close()
	if re != nil && !errors.Is(re, io.EOF) || ce != nil || len(entries) > 2 {
		return ErrAllocationCorrupt
	}
	for _, name := range entries {
		if name != allocationMarkerName && name != "db" {
			return ErrAllocationCorrupt
		}
	}
	return nil
}
func readAllocationMarker(path string) (allocationMarker, error) {
	var marker allocationMarker
	if !allocationRegular(path, false) {
		return marker, ErrAllocationCorrupt
	}
	f, e := os.Open(path)
	if e != nil {
		return marker, ErrAllocationStorage
	}
	raw, re := io.ReadAll(io.LimitReader(f, 8193))
	ce := f.Close()
	if re != nil || ce != nil || len(raw) < 2 || len(raw) > 8192 || raw[len(raw)-1] != '\n' {
		return marker, ErrAllocationCorrupt
	}
	if e = allocationCanonical(raw[:len(raw)-1], &marker, 8191); e != nil {
		return marker, e
	}
	return marker, nil
}
func syncAllocationDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	return errors.Join(f.Sync(), f.Close())
}
func writeAllocationMarker(path string, marker allocationMarker) error {
	raw, e := json.Marshal(marker)
	if e != nil || len(raw)+1 > 8192 {
		return ErrAllocationCapacity
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return ErrAllocationStorage
	}
	raw = append(raw, '\n')
	n, we := f.Write(raw)
	if errors.Join(we, f.Sync(), f.Close()) != nil || n != len(raw) {
		return ErrAllocationOutcomeUnknown
	}
	if errors.Join(syncAllocationDir(filepath.Dir(path)), syncAllocationDir(filepath.Dir(filepath.Dir(path)))) != nil {
		return ErrAllocationOutcomeUnknown
	}
	return nil
}
func openAllocationInventory(ctx context.Context, path string, accounts *gymaccount.Store, binding AllocationBinding, mode string) (*HostedAllocationInventory, error) {
	if wire.TestPoW || ctx == nil || accounts == nil {
		return nil, ErrAllocationProfile
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	id, e := AllocationBindingID(binding)
	if e != nil {
		return nil, e
	}
	info, e := accounts.AuthorityInfo(ctx)
	if e != nil {
		return nil, e
	}
	if info.AuthorityID != binding.AuthorityID || info.Network != binding.InitialManifest.Network || info.Genesis != binding.InitialManifest.Genesis || info.Profile != binding.InitialManifest.Profile {
		return nil, ErrAllocationConflict
	}
	path, e = allocationPath(path)
	if e != nil {
		return nil, e
	}
	_, pe := os.Lstat(path)
	exists := pe == nil
	if pe != nil && !os.IsNotExist(pe) {
		return nil, ErrAllocationStorage
	}
	if mode == "create" && exists {
		return nil, ErrAllocationConflict
	}
	if mode == "open" && !exists {
		return nil, ErrAllocationCorrupt
	}
	if !exists {
		if e = os.Mkdir(path, 0700); e != nil {
			return nil, ErrAllocationStorage
		}
	}
	if e = allocationDirectoryEntries(path); e != nil {
		return nil, e
	}
	marker := allocationMarker{allocationApplication, 1, binding.InventoryID, cloneAllocationBinding(binding)}
	markerPath := filepath.Join(path, allocationMarkerName)
	_, me := os.Lstat(markerPath)
	hasMarker := me == nil
	if me != nil && !os.IsNotExist(me) {
		return nil, ErrAllocationStorage
	}
	if hasMarker {
		got, err := readAllocationMarker(markerPath)
		if err != nil || !reflect.DeepEqual(got, marker) {
			return nil, ErrAllocationCorrupt
		}
	}
	if mode == "open" && !hasMarker {
		return nil, ErrAllocationCorrupt
	}
	dbPath := filepath.Join(path, "db")
	_, de := os.Lstat(dbPath)
	hasDB := de == nil
	if de != nil && !os.IsNotExist(de) {
		return nil, ErrAllocationStorage
	}
	if hasDB && !allocationRegular(dbPath, true) || !hasDB && (mode == "open" || hasMarker) {
		return nil, ErrAllocationCorrupt
	}
	db, e := leveldb.OpenFile(dbPath, &opt.Options{ErrorIfExist: mode == "create", ErrorIfMissing: mode == "open" || hasMarker})
	if e != nil {
		return nil, ErrAllocationStorage
	}
	i := &HostedAllocationInventory{owner: newAllocationLife(), accounts: accounts, binding: cloneAllocationBinding(binding), bindingID: id, path: path, marker: marker, db: db, rows: map[string]allocationRow{}, writeBatch: db.Write, now: time.Now, attachments: map[*HostedAllocator]bool{}, leases: map[*HostedRecoveryHeadLease]bool{}}
	fail := func(cause error) (*HostedAllocationInventory, error) {
		ce := i.Close()
		if errors.Is(ce, ErrAllocationCleanup) {
			return nil, &AllocationCleanupError{errors.Join(cause, ce), i}
		}
		return nil, errors.Join(cause, ce)
	}
	markerHash, _ := allocationHash("", marker)
	if hasMarker || mode == "open" {
		if e = i.audit(); e != nil {
			return fail(e)
		}
	} else {
		it := db.NewIterator(nil, nil)
		nonempty := it.First()
		iterErr := it.Error()
		it.Release()
		if iterErr != nil {
			return fail(ErrAllocationCorrupt)
		}
		if nonempty {
			if e = i.audit(); e != nil {
				return fail(e)
			}
			if i.meta.Allocations != 0 {
				return fail(ErrAllocationCorrupt)
			}
		} else {
			i.meta = allocationMetadata{Version: 1, MarkerSHA256: markerHash}
			raw, _ := json.Marshal(i.meta)
			batch := new(leveldb.Batch)
			batch.Put([]byte("meta"), raw)
			if e = i.writeBatch(batch, &opt.WriteOptions{Sync: true}); e != nil {
				i.poisoned.Store(true)
				return fail(ErrAllocationOutcomeUnknown)
			}
			i.bytes = 4 + len(raw)
		}
		if e = writeAllocationMarker(markerPath, marker); e != nil {
			i.poisoned.Store(true)
			return fail(e)
		}
	}
	if mode == "resume" && i.meta.Allocations != 0 {
		return fail(ErrAllocationConflict)
	}
	if e = ctx.Err(); e != nil {
		return fail(e)
	}
	i.revision.Store(i.meta.Revision)
	return i, nil
}

func (i *HostedAllocationInventory) acquire(ctx context.Context) (context.Context, func(), error) {
	if i == nil {
		return nil, nil, ErrAllocationClosed
	}
	ctx, done, e := i.owner.acquire(ctx)
	if e != nil {
		return nil, nil, e
	}
	if i.poisoned.Load() {
		done()
		return nil, nil, ErrAllocationPoisoned
	}
	return ctx, done, nil
}
func (i *HostedAllocationInventory) Binding() AllocationBinding {
	if i == nil {
		return AllocationBinding{}
	}
	return cloneAllocationBinding(i.binding)
}
func (i *HostedAllocationInventory) Close() error {
	if i == nil {
		return nil
	}
	first, e := i.owner.startClose()
	if !first {
		return e
	}
	i.attachmentsMu.Lock()
	all := make([]*HostedAllocator, 0, len(i.attachments))
	for a := range i.attachments {
		all = append(all, a)
	}
	i.attachmentsMu.Unlock()
	for _, a := range all {
		e = errors.Join(e, a.Close())
	}
	i.leasesMu.Lock()
	leases := make([]*HostedRecoveryHeadLease, 0, len(i.leases))
	for lease := range i.leases {
		leases = append(leases, lease)
	}
	i.leasesMu.Unlock()
	for _, lease := range leases {
		e = errors.Join(e, lease.Close())
	}
	i.owner.active.Wait()
	if i.db != nil {
		if ce := i.db.Close(); ce != nil {
			e = errors.Join(e, ErrAllocationCleanup, ce)
		}
	}
	if i.poisoned.Load() {
		e = errors.Join(e, ErrAllocationPoisoned)
	}
	return i.owner.finishClose(e)
}

func (i *HostedAllocationInventory) audit() error {
	metaRaw, e := i.db.Get([]byte("meta"), nil)
	if e != nil {
		return ErrAllocationCorrupt
	}
	var got allocationMetadata
	if allocationCanonical(metaRaw, &got, 4096) != nil {
		return ErrAllocationCorrupt
	}
	markerHash, _ := allocationHash("", i.marker)
	rows := map[string]allocationRow{}
	count := 0
	size := 0
	metaSeen := false
	it := i.db.NewIterator(nil, nil)
	defer it.Release()
	for it.Next() {
		key, value := it.Key(), it.Value()
		count++
		if count > HostedAllocationMaxRecords+1 || len(key)+len(value) > HostedAllocationMaxBytes-size {
			return ErrAllocationCapacity
		}
		size += len(key) + len(value)
		if string(key) == "meta" {
			if metaSeen {
				return ErrAllocationCorrupt
			}
			metaSeen = true
			continue
		}
		if len(key) != 75 || !bytesAllocationPrefix(key) {
			return ErrAllocationCorrupt
		}
		id := string(key[11:])
		if !withdrawalHex(id, 32, true) {
			return ErrAllocationCorrupt
		}
		var row allocationRow
		if allocationCanonical(value, &row, allocationRowMax) != nil || validateAllocationRow(row, i.bindingID) != nil || row.Reservation.AllocationID != id {
			return ErrAllocationCorrupt
		}
		rows[id] = row
	}
	if it.Error() != nil || !metaSeen {
		return ErrAllocationCorrupt
	}
	order := make([]string, 0, len(rows))
	for id := range rows {
		order = append(order, id)
	}
	sort.Slice(order, func(a, b int) bool { return rows[order[a]].Reservation.Sequence < rows[order[b]].Reservation.Sequence })
	want := allocationMetadata{Version: 1, MarkerSHA256: markerHash}
	consumers := map[string]bool{}
	for n, id := range order {
		row := rows[id]
		r := row.Reservation
		slot := 4 + r.Branch
		consumer := r.Request.Kind + ":" + r.Request.ConsumerID
		if r.Sequence != uint32(n+1) || consumers[consumer] || r.StartIndex != want.Cursors[slot] || r.ReservedAtMS < want.ClockHighWaterMS || want.ActiveAllocationID != "" {
			return ErrAllocationCorrupt
		}
		consumers[consumer] = true
		want.Allocations++
		want.Revision++
		want.Cursors[slot] = r.EndIndex
		want.ClockHighWaterMS = r.ReservedAtMS
		if row.Phase == "reserved" {
			want.ActiveAllocationID = id
		} else {
			want.Revision++
			want.ClockHighWaterMS = row.CompletedAtMS
		}
	}
	if got != want {
		return ErrAllocationCorrupt
	}
	if _, e = allocationManifest(i.binding, want.Cursors); e != nil {
		return e
	}
	i.meta = got
	i.rows = rows
	i.order = order
	i.bytes = size
	return nil
}
func bytesAllocationPrefix(key []byte) bool { return string(key[:11]) == "allocation/" }

// commitRow requires the inventory gate. All encoding, hashing, validation and
// capacity accounting precedes the original account/epoch lease.
func (i *HostedAllocationInventory) commitRow(ctx context.Context, token string, epoch HostedAllocationEpochFence, expected *gymaccount.Account, row allocationRow, next allocationMetadata, newRow bool, cap gymaccount.Capability) (allocationRow, error) {
	if validateAllocationRow(row, i.bindingID) != nil {
		return allocationRow{}, ErrAllocationCorrupt
	}
	raw, e := json.Marshal(row)
	if e != nil {
		return allocationRow{}, ErrAllocationCorrupt
	}
	mr, e := json.Marshal(next)
	if e != nil {
		return allocationRow{}, ErrAllocationCorrupt
	}
	key := []byte("allocation/" + row.Reservation.AllocationID)
	oldMeta, _ := json.Marshal(i.meta)
	size := i.bytes - len(oldMeta) + len(mr)
	if newRow {
		size += len(key) + len(raw)
	} else {
		old, ok := i.rows[row.Reservation.AllocationID]
		if !ok {
			return allocationRow{}, ErrAllocationCorrupt
		}
		oldRaw, _ := json.Marshal(old)
		size += len(raw) - len(oldRaw)
	}
	if len(raw) > allocationRowMax || len(mr) > 4096 || len(key)+len(raw)+4+len(mr) > allocationBatchMax || size > HostedAllocationMaxBytes {
		return allocationRow{}, ErrAllocationCapacity
	}
	batch := new(leveldb.Batch)
	batch.Put(key, raw)
	batch.Put([]byte("meta"), mr)
	if cap != gymaccount.View && cap != gymaccount.Withdrawal {
		return allocationRow{}, ErrAllocationInvalid
	}
	attempted := false
	e = i.authorize(ctx, token, epoch, cap, expected, func(_ gymaccount.Account, check func() error) error {
		if e := check(); e != nil {
			return e
		}
		attempted = true
		if i.writeBatch(batch, &opt.WriteOptions{Sync: true}) != nil {
			return ErrAllocationPoisoned
		}
		i.rows[row.Reservation.AllocationID] = row
		i.meta = next
		i.bytes = size
		if newRow {
			i.order = append(i.order, row.Reservation.AllocationID)
		}
		i.revision.Store(next.Revision)
		return check()
	})
	if e != nil {
		if attempted {
			i.poisoned.Store(true)
			return allocationRow{}, errors.Join(ErrAllocationOutcomeUnknown, e)
		}
		return allocationRow{}, e
	}
	return cloneAllocationRow(row), nil
}

func (i *HostedAllocationInventory) commitReservation(ctx context.Context, token string, epoch HostedAllocationEpochFence, expected *gymaccount.Account, value *allocationReservationValue) (allocationRow, error) {
	if value == nil {
		return allocationRow{}, ErrAllocationInvalid
	}
	r := *value
	r.InvalidIndices = append([]uint32{}, value.InvalidIndices...)
	if old, ok := i.rows[r.AllocationID]; ok {
		if old.Reservation.Request != r.Request {
			return allocationRow{}, ErrAllocationConflict
		}
		cap := gymaccount.View
		if r.Request.Kind == "withdrawal_change" {
			cap = gymaccount.Withdrawal
		}
		if e := i.authorize(ctx, token, epoch, cap, expected, func(_ gymaccount.Account, check func() error) error { return check() }); e != nil {
			return allocationRow{}, e
		}
		return cloneAllocationRow(old), nil
	}
	for _, id := range i.order {
		q := i.rows[id].Reservation.Request
		if q.Kind == r.Request.Kind && q.ConsumerID == r.Request.ConsumerID {
			return allocationRow{}, ErrAllocationConflict
		}
	}
	if i.meta.ActiveAllocationID != "" {
		return allocationRow{}, ErrAllocationBusy
	}
	if i.meta.Allocations >= HostedAllocationMaxRecords {
		return allocationRow{}, ErrAllocationCapacity
	}
	if r.Branch > 1 || r.StartIndex != i.meta.Cursors[4+r.Branch] || r.Sequence != i.meta.Allocations+1 || r.BindingID != i.bindingID {
		return allocationRow{}, ErrAllocationConflict
	}
	now := i.now().UnixMilli()
	if now < 1 || now > allocationMaxTime || now < i.meta.ClockHighWaterMS {
		return allocationRow{}, ErrAllocationUnavailable
	}
	r.ReservedAtMS = now
	if e := validateAllocationReservation(r, i.bindingID); e != nil {
		return allocationRow{}, e
	}
	digest, _ := allocationDomain("reservation", r)
	row := allocationRow{Reservation: r, ReservationDigest: digest, Phase: "reserved"}
	next := i.meta
	next.Allocations++
	next.Revision++
	next.ClockHighWaterMS = now
	next.ActiveAllocationID = r.AllocationID
	next.Cursors[4+r.Branch] = r.EndIndex
	// Charge the largest legal terminal row/metadata before accepting the range.
	terminal := row
	terminal.Phase = "consumed"
	terminal.CompletedAtMS = allocationMaxTime
	terminal.WalletRecordDigest = strings.Repeat("f", 64)
	if r.Request.Kind == "withdrawal_change" {
		terminal.DraftDigest = strings.Repeat("f", 64)
	}
	tr, _ := json.Marshal(terminal)
	worstMeta := next
	worstMeta.Revision++
	worstMeta.ClockHighWaterMS = allocationMaxTime
	worstMeta.ActiveAllocationID = ""
	tm, _ := json.Marshal(worstMeta)
	nm, _ := json.Marshal(next)
	om, _ := json.Marshal(i.meta)
	metaLength := len(tm)
	if len(nm) > metaLength {
		metaLength = len(nm)
	}
	if len(tr) > allocationRowMax || i.bytes-len(om)+metaLength+75+len(tr) > HostedAllocationMaxBytes {
		return allocationRow{}, ErrAllocationCapacity
	}
	cap := gymaccount.View
	if r.Request.Kind == "withdrawal_change" {
		cap = gymaccount.Withdrawal
	}
	return i.commitRow(ctx, token, epoch, expected, row, next, true, cap)
}

func (i *HostedAllocationInventory) commitCompletion(ctx context.Context, token string, epoch HostedAllocationEpochFence, expected *gymaccount.Account, id string, link waddrmgr.HostedAllocationRecord, cap gymaccount.Capability) (allocationRow, error) {
	if cap != gymaccount.View && cap != gymaccount.Withdrawal {
		return allocationRow{}, ErrAllocationInvalid
	}
	row, ok := i.rows[id]
	if !ok {
		return allocationRow{}, ErrAllocationNotFound
	}
	// This private method is reached only through a concrete wallet-minted receipt.
	// Independently bind all public link fields before staging its completion.
	r := row.Reservation
	requestDigest, _ := allocationDomain("request", r.Request)
	if link.InventoryID != i.binding.InventoryID || link.BindingID != i.bindingID || link.Sequence != r.Sequence || link.AllocationID != id || link.ReservationDigest != row.ReservationDigest || link.RequestDigest != requestDigest || link.Purpose != r.Purpose || link.Branch != r.Branch || link.StartIndex != r.StartIndex || link.EndIndex != r.EndIndex || link.SelectedIndex != r.SelectedIndex || !reflect.DeepEqual(link.InvalidIndices, r.InvalidIndices) || link.Address != r.Address || link.Script != r.Script {
		return allocationRow{}, ErrAllocationConflict
	}
	digest, e := waddrmgr.HostedAllocationRecordDigest(link)
	if e != nil {
		return allocationRow{}, e
	}
	var before [8]uint32
	for _, priorID := range i.order {
		prior := i.rows[priorID].Reservation
		if prior.Sequence >= r.Sequence {
			break
		}
		before[4+prior.Branch] = prior.EndIndex
	}
	after := before
	after[4+r.Branch] = r.EndIndex
	if link.CursorsBefore != before || link.CursorsAfter != after {
		return allocationRow{}, ErrAllocationConflict
	}
	if r.Request.Kind == "withdrawal_change" && (link.WithdrawalBindingID != r.Request.WithdrawalBindingID || link.WithdrawalOperationID != r.Request.ConsumerID) {
		return allocationRow{}, ErrAllocationConflict
	}
	if row.Phase != "reserved" {
		if row.Phase != link.Outcome || row.WalletRecordDigest != digest || row.DraftDigest != link.DraftDigest {
			return allocationRow{}, ErrAllocationConflict
		}
		if e = i.authorize(ctx, token, epoch, cap, expected, func(_ gymaccount.Account, check func() error) error { return check() }); e != nil {
			return allocationRow{}, e
		}
		return cloneAllocationRow(row), nil
	}
	if i.meta.ActiveAllocationID != id || r.Sequence != i.meta.Allocations {
		return allocationRow{}, ErrAllocationCorrupt
	}
	now := i.now().UnixMilli()
	if now < i.meta.ClockHighWaterMS || now > allocationMaxTime {
		return allocationRow{}, ErrAllocationUnavailable
	}
	row.Phase = link.Outcome
	row.CompletedAtMS = now
	row.WalletRecordDigest = digest
	row.DraftDigest = link.DraftDigest
	next := i.meta
	next.Revision++
	next.ClockHighWaterMS = now
	next.ActiveAllocationID = ""
	return i.commitRow(ctx, token, epoch, expected, row, next, false, cap)
}
