// Copyright (c) 2026 The SLUG developers
// Use of this source code is governed by an ISC license.

package recoveryvault

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
)

const MaxRecordSize = 256 * 1024
const vaultMarker = "SLUG-RECOVERY-VAULT.json"
const vaultApplication = "slug-public-fixture-recovery-vault"

var (
	ErrClosed   = errors.New("recovery vault closed")
	ErrCorrupt  = errors.New("recovery vault corrupt or incompatible")
	ErrConflict = errors.New("recovery vault binding or revision conflict")
	ErrCapacity = errors.New("recovery vault capacity reached")
	ErrPoisoned = errors.New("recovery vault write outcome uncertain; reopen required")
	ErrNotFound = errors.New("recovery vault reservation unavailable")
	ErrExport   = errors.New("recovery export destination unavailable; partial output may remain")
)

type Receipt struct {
	Version      uint32            `json:"version"`
	Binding      Binding           `json:"binding"`
	Manifest     recovery.Manifest `json:"manifest"`
	ManifestHash string            `json:"manifest_hash"`
	RetentionID  string            `json:"retention_id"`
}
type Status struct {
	Version              uint32   `json:"version"`
	Binding              Binding  `json:"binding"`
	State                string   `json:"state"`
	Revision             uint64   `json:"revision"`
	RecoveryKeyRef       string   `json:"recovery_key_ref"`
	GymKeyRef            string   `json:"gym_key_ref"`
	RecoveryWrapRevision uint64   `json:"recovery_wrap_revision"`
	GymWrapRevision      uint64   `json:"gym_wrap_revision"`
	Receipt              *Receipt `json:"receipt,omitempty"`
}
type vaultHeader struct {
	Application string                   `json:"application"`
	Version     uint32                   `json:"version"`
	Authority   gymaccount.AuthorityInfo `json:"authority"`
	Config      Config                   `json:"config"`
}
type reservationIndex struct {
	AccountID   string `json:"account_id"`
	PrincipalID string `json:"principal_id"`
	ProvisionID string `json:"provision_id"`
}
type vaultMetadata struct {
	Header     vaultHeader        `json:"header"`
	Operations uint32             `json:"operations"`
	Reserved   uint32             `json:"reserved"`
	Accounts   []reservationIndex `json:"accounts"`
}
type vaultRecord struct {
	Binding      Binding           `json:"binding"`
	Manifest     recovery.Manifest `json:"manifest"`
	ManifestHash string            `json:"manifest_hash"`
	State        string            `json:"state"`
	Revision     uint64            `json:"revision"`
	Recovery     *Envelope         `json:"recovery,omitempty"`
	Gym          *Envelope         `json:"gym,omitempty"`
	Receipt      *Receipt          `json:"receipt,omitempty"`
}

// Vault owns one exclusively opened local fixture database. Provider work runs
// outside account/vault gates; Close cancels and joins actual admitted work.
type Vault struct {
	accounts         *gymaccount.Store
	wrapper          KeyWrapper
	config           Config
	authority        gymaccount.AuthorityInfo
	path             string
	db               *leveldb.DB
	meta             vaultMetadata
	gate             chan struct{}
	poisoned, closed bool
	random           io.Reader
	writeBatch       func(*leveldb.Batch, *opt.WriteOptions) error
	lifetime         context.Context
	cancel           context.CancelFunc
	lifeMu           sync.Mutex
	closing          bool
	active           sync.WaitGroup
	closeDone        chan struct{}
	closeErr         error
}

func vaultSetup(ctx context.Context, c Config, accounts *gymaccount.Store, wrapper KeyWrapper) (Config, gymaccount.AuthorityInfo, error) {
	if wire.TestPoW || ctx == nil || accounts == nil || wrapper == nil {
		return Config{}, gymaccount.AuthorityInfo{}, ErrConfig
	}
	c, err := normalizedConfig(c)
	if err != nil || wrapper.ID() != c.WrapperID {
		return Config{}, gymaccount.AuthorityInfo{}, ErrConfig
	}
	a, err := accounts.AuthorityInfo(ctx)
	if err != nil {
		return Config{}, gymaccount.AuthorityInfo{}, err
	}
	if a.Version != gymaccount.IdentityVersion || a.Network != gymaccount.FixtureNetwork || a.Genesis != gymaccount.FixtureGenesis || a.Profile != gymaccount.FixtureProfile {
		return Config{}, gymaccount.AuthorityInfo{}, ErrConfig
	}
	return c, a, nil
}
func newVault(path string, c Config, a gymaccount.AuthorityInfo, accounts *gymaccount.Store, w KeyWrapper, db *leveldb.DB) *Vault {
	lifetime, cancel := context.WithCancel(context.Background())
	return &Vault{accounts: accounts, wrapper: w, config: c, authority: a, path: path, db: db, gate: make(chan struct{}, 1), random: rand.Reader, writeBatch: db.Write, lifetime: lifetime, cancel: cancel, closeDone: make(chan struct{})}
}
func Create(ctx context.Context, path string, c Config, accounts *gymaccount.Store, wrapper KeyWrapper) (*Vault, error) {
	c, a, err := vaultSetup(ctx, c, accounts, wrapper)
	if err != nil {
		return nil, err
	}
	header := vaultHeader{Application: vaultApplication, Version: Version1, Authority: a, Config: c}
	raw, err := json.Marshal(header)
	if err != nil || len(raw) > MaxRecordSize {
		return nil, ErrConfig
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if os.Mkdir(path, 0700) != nil {
		return nil, ErrCorrupt
	}
	file, err := os.OpenFile(filepath.Join(path, vaultMarker), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, ErrCorrupt
	}
	_, we := file.Write(raw)
	if errors.Join(we, file.Sync(), file.Close()) != nil {
		return nil, ErrCorrupt
	}
	db, err := leveldb.OpenFile(filepath.Join(path, "db"), &opt.Options{ErrorIfExist: true})
	if err != nil {
		return nil, ErrCorrupt
	}
	canonicalPath, canonicalErr := filepath.EvalSymlinks(path)
	if canonicalErr == nil {
		canonicalPath, canonicalErr = filepath.Abs(canonicalPath)
	}
	if canonicalErr != nil {
		db.Close()
		return nil, ErrCorrupt
	}
	v := newVault(canonicalPath, c, a, accounts, wrapper, db)
	v.meta = vaultMetadata{Header: header, Accounts: []reservationIndex{}}
	batch := new(leveldb.Batch)
	err = putVault(batch, "meta", v.meta)
	if err == nil {
		err = db.Write(batch, &opt.WriteOptions{Sync: true})
	}
	if err == nil {
		err = syncVaultDir(path)
	}
	if err == nil {
		err = syncVaultDir(filepath.Dir(path))
	}
	if err != nil {
		db.Close()
		v.cancel()
		return nil, ErrPoisoned
	}
	return v, nil
}
func Open(ctx context.Context, path string, c Config, accounts *gymaccount.Store, wrapper KeyWrapper) (*Vault, error) {
	c, a, err := vaultSetup(ctx, c, accounts, wrapper)
	if err != nil {
		return nil, err
	}
	if !vaultRegular(path, true) || !vaultRegular(filepath.Join(path, "db"), true) || !vaultRegular(filepath.Join(path, vaultMarker), false) {
		return nil, ErrCorrupt
	}
	f, err := os.Open(filepath.Join(path, vaultMarker))
	if err != nil {
		return nil, ErrCorrupt
	}
	raw, re := io.ReadAll(io.LimitReader(f, MaxRecordSize+1))
	ce := f.Close()
	var h vaultHeader
	if re != nil || ce != nil || strictVault(raw, &h) != nil || h.Application != vaultApplication || h.Version != Version1 || h.Authority != a || !reflect.DeepEqual(h.Config, c) {
		return nil, ErrCorrupt
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	db, err := leveldb.OpenFile(filepath.Join(path, "db"), &opt.Options{ErrorIfMissing: true})
	if err != nil {
		return nil, ErrCorrupt
	}
	canonicalPath, canonicalErr := filepath.EvalSymlinks(path)
	if canonicalErr == nil {
		canonicalPath, canonicalErr = filepath.Abs(canonicalPath)
	}
	if canonicalErr != nil {
		db.Close()
		return nil, ErrCorrupt
	}
	v := newVault(canonicalPath, c, a, accounts, wrapper, db)
	if v.load("meta", &v.meta) != nil || !reflect.DeepEqual(v.meta.Header, h) || v.audit() != nil {
		db.Close()
		v.cancel()
		return nil, ErrCorrupt
	}
	return v, nil
}
func vaultRegular(path string, dir bool) bool {
	st, err := os.Lstat(path)
	return err == nil && st.Mode()&os.ModeSymlink == 0 && ((dir && st.IsDir()) || (!dir && st.Mode().IsRegular()))
}
func syncVaultDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
func strictVault(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > MaxRecordSize || json.Unmarshal(raw, out) != nil {
		return ErrCorrupt
	}
	encoded, err := json.Marshal(out)
	if err != nil || !bytes.Equal(raw, encoded) {
		return ErrCorrupt
	}
	return nil
}
func putVault(batch *leveldb.Batch, key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > MaxRecordSize {
		return ErrCorrupt
	}
	batch.Put([]byte(key), raw)
	return nil
}
func (v *Vault) load(key string, out any) error {
	raw, err := v.db.Get([]byte(key), nil)
	if errors.Is(err, leveldb.ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return ErrCorrupt
	}
	return strictVault(raw, out)
}
func (v *Vault) begin(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, ErrConfig
	}
	v.lifeMu.Lock()
	if v.closing {
		v.lifeMu.Unlock()
		return nil, nil, ErrClosed
	}
	v.active.Add(1)
	v.lifeMu.Unlock()
	op, cancel := context.WithTimeout(ctx, 30*time.Second)
	stop := context.AfterFunc(v.lifetime, cancel)
	return op, func() { stop(); cancel(); v.active.Done() }, nil
}
func (v *Vault) lock(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case v.gate <- struct{}{}:
	}
	if err := ctx.Err(); err != nil {
		<-v.gate
		return err
	}
	if v.closed || v.poisoned {
		<-v.gate
		if v.poisoned {
			return ErrPoisoned
		}
		return ErrClosed
	}
	return nil
}
func (v *Vault) unlock() { <-v.gate }
func (v *Vault) Close() error {
	v.lifeMu.Lock()
	if v.closing {
		done := v.closeDone
		v.lifeMu.Unlock()
		<-done
		return v.closeErr
	}
	v.closing = true
	v.cancel()
	v.lifeMu.Unlock()
	v.active.Wait()
	v.gate <- struct{}{}
	v.closed = true
	err := v.db.Close()
	if err != nil {
		err = ErrCorrupt
	}
	if v.poisoned {
		err = errors.Join(ErrPoisoned, err)
	}
	v.unlock()
	v.lifeMu.Lock()
	v.closeErr = err
	close(v.closeDone)
	v.lifeMu.Unlock()
	return err
}
func cloneManifest(m recovery.Manifest) recovery.Manifest {
	m.Accounts = append([]recovery.Account(nil), m.Accounts...)
	return m
}
func cloneReceipt(r Receipt) Receipt { r.Manifest = cloneManifest(r.Manifest); return r }
func cloneRecord(r vaultRecord) vaultRecord {
	r.Manifest = cloneManifest(r.Manifest)
	if r.Recovery != nil {
		e := *r.Recovery
		r.Recovery = &e
	}
	if r.Gym != nil {
		e := *r.Gym
		r.Gym = &e
	}
	if r.Receipt != nil {
		x := cloneReceipt(*r.Receipt)
		r.Receipt = &x
	}
	return r
}
func manifestDigest(m recovery.Manifest) (string, error) {
	raw, err := recovery.MarshalManifest(m)
	if err != nil {
		return "", ErrCorrupt
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func retentionReceipt(r vaultRecord) Receipt {
	digest := sha256.New()
	digest.Write([]byte("SLUG fixture retention receipt\x00v1\x00"))
	raw, _ := json.Marshal(r.Binding)
	digest.Write(raw)
	digest.Write([]byte(r.ManifestHash))
	for _, e := range []*Envelope{r.Recovery, r.Gym} {
		digest.Write([]byte(e.Nonce))
		digest.Write([]byte(e.Ciphertext))
	}
	return Receipt{Version: Version1, Binding: r.Binding, Manifest: cloneManifest(r.Manifest), ManifestHash: r.ManifestHash, RetentionID: hex.EncodeToString(digest.Sum(nil))}
}
func remaining(r vaultRecord) uint32 {
	switch r.State {
	case "reserved":
		return 3
	case "sealed":
		return 2
	case "verified":
		return 1
	case "enrolled":
		return 0
	}
	return 1000
}
func (v *Vault) validateRecord(r vaultRecord) error {
	if r.Revision == 0 || r.Revision > uint64(v.config.MaxOperations) || validateBinding(r.Binding) != nil || r.Binding.AuthorityID != v.authority.AuthorityID || recovery.ValidateManifest(r.Manifest) != nil || !reflect.DeepEqual(r.Manifest.Accounts, recovery.DefaultAccounts()) || r.Manifest.RootPublicKey != r.Binding.RootPublicKey || r.Manifest.GymPublicKey != r.Binding.GymPublicKey || r.Manifest.GymID != r.Binding.GymID {
		return ErrCorrupt
	}
	hash, err := manifestDigest(r.Manifest)
	if err != nil || hash != r.ManifestHash {
		return ErrCorrupt
	}
	if r.State == "reserved" {
		if r.Revision != 1 || r.Recovery != nil || r.Gym != nil || r.Receipt != nil {
			return ErrCorrupt
		}
		return nil
	}
	if r.Recovery == nil || r.Gym == nil {
		return ErrCorrupt
	}
	for _, e := range []*Envelope{r.Recovery, r.Gym} {
		if validateEnvelope(*e) != nil || e.Binding != r.Binding || e.ContentRevision != 1 || e.ManifestHash != r.ManifestHash || e.WrapperID != v.config.WrapperID || !allowedKey(v.config, e.Purpose, e.KeyRef) {
			return ErrCorrupt
		}
	}
	expectedWrap := uint64(1)
	if r.State == "enrolled" && r.Revision >= 4 {
		expectedWrap = r.Revision - 3
	}
	if r.Recovery.WrapRevision != expectedWrap || r.Gym.WrapRevision != expectedWrap {
		return ErrCorrupt
	}
	if r.Recovery.Purpose != RecoveryPurpose || r.Gym.Purpose != GymPurpose {
		return ErrCorrupt
	}
	switch r.State {
	case "sealed":
		if r.Revision != 2 || r.Receipt != nil {
			return ErrCorrupt
		}
	case "verified":
		if r.Revision != 3 || r.Receipt == nil {
			return ErrCorrupt
		}
	case "enrolled":
		if r.Revision < 4 || r.Receipt == nil {
			return ErrCorrupt
		}
	default:
		return ErrCorrupt
	}
	if r.Receipt != nil && !reflect.DeepEqual(*r.Receipt, retentionReceipt(r)) {
		return ErrCorrupt
	}
	return nil
}
func (v *Vault) record(id string) (vaultRecord, error) {
	var r vaultRecord
	var found *reservationIndex
	for i := range v.meta.Accounts {
		if v.meta.Accounts[i].AccountID == id {
			found = &v.meta.Accounts[i]
			break
		}
	}
	err := v.load("account:"+id, &r)
	if found == nil {
		if !errors.Is(err, ErrNotFound) {
			return r, ErrCorrupt
		}
		return r, ErrNotFound
	}
	if err != nil || r.Binding.AccountID != id || r.Binding.PrincipalID != found.PrincipalID || r.Binding.ProvisionID != found.ProvisionID || v.validateRecord(r) != nil {
		return vaultRecord{}, ErrCorrupt
	}
	return r, nil
}
func (v *Vault) commit(ctx context.Context, r vaultRecord, next vaultMetadata) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	batch := new(leveldb.Batch)
	if putVault(batch, "account:"+r.Binding.AccountID, r) != nil || putVault(batch, "meta", next) != nil {
		return ErrCorrupt
	}
	if v.writeBatch(batch, &opt.WriteOptions{Sync: true}) != nil {
		v.poisoned = true
		return ErrPoisoned
	}
	v.meta = next
	return nil
}
func (v *Vault) audit() error {
	if len(v.meta.Accounts) > 2 || uint64(v.meta.Operations)+uint64(v.meta.Reserved) > uint64(v.config.MaxOperations) {
		return ErrCorrupt
	}
	ids, provisions, gyms := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var ops, reserved uint64
	for _, idx := range v.meta.Accounts {
		if !canonicalHex(idx.AccountID, 32) || !canonicalHex(idx.PrincipalID, 32) || !canonicalHex(idx.ProvisionID, 32) || ids[idx.AccountID] || provisions[idx.ProvisionID] {
			return ErrCorrupt
		}
		ids[idx.AccountID] = true
		provisions[idx.ProvisionID] = true
		r, err := v.record(idx.AccountID)
		if err != nil || gyms[r.Binding.GymID] {
			return ErrCorrupt
		}
		gyms[r.Binding.GymID] = true
		ops += r.Revision
		reserved += uint64(remaining(r))
	}
	if ops != uint64(v.meta.Operations) || reserved != uint64(v.meta.Reserved) {
		return ErrCorrupt
	}
	it := v.db.NewIterator(nil, nil)
	defer it.Release()
	count := 0
	for it.Next() {
		count++
		key := string(it.Key())
		if len(it.Value()) > MaxRecordSize || (key != "meta" && (len(key) != 72 || key[:8] != "account:" || !ids[key[8:]])) {
			return ErrCorrupt
		}
	}
	if it.Error() != nil || count != 1+len(ids) {
		return ErrCorrupt
	}
	return nil
}
