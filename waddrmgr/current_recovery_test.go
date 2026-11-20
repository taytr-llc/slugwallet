package waddrmgr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/walletdb"
)

type currentInventoryLayout struct {
	ManagerVersion  uint32          `json:"manager_version"`
	DerivationMode  uint32          `json:"derivation_mode"`
	RecoveryVersion uint32          `json:"recovery_version"`
	WatchOnly       bool            `json:"watch_only"`
	Network         uint32          `json:"network"`
	Genesis         string          `json:"genesis"`
	PublicManifest  json.RawMessage `json:"public_manifest"`
	PublicRoot      string          `json:"public_root"`
	Scopes          []struct {
		Key      string `json:"key_hex"`
		IsBucket bool   `json:"is_bucket"`
		Schema   string `json:"schema_hex"`
		Accounts []struct {
			Key string `json:"key_hex"`
			Row string `json:"row_hex"`
		} `json:"accounts"`
		Imported string `json:"imported_index"`
	} `json:"scopes"`
}
type currentPublicVectors struct {
	Actual map[string]recovery.Manifest `json:"inherited_actual_manifests"`
	Rows   []struct {
		Name     string `json:"name"`
		Account  uint32 `json:"account"`
		Raw      string `json:"row_hex"`
		Accepted bool   `json:"accepted"`
		Cursors  struct {
			External uint32 `json:"next_external"`
			Internal uint32 `json:"next_internal"`
		} `json:"cursors"`
	} `json:"rows"`
	Inventories []struct {
		Name      string                 `json:"name"`
		Fixture   string                 `json:"fixture"`
		Layout    currentInventoryLayout `json:"layout"`
		Accepted  bool                   `json:"accepted"`
		Manifest  recovery.Manifest      `json:"manifest"`
		Canonical string                 `json:"manifest_canonical_utf8"`
		SHA       string                 `json:"manifest_sha256"`
	} `json:"inventories"`
}

func currentVectors(t *testing.T) currentPublicVectors {
	t.Helper()
	raw, e := os.ReadFile("../wallet/testdata/hosted-current-recovery/public.json")
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != "e5b71e541b8fd41328dc46ccfd4c14fb9f3de724eea34e9d2fec3d54b349ed3c" {
		t.Fatal("independent public reference changed")
	}
	var v currentPublicVectors
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	if len(v.Rows) != 25 || len(v.Inventories) != 38 {
		t.Fatal("incomplete independent corpus")
	}
	return v
}
func currentHex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestCurrentRecoveryIndependentMixedRows(t *testing.T) {
	for _, v := range currentVectors(t).Rows {
		t.Run(v.Name, func(t *testing.T) {
			x, y, e := currentAccountCursors(currentHex(t, v.Raw), v.Account)
			if (e == nil) != v.Accepted {
				t.Fatalf("accepted=%v error=%v", v.Accepted, e)
			}
			if e == nil && (x != v.Cursors.External || y != v.Cursors.Internal) {
				t.Fatal("independent cursor mismatch")
			}
			if e != nil && (x != 0 || y != 0) {
				t.Fatal("partial cursor result")
			}
		})
	}
}

func currentManager(t *testing.T, fixture string, original recovery.Manifest) (walletdb.DB, *Manager) {
	t.Helper()
	if wire.TestPoW {
		t.Skip("normal profile")
	}
	var entropy [32]byte
	if fixture == "incrementing256" {
		for i := range entropy {
			entropy[i] = byte(i)
		}
	} else if fixture != "zero256" {
		t.Fatal("fixture")
	}
	seed := recovery.SeedFromEntropy(entropy)
	root, e := hdkeychain.NewMaster(seed[:], &chaincfg.MainNetParams)
	clear(seed[:])
	if e != nil {
		t.Fatal(e)
	}
	defer root.Zero()
	raw, e := recovery.MarshalManifest(original)
	if e != nil {
		t.Fatal(e)
	}
	db, e := walletdb.Create("bdb", filepath.Join(t.TempDir(), "current.db"), true, time.Second, false)
	if e != nil {
		t.Fatal(e)
	}
	var mgr *Manager
	e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns, e := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if e != nil {
			return e
		}
		if e = CreateWithRecovery(ns, root, pubPassphrase, privPassphrase, &chaincfg.MainNetParams, fastScrypt, time.Unix(0, 0), raw, []byte("published fixture setup only")); e != nil {
			return e
		}
		mgr, e = Open(ns, pubPassphrase, &chaincfg.MainNetParams)
		return e
	})
	if e != nil {
		db.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { mgr.Close(); db.Close() })
	return db, mgr
}

type currentReadSpy struct {
	t        *testing.T
	counts   map[string]int
	cancel   context.CancelFunc
	cancelAt string
}
type currentReadBucket struct {
	walletdb.ReadBucket
	spy  *currentReadSpy
	path string
}

func (b currentReadBucket) NestedReadBucket(key []byte) walletdb.ReadBucket {
	p := b.path + "/" + hex.EncodeToString(key)
	allowed := false
	switch {
	case b.path == "":
		allowed = bytes.Equal(key, mainBucketName) || bytes.Equal(key, scopeBucketName) || bytes.Equal(key, scopeSchemaBucketName)
	case b.path == "/"+hex.EncodeToString(scopeBucketName):
		allowed = len(key) == 8
	case strings.Count(b.path, "/") == 2:
		allowed = bytes.Equal(key, acctBucketName) || bytes.Equal(key, addrAcctIdxBucketName)
	case strings.HasSuffix(b.path, "/"+hex.EncodeToString(addrAcctIdxBucketName)):
		allowed = bytes.Equal(key, uint32ToBytes(ImportedAddrAccount))
	}
	if !allowed {
		b.spy.t.Fatal("unexpected bucket read", p)
	}
	v := b.ReadBucket.NestedReadBucket(key)
	if v == nil {
		return nil
	}
	return currentReadBucket{v, b.spy, p}
}
func (b currentReadBucket) Get(key []byte) []byte {
	allowed := false
	switch b.path {
	case "/" + hex.EncodeToString(mainBucketName):
		for _, k := range [][]byte{mgrVersionName, derivationModeName, recoveryVersionName, watchingOnlyName, recoveryPublicName, masterHDPubName} {
			allowed = allowed || bytes.Equal(key, k)
		}
	case "/" + hex.EncodeToString(scopeSchemaBucketName):
		allowed = len(key) == 8
	default:
		allowed = strings.HasSuffix(b.path, "/"+hex.EncodeToString(addrAcctIdxBucketName)) && bytes.Equal(key, uint32ToBytes(ImportedAddrAccount))
	}
	if !allowed {
		b.spy.t.Fatal("private or unrelated Get", b.path, string(key))
	}
	return b.ReadBucket.Get(key)
}
func (b currentReadBucket) ForEach(func([]byte, []byte) error) error {
	b.spy.t.Fatal("unbounded ForEach")
	return nil
}
func (b currentReadBucket) ReadCursor() walletdb.ReadCursor {
	limit := 0
	switch {
	case b.path == "/"+hex.EncodeToString(scopeBucketName):
		limit = 5
	case strings.HasSuffix(b.path, "/"+hex.EncodeToString(acctBucketName)):
		limit = 3
	case strings.HasSuffix(b.path, "/"+hex.EncodeToString(addrAcctIdxBucketName)+"/"+hex.EncodeToString(uint32ToBytes(ImportedAddrAccount))):
		limit = 1
	}
	if limit == 0 {
		b.spy.t.Fatal("unexpected inventory cursor", b.path)
	}
	return &currentReadCursor{ReadCursor: b.ReadBucket.ReadCursor(), spy: b.spy, path: b.path, limit: limit}
}

type currentReadCursor struct {
	walletdb.ReadCursor
	spy   *currentReadSpy
	path  string
	limit int
}

func (c *currentReadCursor) check(k, v []byte) ([]byte, []byte) {
	if k != nil {
		c.spy.counts[c.path]++
		if c.spy.counts[c.path] > c.limit {
			c.spy.t.Fatal("unbounded cursor", c.path)
		}
		if c.spy.cancel != nil && c.path == c.spy.cancelAt {
			c.spy.cancel()
		}
	}
	return k, v
}
func (c *currentReadCursor) First() ([]byte, []byte) { return c.check(c.ReadCursor.First()) }
func (c *currentReadCursor) Next() ([]byte, []byte)  { return c.check(c.ReadCursor.Next()) }

func currentApplyLayout(t *testing.T, ns walletdb.ReadWriteBucket, mgr *Manager, v currentInventoryLayout) {
	t.Helper()
	must := func(e error) {
		if e != nil {
			t.Fatal(e)
		}
	}
	main := ns.NestedReadWriteBucket(mainBucketName)
	for _, row := range []struct {
		k []byte
		v uint32
	}{{mgrVersionName, v.ManagerVersion}, {derivationModeName, v.DerivationMode}, {recoveryVersionName, v.RecoveryVersion}} {
		must(main.Put(row.k, uint32ToBytes(row.v)))
	}
	watch := byte(0)
	if v.WatchOnly {
		watch = 1
	}
	must(main.Put(watchingOnlyName, []byte{watch}))
	var compact bytes.Buffer
	if e := json.Compact(&compact, v.PublicManifest); e != nil {
		t.Fatal(e)
	}
	pub, e := mgr.cryptoKeyPub.Encrypt(compact.Bytes())
	must(e)
	must(main.Put(recoveryPublicName, pub))
	root, e := mgr.cryptoKeyPub.Encrypt([]byte(v.PublicRoot))
	must(e)
	must(main.Put(masterHDPubName, root))
	must(ns.DeleteNestedBucket(scopeBucketName))
	must(ns.DeleteNestedBucket(scopeSchemaBucketName))
	scopes, e := ns.CreateBucket(scopeBucketName)
	must(e)
	schemas, e := ns.CreateBucket(scopeSchemaBucketName)
	must(e)
	for _, s := range v.Scopes {
		key := currentHex(t, s.Key)
		must(schemas.Put(key, currentHex(t, s.Schema)))
		if !s.IsBucket {
			must(scopes.Put(key, []byte("value")))
			continue
		}
		b, e := scopes.CreateBucket(key)
		must(e)
		a, e := b.CreateBucket(acctBucketName)
		must(e)
		for _, row := range s.Accounts {
			must(a.Put(currentHex(t, row.Key), currentHex(t, row.Row)))
		}
		if s.Imported == "parent_missing" {
			continue
		}
		idx, e := b.CreateBucket(addrAcctIdxBucketName)
		must(e)
		if s.Imported != "absent" {
			imp, e := idx.CreateBucket(uint32ToBytes(ImportedAddrAccount))
			must(e)
			if s.Imported == "present" {
				must(imp.Put([]byte{1}, []byte{1}))
			}
		}
	}
}

func TestCurrentRecoveryIndependentInventoriesAndNoPrivateReads(t *testing.T) {
	vectors := currentVectors(t)
	for _, fixture := range []string{"zero256", "incrementing256"} {
		t.Run(fixture, func(t *testing.T) {
			original := vectors.Actual[fixture]
			original.Accounts = recovery.DefaultAccounts()
			db, mgr := currentManager(t, fixture, original)
			rollback := errors.New("test-only rollback")
			for _, v := range vectors.Inventories {
				if v.Fixture != fixture {
					continue
				}
				t.Run(v.Name, func(t *testing.T) {
					params := *mgr.chainParams
					params.Net = wire.BitcoinNet(v.Layout.Network)
					hash, e := chainhash.NewHashFromStr(v.Layout.Genesis)
					if e != nil {
						t.Fatal(e)
					}
					params.GenesisHash = hash
					old := mgr.chainParams
					mgr.chainParams = &params
					defer func() { mgr.chainParams = old }()
					var got recovery.Manifest
					var readErr error
					spy := &currentReadSpy{t: t, counts: map[string]int{}}
					e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
						ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
						currentApplyLayout(t, ns, mgr, v.Layout)
						got, readErr = mgr.ReadCurrentRecoveryManifest(context.Background(), currentReadBucket{ns, spy, ""})
						return rollback
					})
					if !errors.Is(e, rollback) {
						t.Fatal(e)
					}
					if (readErr == nil) != v.Accepted {
						t.Fatalf("accepted=%v error=%v", v.Accepted, readErr)
					}
					if readErr == nil {
						raw, e := recovery.MarshalManifest(got)
						if e != nil || string(raw) != v.Canonical || !reflect.DeepEqual(got, v.Manifest) {
							t.Fatal("independent manifest mismatch", e)
						}
						sum := sha256.Sum256(raw)
						if hex.EncodeToString(sum[:]) != v.SHA {
							t.Fatal("independent digest mismatch")
						}
					}
					if readErr != nil && !reflect.DeepEqual(got, recovery.Manifest{}) {
						t.Fatal("partial inventory")
					}
					if !mgr.IsLocked() {
						t.Fatal("reader unlocked manager")
					}
				})
			}
		})
	}
}

func TestCurrentRecoveryCancellationClosedAndNoSyncRequirement(t *testing.T) {
	v := currentVectors(t)
	m := v.Actual["zero256"]
	m.Accounts = recovery.DefaultAccounts()
	db, mgr := currentManager(t, "zero256", m)
	if e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return tx.ReadWriteBucket(waddrmgrNamespaceKey).DeleteNestedBucket(syncBucketName)
	}); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	spy := &currentReadSpy{t: t, counts: map[string]int{}, cancel: cancel, cancelAt: "/" + hex.EncodeToString(scopeBucketName)}
	if e := walletdb.View(db, func(tx walletdb.ReadTx) error {
		got, e := mgr.ReadCurrentRecoveryManifest(ctx, currentReadBucket{tx.ReadBucket(waddrmgrNamespaceKey), spy, ""})
		if !reflect.DeepEqual(got, recovery.Manifest{}) {
			t.Fatal("cancelled partial inventory")
		}
		return e
	}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if e := walletdb.View(db, func(tx walletdb.ReadTx) error {
		_, e := mgr.ReadCurrentRecoveryManifest(context.Background(), currentReadBucket{tx.ReadBucket(waddrmgrNamespaceKey), &currentReadSpy{t: t, counts: map[string]int{}}, ""})
		return e
	}); e != nil {
		t.Fatal("capture improperly required chain sync", e)
	}
	mgr.Close()
	if e := walletdb.View(db, func(tx walletdb.ReadTx) error {
		_, e := mgr.ReadCurrentRecoveryManifest(context.Background(), tx.ReadBucket(waddrmgrNamespaceKey))
		return e
	}); !errors.Is(e, ErrCurrentRecoveryUnavailable) {
		t.Fatal(e)
	}
}

func TestCurrentRecoveryCheapProfileBeforePublicStorage(t *testing.T) {
	if !wire.TestPoW {
		t.Skip("tagged refusal")
	}
	var mgr *Manager
	_, e := mgr.ReadCurrentRecoveryManifest(context.Background(), currentReadBucket{})
	if !errors.Is(e, ErrCurrentRecoveryProfile) {
		t.Fatal(e)
	}
}

type currentNoDecrypt struct {
	EncryptorDecryptor
	t *testing.T
}

func (c currentNoDecrypt) Decrypt([]byte) ([]byte, error) {
	c.t.Fatal("oversized public field reached decryption")
	return nil, ErrCurrentRecoveryCorrupt
}
func TestCurrentRecoveryPublicCipherBoundBeforeDecrypt(t *testing.T) {
	v := currentVectors(t)
	m := v.Actual["zero256"]
	m.Accounts = recovery.DefaultAccounts()
	db, mgr := currentManager(t, "zero256", m)
	if e := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return tx.ReadWriteBucket(waddrmgrNamespaceKey).NestedReadWriteBucket(mainBucketName).Put(recoveryPublicName, make([]byte, 4096+41))
	}); e != nil {
		t.Fatal(e)
	}
	key := mgr.cryptoKeyPub
	mgr.cryptoKeyPub = currentNoDecrypt{key, t}
	defer func() { mgr.cryptoKeyPub = key }()
	e := walletdb.View(db, func(tx walletdb.ReadTx) error {
		_, e := mgr.ReadCurrentRecoveryManifest(context.Background(), currentReadBucket{tx.ReadBucket(waddrmgrNamespaceKey), &currentReadSpy{t: t, counts: map[string]int{}}, ""})
		return e
	})
	if !errors.Is(e, ErrCurrentRecoveryCorrupt) {
		t.Fatal("public ciphertext capacity", e)
	}
}
