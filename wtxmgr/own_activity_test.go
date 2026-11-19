package wtxmgr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/taytr-llc/slug/chainhash/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
)

type activityFixtureRecord struct {
	TxID     string `json:"txid"`
	Raw      string `json:"raw_hex"`
	Recorded int64  `json:"recorded_at_ms"`
	Block    *struct {
		Height uint32 `json:"height"`
		Hash   string `json:"hash"`
		Time   int64  `json:"time_ms"`
	} `json:"block"`
	Credits []struct {
		Index  uint32 `json:"index"`
		Atoms  int64  `json:"atoms"`
		Change bool   `json:"change"`
	} `json:"credits"`
	Debits []struct {
		Index uint32 `json:"index"`
		Atoms int64  `json:"atoms"`
	} `json:"debits"`
}
type activityFixtureStorage struct {
	Name     string                       `json:"name"`
	Height   uint32                       `json:"height"`
	Buckets  map[string]map[string]string `json:"buckets"`
	Expected json.RawMessage              `json:"expected"`
	Category string                       `json:"category"`
}
type activityFixture struct {
	Transactions struct {
		Positives []struct {
			Name   string                `json:"name"`
			Record activityFixtureRecord `json:"record"`
		} `json:"positives"`
		Raw      []struct{ Name, Raw, Category string } `json:"unused"`
		RawCases []struct {
			Name     string `json:"name"`
			Raw      string `json:"raw_hex"`
			Category string `json:"category"`
		} `json:"raw_cases"`
	} `json:"transactions"`
	Storage []activityFixtureStorage `json:"storage"`
	Budgets []struct {
		Name               string                       `json:"name"`
		Remaining          int                          `json:"remaining_raw_bytes"`
		TxID               string                       `json:"txid"`
		Buckets            map[string]map[string]string `json:"buckets"`
		Expected, Category string
		Record             activityFixtureRecord `json:"record"`
	} `json:"raw_budget_controls"`
}

func activityFixtures(t *testing.T) activityFixture {
	t.Helper()
	raw, e := os.ReadFile("../wallet/testdata/own-activity/core-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != "4b3880f7facb9286502aa6a3bdcf38db7821a96e1d1b622f4d27a898a057598e" {
		t.Fatal("frozen independent corpus changed")
	}
	var f activityFixture
	if e = json.Unmarshal(raw, &f); e != nil {
		t.Fatal(e)
	}
	if len(f.Storage) != 27 || len(f.Transactions.Positives) != 44 || len(f.Transactions.RawCases) != 18 || len(f.Budgets) != 4 {
		t.Fatal("independent case counts")
	}
	return f
}
func activityHex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func activityHash(t *testing.T, s string) chainhash.Hash {
	t.Helper()
	h, e := chainhash.NewHashFromStr(s)
	if e != nil {
		t.Fatal(e)
	}
	return *h
}
func activityExpected(t *testing.T, r activityFixtureRecord) OwnActivityRecord {
	t.Helper()
	v := OwnActivityRecord{TxID: activityHash(t, r.TxID), Raw: activityHex(t, r.Raw), RecordedAtMS: r.Recorded, Credits: make([]OwnActivityCredit, 0), Debits: make([]OwnActivityDebit, 0)}
	if r.Block != nil {
		v.Block = &OwnActivityBlock{Height: r.Block.Height, Hash: activityHash(t, r.Block.Hash), TimeMS: r.Block.Time}
	}
	for _, c := range r.Credits {
		v.Credits = append(v.Credits, OwnActivityCredit{Index: c.Index, Atoms: c.Atoms, Change: c.Change})
	}
	for _, d := range r.Debits {
		v.Debits = append(v.Debits, OwnActivityDebit{Index: d.Index, Atoms: d.Atoms})
	}
	return v
}
func activityDB(t *testing.T, buckets map[string]map[string]string) (*Store, walletdb.DB) {
	t.Helper()
	s, db, e := testStore(t)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(namespaceKey)
		for name, rows := range buckets {
			b := ns.NestedReadWriteBucket([]byte(name))
			if b == nil {
				var e error
				b, e = ns.CreateBucket([]byte(name))
				if e != nil {
					return e
				}
			}
			for k, v := range rows {
				if e := b.Put(activityHex(t, k), activityHex(t, v)); e != nil {
					return e
				}
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return s, db
}

type activityCount struct {
	gets, positions int
	t               *testing.T
}
type activityBucket struct {
	walletdb.ReadBucket
	name  string
	count *activityCount
}

func (b activityBucket) NestedReadBucket(k []byte) walletdb.ReadBucket {
	v := b.ReadBucket.NestedReadBucket(k)
	if v == nil {
		return nil
	}
	return activityBucket{ReadBucket: v, name: string(k), count: b.count}
}
func (b activityBucket) Get(k []byte) []byte {
	if b.name == "mi" || b.name == "l" || b.name == "lo" {
		b.count.t.Fatal("unrelated wallet data read", b.name)
	}
	b.count.gets++
	return b.ReadBucket.Get(k)
}
func (b activityBucket) ForEach(f func([]byte, []byte) error) error {
	b.count.t.Fatal("unbounded bucket enumeration", b.name)
	return nil
}
func (b activityBucket) ReadCursor() walletdb.ReadCursor {
	if b.name == "t" || b.name == "mi" {
		b.count.t.Fatal("whole mined/spender cursor", b.name)
	}
	return activityCursor{ReadCursor: b.ReadBucket.ReadCursor(), name: b.name, count: b.count}
}

type activityCursor struct {
	walletdb.ReadCursor
	name  string
	count *activityCount
}

func (c activityCursor) result(k, v []byte) ([]byte, []byte) {
	if c.name == "c" || c.name == "d" || c.name == "mc" {
		c.count.positions++
	}
	return k, v
}
func (c activityCursor) First() ([]byte, []byte)        { return c.result(c.ReadCursor.First()) }
func (c activityCursor) Last() ([]byte, []byte)         { return c.result(c.ReadCursor.Last()) }
func (c activityCursor) Next() ([]byte, []byte)         { return c.result(c.ReadCursor.Next()) }
func (c activityCursor) Prev() ([]byte, []byte)         { return c.result(c.ReadCursor.Prev()) }
func (c activityCursor) Seek(k []byte) ([]byte, []byte) { return c.result(c.ReadCursor.Seek(k)) }
func activityErrorIs(e error, category string) bool {
	if category == "capacity" {
		return errors.Is(e, ErrOwnActivityCapacity)
	}
	return errors.Is(e, ErrOwnActivityCorrupt)
}

func TestOwnActivityIndependentStorage(t *testing.T) {
	for _, v := range activityFixtures(t).Storage {
		t.Run(v.Name, func(t *testing.T) {
			s, db := activityDB(t, v.Buckets)
			var rows []OwnActivityRecord
			var older bool
			counts := &activityCount{t: t}
			e := walletdb.View(db, func(tx walletdb.ReadTx) error {
				var e error
				rows, older, e = s.CaptureOwnActivity(context.Background(), activityBucket{ReadBucket: tx.ReadBucket(namespaceKey), count: counts}, v.Height)
				return e
			})
			if string(v.Expected) == `"reject"` {
				if !activityErrorIs(e, v.Category) || rows != nil || older {
					t.Fatalf("expected %s no partial data: %v", v.Category, e)
				}
				return
			}
			var expected struct {
				Older     bool                    `json:"has_older"`
				Records   []activityFixtureRecord `json:"records"`
				Gets      int                     `json:"gets"`
				Positions int                     `json:"index_positions"`
				Visits    int                     `json:"metadata_visits"`
			}
			if json.Unmarshal(v.Expected, &expected) != nil {
				t.Fatal("reference result")
			}
			if e != nil || older != expected.Older || len(rows) != len(expected.Records) || rows == nil {
				t.Fatalf("capture shape %d/%d older %v/%v: %v", len(rows), len(expected.Records), older, expected.Older, e)
			}
			for i, want := range expected.Records {
				if !reflect.DeepEqual(rows[i], activityExpected(t, want)) {
					t.Fatalf("record %d differs from independent source", i)
				}
			}
			if counts.gets != expected.Gets || counts.positions != expected.Positions {
				t.Fatalf("bounded reads gets=%d/%d positions=%d/%d", counts.gets, expected.Gets, counts.positions, expected.Positions)
			}
			e = walletdb.View(db, func(tx walletdb.ReadTx) error {
				r := activityReader{ns: tx.ReadBucket(namespaceKey)}
				_, _, e := r.selectRecords(context.Background(), v.Height)
				if e == nil && r.visits != expected.Visits {
					t.Fatalf("metadata charge %d/%d", r.visits, expected.Visits)
				}
				return e
			})
			if e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestOwnActivityIndependentRawAndBudget(t *testing.T) {
	f := activityFixtures(t)
	for _, v := range f.Transactions.Positives {
		t.Run(v.Name, func(t *testing.T) {
			raw := activityHex(t, v.Record.Raw)
			tx, _, e := parseOwnActivityTx(context.Background(), raw)
			if e != nil || tx.TxHash() != activityHash(t, v.Record.TxID) {
				t.Fatal("independent valid transaction", e)
			}
		})
	}
	for _, v := range f.Transactions.RawCases {
		t.Run(v.Name, func(t *testing.T) {
			_, _, e := parseOwnActivityTx(context.Background(), activityHex(t, v.Raw))
			if !activityErrorIs(e, v.Category) {
				t.Fatalf("expected %s: %v", v.Category, e)
			}
		})
	}
	for _, v := range f.Budgets {
		t.Run(v.Name, func(t *testing.T) {
			_, db := activityDB(t, v.Buckets)
			var got OwnActivityRecord
			e := walletdb.View(db, func(tx walletdb.ReadTx) error {
				r := activityReader{ns: tx.ReadBucket(namespaceKey)}
				h := activityHash(t, v.TxID)
				raw := r.ns.NestedReadBucket(bucketUnmined).Get(h[:])
				stamp, err := activityTime(raw[:8])
				if err != nil {
					return err
				}
				got, err = r.record(context.Background(), activitySelection{hash: h, recorded: stamp}, v.Remaining)
				return err
			})
			if v.Expected == "reject" {
				if !activityErrorIs(e, v.Category) || got.Raw != nil {
					t.Fatalf("budget expected %s: %v", v.Category, e)
				}
			} else if e != nil || !reflect.DeepEqual(got, activityExpected(t, v.Record)) {
				t.Fatal("exact budget rejected", e)
			}
		})
	}
}
func TestOwnActivityOwnedAndCancelled(t *testing.T) {
	var v activityFixtureStorage
	for _, c := range activityFixtures(t).Storage {
		if c.Name == "actual-shaped-zero256" {
			v = c
		}
	}
	s, db := activityDB(t, v.Buckets)
	read := func(ctx context.Context) ([]OwnActivityRecord, error) {
		var rows []OwnActivityRecord
		e := walletdb.View(db, func(tx walletdb.ReadTx) error {
			var err error
			rows, _, err = s.CaptureOwnActivity(ctx, tx.ReadBucket(namespaceKey), v.Height)
			return err
		})
		return rows, e
	}
	rows, e := read(context.Background())
	if e != nil || len(rows) != 3 {
		t.Fatal(e)
	}
	second, e := read(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	rows[0].Raw[0] ^= 1
	rows[0].Credits[0].Atoms++
	rows[0].Block.Height++
	if reflect.DeepEqual(rows[0], second[0]) {
		t.Fatal("test mutation")
	}
	third, e := read(context.Background())
	if e != nil || !reflect.DeepEqual(third, second) {
		t.Fatal("returned storage aliased", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled, e := read(ctx)
	if !errors.Is(e, context.Canceled) || cancelled != nil {
		t.Fatal("partial cancelled capture", e)
	}
	if e = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return tx.ReadWriteBucket(namespaceKey).DeleteNestedBucket(bucketTxRecords)
	}); e != nil {
		t.Fatal(e)
	}
	if len(second[0].Raw) == 0 || bytes.Equal(rows[0].Raw, second[0].Raw) {
		t.Fatal("owned evidence lost")
	}
	absent, e := read(context.Background())
	if !errors.Is(e, ErrOwnActivityCorrupt) || absent != nil {
		t.Fatal("missing required bucket", e)
	}
}
