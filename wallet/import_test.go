package wallet

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/taytr-llc/slug/address/v2"
	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/txscript/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func hardenedKey(key uint32) uint32 {
	return key + hdkeychain.HardenedKeyStart
}

func deriveAcctPubKey(t *testing.T, root *hdkeychain.ExtendedKey,
	scope waddrmgr.KeyScope, paths ...uint32) *hdkeychain.ExtendedKey {

	path := []uint32{hardenedKey(scope.Purpose), hardenedKey(scope.Coin)}
	path = append(path, paths...)

	var (
		currentKey = root
		err        error
	)
	for _, pathPart := range path {
		currentKey, err = currentKey.Derive(pathPart)
		require.NoError(t, err)
	}

	// The Neuter() method checks the version and doesn't know any
	// non-standard methods. We need to convert them to standard, neuter,
	// then convert them back with the target extended public key version.
	pubVersionBytes := make([]byte, 4)
	copy(pubVersionBytes, chaincfg.TestNet3Params.HDPublicKeyID[:])
	privateVersion := chaincfg.TestNet3Params.HDPrivateKeyID
	switch {
	case root.IsForNet(&chaincfg.MainNetParams):
		copy(pubVersionBytes, chaincfg.MainNetParams.HDPublicKeyID[:])
		privateVersion = chaincfg.MainNetParams.HDPrivateKeyID

	case strings.HasPrefix(root.String(), "uprv"):
		binary.BigEndian.PutUint32(pubVersionBytes, uint32(
			waddrmgr.HDVersionTestNetBIP0049,
		))

	case strings.HasPrefix(root.String(), "vprv"):
		binary.BigEndian.PutUint32(pubVersionBytes, uint32(
			waddrmgr.HDVersionTestNetBIP0084,
		))
	}

	currentKey, err = currentKey.CloneWithVersion(
		privateVersion[:],
	)
	require.NoError(t, err)
	currentKey, err = currentKey.Neuter()
	require.NoError(t, err)
	currentKey, err = currentKey.CloneWithVersion(pubVersionBytes)
	require.NoError(t, err)

	return currentKey
}

type testCase struct {
	name               string
	masterPriv         string
	accountIndex       uint32
	addrType           waddrmgr.AddressType
	expectedScope      waddrmgr.KeyScope
	expectedAddr       string
	expectedChangeAddr string
}

var (
	testCases = []*testCase{{
		name: "bip44 with nested witness address type",
		masterPriv: "tprv8ZgxMBicQKsPeWwrFuNjEGTTDSY4mRLwd2KDJAPGa1AY" +
			"quw38bZqNMSuB3V1Va3hqJBo9Pt8Sx7kBQer5cNMrb8SYquoWPt9" +
			"Y3BZdhdtUcw",
		accountIndex:       0,
		addrType:           waddrmgr.NestedWitnessPubKey,
		expectedScope:      waddrmgr.KeyScopeBIP0049Plus,
		expectedAddr:       "2N5YTxG9XtGXx1YyhZb7N2pwEjoZLLMHGKj",
		expectedChangeAddr: "2N7wpz5Gy2zEJTvq2MAuU6BCTEBLXNQ8dUw",
	}, {
		name: "bip44 with witness address type",
		masterPriv: "tprv8ZgxMBicQKsPeWwrFuNjEGTTDSY4mRLwd2KDJAPGa1AY" +
			"quw38bZqNMSuB3V1Va3hqJBo9Pt8Sx7kBQer5cNMrb8SYquoWPt9" +
			"Y3BZdhdtUcw",
		accountIndex:       777,
		addrType:           waddrmgr.WitnessPubKey,
		expectedScope:      waddrmgr.KeyScopeBIP0084,
		expectedAddr:       "tb1qllxcutkzsukf8u8c8stkp464j0esu9xq7qju8x",
		expectedChangeAddr: "tb1qu6jmqglrthscptjqj3egx54wy8xqvzn5hslgw7",
	}, {
		name: "traditional bip49",
		masterPriv: "uprv8tXDerPXZ1QsVp8y6GAMSMYxPQgWi3LSY8qS5ZH9x1YRu" +
			"1kGPFjPzR73CFSbVUhdEwJbtsUgucUJ4hGQoJnNepp3RBcE6Jhdom" +
			"FD2KeY6G9",
		accountIndex:       9,
		addrType:           waddrmgr.NestedWitnessPubKey,
		expectedScope:      waddrmgr.KeyScopeBIP0049Plus,
		expectedAddr:       "2NBCJ9WzGXZqpLpXGq3Hacybj3c4eHRcqgh",
		expectedChangeAddr: "2N3bankFu6F3ZNU41iVJQqyS9MXqp9dvn1M",
	}, {
		name: "bip49+",
		masterPriv: "uprv8tXDerPXZ1QsVp8y6GAMSMYxPQgWi3LSY8qS5ZH9x1YRu" +
			"1kGPFjPzR73CFSbVUhdEwJbtsUgucUJ4hGQoJnNepp3RBcE6Jhdom" +
			"FD2KeY6G9",
		accountIndex:       9,
		addrType:           waddrmgr.WitnessPubKey,
		expectedScope:      waddrmgr.KeyScopeBIP0049Plus,
		expectedAddr:       "2NBCJ9WzGXZqpLpXGq3Hacybj3c4eHRcqgh",
		expectedChangeAddr: "tb1qeqn05w2hfq6axpdprhs4y7x65gxkkvfvyxqk4u",
	}, {
		name: "bip84",
		masterPriv: "vprv9DMUxX4ShgxMM7L5vcwyeSeTZNpxefKwTFMerxB3L1vJ" +
			"x7ZVdutxcUmBDTQBVPMYeaRQeM5FNGpqwysyX1CPT4VeHXJegDX8" +
			"5VJrQvaFaz3",
		accountIndex:       1,
		addrType:           waddrmgr.WitnessPubKey,
		expectedScope:      waddrmgr.KeyScopeBIP0084,
		expectedAddr:       "tb1q5vepvcl0z8xj7kps4rsux722r4dvfwlhk6j532",
		expectedChangeAddr: "tb1qlwe2kgxcsa8x4huu79yff4rze0l5mwafg5c7xd",
	}}
)

// TestImportAccount tests that extended public keys can successfully be
// imported into both watch only and normal wallets.
func TestImportAccount(t *testing.T) {
	t.Parallel()

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w, cleanup := testWallet(t)
			defer cleanup()

			testImportAccount(t, w, tc, false, tc.name)
		})

		name := tc.name + " watch-only"
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			w, cleanup := testWalletWatchingOnly(t)
			defer cleanup()

			testImportAccount(t, w, tc, true, name)
		})
	}
}

func testImportAccount(t *testing.T, w *Wallet, tc *testCase, watchOnly bool,
	name string) {

	// First derive the master public key of the account we want to import.
	root, err := hdkeychain.NewKeyFromString(tc.masterPriv)
	require.NoError(t, err)

	// Derive the extended private and public key for our target account.
	acct1Pub := deriveAcctPubKey(
		t, root, tc.expectedScope, hardenedKey(tc.accountIndex),
	)

	// We want to make sure we can import and handle multiple accounts, so
	// we create another one.
	acct2Pub := deriveAcctPubKey(
		t, root, tc.expectedScope, hardenedKey(tc.accountIndex+1),
	)

	// And we also want to be able to import loose extended public keys
	// without needing to specify an explicit scope.
	acct3ExternalExtPub := deriveAcctPubKey(
		t, root, tc.expectedScope, hardenedKey(tc.accountIndex+2), 0, 0,
	)
	acct3ExternalPub, err := acct3ExternalExtPub.ECPubKey()
	require.NoError(t, err)

	// Do a dry run import first and check that it results in the expected
	// addresses being derived.
	_, extAddrs, intAddrs, err := w.ImportAccountDryRun(
		name+"1", acct1Pub, root.ParentFingerprint(), &tc.addrType, 1,
	)
	require.NoError(t, err)
	require.Len(t, extAddrs, 1)
	require.Equal(t, tc.expectedAddr, extAddrs[0].Address().String())
	require.Len(t, intAddrs, 1)
	require.Equal(t, tc.expectedChangeAddr, intAddrs[0].Address().String())

	// Import the extended public keys into new accounts.
	acct1, err := w.ImportAccount(
		name+"1", acct1Pub, root.ParentFingerprint(), &tc.addrType,
	)
	require.NoError(t, err)
	require.Equal(t, tc.expectedScope, acct1.KeyScope)

	acct2, err := w.ImportAccount(
		name+"2", acct2Pub, root.ParentFingerprint(), &tc.addrType,
	)
	require.NoError(t, err)
	require.Equal(t, tc.expectedScope, acct2.KeyScope)

	err = w.ImportPublicKey(acct3ExternalPub, tc.addrType)
	require.NoError(t, err)

	// If the wallet is watch only, there is no default account and our
	// imported account will be index 0.
	firstAccountIndex := uint32(1)
	numAccounts := 2
	if watchOnly {
		firstAccountIndex = 0
		numAccounts = 1
	}

	// We should have 2 additional accounts now.
	acctResult, err := w.Accounts(tc.expectedScope)
	require.NoError(t, err)
	require.Len(t, acctResult.Accounts, numAccounts+2)

	// Validate the state of the accounts.
	require.Equal(t, firstAccountIndex, acct1.AccountNumber)
	require.Equal(t, name+"1", acct1.AccountName)
	require.Equal(t, true, acct1.IsWatchOnly)
	require.Equal(t, root.ParentFingerprint(), acct1.MasterKeyFingerprint)
	require.NotNil(t, acct1.AccountPubKey)
	require.Equal(t, acct1Pub.String(), acct1.AccountPubKey.String())
	require.Equal(t, uint32(0), acct1.InternalKeyCount)
	require.Equal(t, uint32(0), acct1.ExternalKeyCount)
	require.Equal(t, uint32(0), acct1.ImportedKeyCount)

	require.Equal(t, firstAccountIndex+1, acct2.AccountNumber)
	require.Equal(t, name+"2", acct2.AccountName)
	require.Equal(t, true, acct2.IsWatchOnly)
	require.Equal(t, root.ParentFingerprint(), acct2.MasterKeyFingerprint)
	require.NotNil(t, acct2.AccountPubKey)
	require.Equal(t, acct2Pub.String(), acct2.AccountPubKey.String())
	require.Equal(t, uint32(0), acct2.InternalKeyCount)
	require.Equal(t, uint32(0), acct2.ExternalKeyCount)
	require.Equal(t, uint32(0), acct2.ImportedKeyCount)

	// Test address derivation.
	extAddr, err := w.NewAddress(acct1.AccountNumber, tc.expectedScope)
	require.NoError(t, err)
	require.Equal(t, tc.expectedAddr, extAddr.String())
	intAddr, err := w.NewChangeAddress(acct1.AccountNumber, tc.expectedScope)
	require.NoError(t, err)
	require.Equal(t, tc.expectedChangeAddr, intAddr.String())

	// Make sure the key count was increased.
	acct1, err = w.AccountProperties(tc.expectedScope, acct1.AccountNumber)
	require.NoError(t, err)
	require.Equal(t, uint32(1), acct1.InternalKeyCount)
	require.Equal(t, uint32(1), acct1.ExternalKeyCount)
	require.Equal(t, uint32(0), acct1.ImportedKeyCount)

	// Make sure we can't get private keys for the imported accounts.
	_, err = w.DumpWIFPrivateKey(intAddr)
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrWatchingOnly))

	// Get the address info for the single key we imported.
	switch tc.addrType {
	case waddrmgr.NestedWitnessPubKey:
		witnessAddr, err := address.NewAddressWitnessPubKeyHash(
			address.Hash160(acct3ExternalPub.SerializeCompressed()),
			w.chainParams,
		)
		require.NoError(t, err)

		witnessProg, err := txscript.PayToAddrScript(witnessAddr)
		require.NoError(t, err)

		intAddr, err = address.NewAddressScriptHash(
			witnessProg, w.chainParams,
		)
		require.NoError(t, err)

	case waddrmgr.WitnessPubKey:
		intAddr, err = address.NewAddressWitnessPubKeyHash(
			address.Hash160(acct3ExternalPub.SerializeCompressed()),
			w.chainParams,
		)
		require.NoError(t, err)

	default:
		t.Fatalf("unhandled address type %v", tc.addrType)
	}

	addrManaged, err := w.AddressInfo(intAddr)
	require.NoError(t, err)
	require.Equal(t, true, addrManaged.Imported())
}

// TestSLUGImportAccount preserves the upstream testnet key/script payloads,
// using independently re-encoded SLUG fixtures. A native SLUG extended-key
// prefix carries network identity; callers must supply the address schema.
func TestSLUGImportAccount(t *testing.T) {
	raw, err := os.ReadFile("../waddrmgr/testdata/slug_encoding_vectors.json")
	require.NoError(t, err)
	var vectors []struct {
		Bitcoin string `json:"bitcoin"`
		SLUG    string `json:"slug"`
	}
	require.NoError(t, json.Unmarshal(raw, &vectors))
	encoded := make(map[string]string)
	for _, vector := range vectors {
		encoded[vector.Bitcoin] = vector.SLUG
	}
	convert := func(original string) string {
		t.Helper()
		value, ok := encoded[original]
		require.True(t, ok, "missing independent encoding fixture")
		return value
	}

	// The mixed BIP49+ external/internal schema is intentionally absent:
	// one network prefix cannot encode that extra recovery metadata.
	for _, index := range []int{0, 1, 2, 4} {
		original := testCases[index]
		t.Run(original.name, func(t *testing.T) {
			loader := NewLoader(
				&chaincfg.MainNetParams, t.TempDir(), true,
				defaultDBTimeout, 250,
			)
			w, err := loader.CreateNewWatchingOnlyWallet(
				[]byte("public-SLUG-fixture-only"), time.Unix(1, 0),
			)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, loader.UnloadWallet()) })
			w.chainClient = &mockChainClient{}
			err = walletdb.Update(w.Database(), func(tx walletdb.ReadWriteTx) error {
				ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
				for scope, schema := range waddrmgr.ScopeAddrMap {
					if _, err := w.Manager.NewScopedKeyManager(ns, scope, schema); err != nil {
						return err
					}
				}
				return nil
			})
			require.NoError(t, err)
			fixture := *original
			fixture.masterPriv = convert(original.masterPriv)
			fixture.expectedAddr = convert(original.expectedAddr)
			fixture.expectedChangeAddr = convert(original.expectedChangeAddr)
			testImportAccount(t, w, &fixture, true, "SLUG "+fixture.name)

			root, err := hdkeychain.NewKeyFromString(fixture.masterPriv)
			require.NoError(t, err)
			pub := deriveAcctPubKey(t, root, fixture.expectedScope, hardenedKey(123))
			require.Equal(t, []byte{0x53, 0x4c, 0x55, 0x47}, pub.Version())
			_, _, _, err = w.ImportAccountDryRun("missing-schema", pub, 0, nil, 1)
			require.Error(t, err, "SLUG encoding must not guess recovery schema")
			for _, version := range [][4]byte{
				{0x04, 0x88, 0xb2, 0x1e}, // Bitcoin xpub.
				{0x04, 0x9d, 0x7c, 0xb2}, // Bitcoin ypub.
				{0x04, 0xb2, 0x47, 0x46}, // Bitcoin zpub.
				{0x04, 0x35, 0x87, 0xcf}, // Testnet tpub.
			} {
				wrongNetwork, err := pub.CloneWithVersion(version[:])
				require.NoError(t, err)
				_, _, _, err = w.ImportAccountDryRun(
					"wrong-network", wrongNetwork, 0, &fixture.addrType, 1,
				)
				require.Error(t, err, "foreign network HD encoding accepted")
			}
		})
	}
}
