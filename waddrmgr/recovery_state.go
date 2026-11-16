package waddrmgr

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slugwallet/internal/zero"
	"github.com/taytr-llc/slugwallet/walletdb"
)

// DerivationMode is persisted separately from network/extended-key versions.
// Only the legacy manager schema may omit recovery state.
type DerivationMode uint32

const (
	DerivationLegacy DerivationMode = iota
	DerivationStandard
	maxRecoveryData               = 65536
	maxRecoveryBranchIndex uint32 = 4096
	// RecoveryManagerVersion is exclusive to new retained-recovery wallets.
	// Older binaries reject it; legacy managers remain at schema8.
	RecoveryManagerVersion uint32 = 9
)

var (
	ErrRecoveryUnavailable = errors.New("wallet recovery material unavailable")
	ErrRecoveryState       = errors.New("invalid wallet recovery state")
	ErrRecoveryProtected   = errors.New("retained recovery material prevents this destructive operation")
	ErrRecoveryInventory   = errors.New("wallet contains material outside its recovery profile")
	derivationModeName     = []byte("slug-derivation-mode")
	recoveryVersionName    = []byte("slug-recovery-version")
	recoveryPublicName     = []byte("slug-recovery-public")
	recoveryPrivateName    = []byte("slug-recovery-private")
)

func deriveHDChild(key *hdkeychain.ExtendedKey, index uint32, modes ...DerivationMode) (*hdkeychain.ExtendedKey, error) {
	mode := DerivationLegacy
	if len(modes) > 0 {
		mode = modes[0]
	}
	switch mode {
	case DerivationLegacy:
		return key.DeriveNonStandard(index) // nolint:staticcheck
	case DerivationStandard:
		return key.Derive(index)
	default:
		return nil, ErrRecoveryState
	}
}

func fetchRecoveryState(ns walletdb.ReadBucket) (DerivationMode, bool, error) {
	if ns == nil {
		return 0, false, ErrRecoveryState
	}
	b := ns.NestedReadBucket(mainBucketName)
	if b == nil {
		return 0, false, ErrRecoveryState
	}
	managerVersion, err := fetchManagerVersion(ns)
	if err != nil {
		return 0, false, ErrRecoveryState
	}
	mode, version := b.Get(derivationModeName), b.Get(recoveryVersionName)
	pub, priv := b.Get(recoveryPublicName), b.Get(recoveryPrivateName)
	if managerVersion == latestMgrVersion && mode == nil && version == nil && pub == nil && priv == nil {
		return DerivationLegacy, false, nil
	}
	if managerVersion != RecoveryManagerVersion || len(mode) != 4 || binary.LittleEndian.Uint32(mode) != uint32(DerivationStandard) ||
		len(version) != 4 || binary.LittleEndian.Uint32(version) != 1 ||
		len(pub) <= 40 || len(pub) > maxRecoveryData+40 || len(priv) <= 40 || len(priv) > maxRecoveryData+40 {
		return 0, false, ErrRecoveryState
	}
	return DerivationStandard, true, nil
}

func putRecoveryData(ns walletdb.ReadWriteBucket, pub, priv []byte, pubKey, privKey EncryptorDecryptor) error {
	pubCipher, err := pubKey.Encrypt(pub)
	if err != nil {
		return ErrRecoveryState
	}
	privCipher, err := privKey.Encrypt(priv)
	if err != nil {
		return ErrRecoveryState
	}
	b := ns.NestedReadWriteBucket(mainBucketName)
	for _, item := range []struct{ key, value []byte }{
		{derivationModeName, uint32ToBytes(uint32(DerivationStandard))},
		{recoveryVersionName, uint32ToBytes(1)},
		{recoveryPublicName, pubCipher}, {recoveryPrivateName, privCipher},
	} {
		if err := b.Put(item.key, item.value); err != nil {
			return err
		}
	}
	return putManagerVersion(ns, RecoveryManagerVersion)
}

// CreateWithRecovery creates an explicitly standard-BIP32 manager and retains
// authenticated public/private recovery payloads in the caller's creation
// transaction. Payload ownership remains with the caller, which must zero the
// private plaintext. This does not upgrade an existing manager.
func CreateWithRecovery(ns walletdb.ReadWriteBucket, rootKey *hdkeychain.ExtendedKey,
	pubPassphrase, privPassphrase []byte, params *chaincfg.Params, config *ScryptOptions,
	birthday time.Time, recoveryPublic, recoveryPrivate []byte) error {
	if rootKey == nil || !rootKey.IsPrivate() || len(recoveryPublic) == 0 || len(recoveryPublic) > maxRecoveryData ||
		len(recoveryPrivate) == 0 || len(recoveryPrivate) > maxRecoveryData {
		return ErrRecoveryState
	}
	return createManager(ns, rootKey, pubPassphrase, privPassphrase, params, config, birthday,
		DerivationStandard, recoveryPublic, recoveryPrivate)
}

// DerivationMode reports the immutable mode loaded from this manager's state.
func (m *Manager) DerivationMode() DerivationMode { return m.derivationMode }

// RecoveryEnabled reports whether this manager was explicitly created with
// retained material. It does not promise that the supported inventory is intact.
func (m *Manager) RecoveryEnabled() bool { return m.recoveryEnabled }

// RecoveryData returns an owned decrypted payload. Private reads require an
// unlocked non-watch-only manager; callers must clear the returned plaintext.
func (m *Manager) RecoveryData(ns walletdb.ReadBucket, private bool) ([]byte, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if m.closed {
		return nil, ErrRecoveryUnavailable
	}
	mode, enabled, err := fetchRecoveryState(ns)
	if err != nil {
		return nil, err
	}
	if !enabled || !m.recoveryEnabled {
		return nil, ErrRecoveryUnavailable
	}
	if mode != m.derivationMode {
		return nil, ErrRecoveryState
	}
	keyType, name := CKTPublic, recoveryPublicName
	if private {
		keyType, name = CKTPrivate, recoveryPrivateName
	}
	key, err := m.selectCryptoKey(keyType)
	if err != nil {
		return nil, err
	}
	plain, err := key.Decrypt(ns.NestedReadBucket(mainBucketName).Get(name))
	if err != nil {
		return nil, ErrRecoveryState
	}
	if len(plain) == 0 || len(plain) > maxRecoveryData {
		zero.Bytes(plain)
		return nil, ErrRecoveryState
	}
	return plain, nil
}

// RecoveryRootPublicKey reads the stored root identity without private access.
func (m *Manager) RecoveryRootPublicKey(ns walletdb.ReadBucket) (string, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if m.closed || !m.recoveryEnabled {
		return "", ErrRecoveryUnavailable
	}
	_, encrypted := fetchMasterHDKeys(ns)
	plain, err := m.cryptoKeyPub.Decrypt(encrypted)
	if err != nil {
		return "", ErrRecoveryState
	}
	defer zero.Bytes(plain)
	return string(plain), nil
}

// RecoveryAccount is a database snapshot, not an arbitrary backup descriptor.
type RecoveryAccount struct {
	Scope                      KeyScope
	Schema                     ScopeAddrSchema
	NextExternal, NextInternal uint32
}

// RecoveryAccounts rejects extra scopes/accounts/imported keys/scripts and
// bounds restoration work. Call within a single read or creation transaction.
func RecoveryAccounts(ns walletdb.ReadBucket) ([]RecoveryAccount, error) {
	_, enabled, err := fetchRecoveryState(ns)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, ErrRecoveryUnavailable
	}
	var accounts []RecoveryAccount
	scopeBucket := ns.NestedReadBucket(scopeBucketName)
	if scopeBucket == nil {
		return nil, ErrRecoveryInventory
	}
	err = scopeBucket.ForEach(func(key, value []byte) error {
		if len(key) != 8 || value != nil {
			return ErrRecoveryInventory
		}
		scope := KeyScope{Purpose: binary.LittleEndian.Uint32(key), Coin: binary.LittleEndian.Uint32(key[4:])}
		if len(accounts) >= len(DefaultKeyScopes) {
			return ErrRecoveryInventory
		}
		expected, ok := ScopeAddrMap[scope]
		if !ok || scope.Coin != 0 {
			return ErrRecoveryInventory
		}
		schema, err := fetchScopeAddrSchema(ns, &scope)
		if err != nil || *schema != expected {
			return ErrRecoveryInventory
		}
		foundDefault, foundImported := false, false
		var state RecoveryAccount
		state.Scope, state.Schema = scope, *schema
		scoped, err := fetchReadScopeBucket(ns, &scope)
		if err != nil {
			return ErrRecoveryInventory
		}
		accountBucket := scoped.NestedReadBucket(acctBucketName)
		if accountBucket == nil {
			return ErrRecoveryInventory
		}
		err = accountBucket.ForEach(func(key, value []byte) error {
			if len(key) != 4 || len(value) < 5 || len(value) > maxRecoveryData || accountType(value[0]) != accountDefault {
				return ErrRecoveryInventory
			}
			account := binary.LittleEndian.Uint32(key)
			if account != DefaultAccountNum && account != ImportedAddrAccount {
				return ErrRecoveryInventory
			}
			row, err := fetchAccountInfo(ns, &scope, account)
			if err != nil {
				return ErrRecoveryInventory
			}
			data, ok := row.(*dbDefaultAccountRow)
			if !ok {
				return ErrRecoveryInventory
			}
			if account == ImportedAddrAccount {
				foundImported = true
				if len(data.pubKeyEncrypted) != 0 || len(data.privKeyEncrypted) != 0 || data.nextExternalIndex != 0 || data.nextInternalIndex != 0 {
					return ErrRecoveryInventory
				}
				return nil
			}
			foundDefault = true
			if len(data.pubKeyEncrypted) == 0 || len(data.privKeyEncrypted) == 0 || data.nextExternalIndex > maxRecoveryBranchIndex || data.nextInternalIndex > maxRecoveryBranchIndex {
				return ErrRecoveryInventory
			}
			state.NextExternal, state.NextInternal = data.nextExternalIndex, data.nextInternalIndex
			return nil
		})
		if err != nil || !foundDefault || !foundImported {
			return ErrRecoveryInventory
		}
		addressBucket := scoped.NestedReadBucket(addrBucketName)
		if addressBucket == nil {
			return ErrRecoveryInventory
		}
		var addressCount uint32
		err = addressBucket.ForEach(func(key, value []byte) error {
			addressCount++
			// Only exact fixed-size chain rows belong to this profile. Refuse
			// imports, nested buckets and malformed lengths before any generic
			// decoder can allocate based on disk-controlled data.
			if addressCount > 2*maxRecoveryBranchIndex || len(key) != 32 || len(value) != 26 || addressType(value[0]) != adtChain {
				return ErrRecoveryInventory
			}
			row, err := deserializeAddressRow(value)
			if err != nil {
				return ErrRecoveryInventory
			}
			address, err := deserializeChainedAddress(row)
			if err != nil || address.account != DefaultAccountNum {
				return ErrRecoveryInventory
			}
			switch address.branch {
			case ExternalBranch:
				if address.index >= state.NextExternal {
					return ErrRecoveryInventory
				}
			case InternalBranch:
				if address.index >= state.NextInternal {
					return ErrRecoveryInventory
				}
			default:
				return ErrRecoveryInventory
			}
			return nil
		})
		if err != nil {
			return err
		}
		accounts = append(accounts, state)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(accounts) != len(DefaultKeyScopes) {
		return nil, ErrRecoveryInventory
	}
	return accounts, nil
}
