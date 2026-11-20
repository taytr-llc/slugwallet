// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/taytr-llc/slug/btcutil/v2/hdkeychain"
	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slug/wire/v2"
	"github.com/taytr-llc/slugwallet/waddrmgr"
	"github.com/taytr-llc/slugwallet/walletdb"
	"github.com/taytr-llc/slugwallet/wtxmgr"
)

func openPoolSettlementWallet(life context.Context, rootPath string, expected PoolWalletBinding, pubPass, privPass []byte, root *hdkeychain.ExtendedKey, birthday time.Time, create bool) (*PoolWalletOwner, error) {
	if wire.TestPoW {
		return nil, waddrmgr.ErrPoolSettlementProfile
	}
	if life == nil || ValidatePoolWalletBinding(expected) != nil || len(pubPass) > 1024 || !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath {
		return nil, ErrPoolWalletInvalid
	}
	if e := life.Err(); e != nil {
		return nil, e
	}
	if create && (root == nil || !root.IsPrivate() || len(privPass) == 0 || len(privPass) > 1024 || birthday.IsZero()) {
		return nil, ErrPoolWalletInvalid
	}
	pubPass = append([]byte(nil), pubPass...)
	defer clear(pubPass)
	privPass = append([]byte(nil), privPass...)
	defer clear(privPass)
	if e := poolNoSymlinkParents(filepath.Dir(rootPath)); e != nil {
		return nil, e
	}
	if create {
		if e := os.Mkdir(rootPath, 0700); e != nil {
			return nil, ErrPoolWalletStorage
		}
	}
	dir, e := poolPathInfo(rootPath, true)
	if e != nil {
		return nil, e
	}
	dbPath := filepath.Join(rootPath, WalletDBName)
	var file os.FileInfo
	if !create {
		file, e = poolPathInfo(dbPath, false)
		if e != nil {
			return nil, e
		}
	} else {
		if _, e = os.Lstat(dbPath); !os.IsNotExist(e) {
			return nil, ErrPoolWalletStorage
		}
	}
	loader := NewLoader(&chaincfg.MainNetParams, rootPath, false, 5*time.Second, 0)
	ctx, cancel := context.WithCancel(life)
	o := &PoolWalletOwner{life: ctx, cancel: cancel, closed: make(chan struct{}), gate: make(chan struct{}, 1), binding: ownedPoolBinding(expected), loader: loader, rootPath: rootPath, dir: dir, file: file}
	if create {
		loader.db, e = walletdb.Create("bdb", dbPath, false, 5*time.Second, false)
	} else {
		loader.db, e = walletdb.Open("bdb", dbPath, false, 5*time.Second, false)
	}
	if e != nil {
		return poolOwnerFailure(o, ErrPoolWalletStorage)
	}
	o.file, e = poolPathInfo(dbPath, false)
	if e != nil || file != nil && !os.SameFile(file, o.file) {
		return poolOwnerFailure(o, ErrPoolWalletStorage)
	}
	if e = o.checkPaths(); e != nil {
		return poolOwnerFailure(o, e)
	}
	if create {
		e = walletdb.Update(loader.db, func(tx walletdb.ReadWriteTx) error {
			ns, e := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
			if e != nil {
				return ErrPoolWalletStorage
			}
			tm, e := tx.CreateTopLevelBucket(wtxmgrNamespaceKey)
			if e != nil {
				return ErrPoolWalletStorage
			}
			if e = waddrmgr.CreateWithPoolSettlement(ctx, ns, root, pubPass, privPass, &chaincfg.MainNetParams, nil, birthday, expected.Guard); e != nil {
				return e
			}
			if e = wtxmgr.Create(tm); e != nil {
				return ErrPoolWalletStorage
			}
			return ctx.Err()
		})
		if e != nil {
			return poolOwnerFailure(o, e)
		}
	}
	var manager *waddrmgr.Manager
	var store *wtxmgr.Store
	e = walletdb.View(loader.db, func(tx walletdb.ReadTx) error {
		if e := poolOwnerInventory(tx); e != nil {
			return e
		}
		var e error
		manager, e = waddrmgr.OpenPoolSettlement(ctx, tx.ReadBucket(waddrmgrNamespaceKey), pubPass, &chaincfg.MainNetParams, expected.Guard)
		if e != nil {
			return e
		}
		tm := tx.ReadBucket(wtxmgrNamespaceKey)
		if tm == nil {
			return ErrPoolWalletStorage
		}
		store, e = wtxmgr.Open(tm, &chaincfg.MainNetParams)
		if e != nil {
			return ErrPoolWalletStorage
		}
		return ctx.Err()
	})
	if e != nil {
		if manager != nil {
			manager.Close()
		}
		return poolOwnerFailure(o, e)
	}
	w := walletFromManagers(loader.db, append([]byte(nil), pubPass...), &chaincfg.MainNetParams, 0, loader.cfg.walletSyncRetryInterval, manager, store)
	// No callbacks, RPC server, synchronization backend or ordinary loader escape.
	o.wallet = w
	loader.wallet = w
	w.Start()
	if create {
		if e = o.syncPoolDirectory(rootPath); e == nil {
			e = o.syncPoolDirectory(filepath.Dir(rootPath))
		}
		if e != nil {
			return poolOwnerFailure(o, e)
		}
	}
	if e = o.checkPaths(); e != nil {
		return poolOwnerFailure(o, e)
	}
	if e = ctx.Err(); e != nil {
		return poolOwnerFailure(o, e)
	}
	return o, nil
}
func poolNoSymlinkParents(path string) error {
	for {
		info, e := os.Lstat(path)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrPoolWalletStorage
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}
func (o *PoolWalletOwner) syncPoolDirectory(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return ErrPoolWalletStorage
	}
	return o.syncPoolDirectoryFile(f)
}
func (o *PoolWalletOwner) syncPoolDirectoryFile(f *os.File) error {
	e := f.Sync()
	closeErr := f.Close()
	if closeErr != nil {
		// Do not release the custody owner after losing cleanup certainty. The
		// exact failed descriptor is retained; later Close cannot relabel it clean.
		o.failedDirectories = append(o.failedDirectories, f)
		o.closeErr = ErrPoolWalletStorage
	}
	if e != nil || closeErr != nil {
		return ErrPoolWalletStorage
	}
	return nil
}
func (o *PoolWalletOwner) checkPaths() error {
	dir, e := poolPathInfo(o.rootPath, true)
	if e != nil || !os.SameFile(dir, o.dir) {
		return ErrPoolWalletStorage
	}
	file, e := poolPathInfo(filepath.Join(o.rootPath, WalletDBName), false)
	if e != nil || !os.SameFile(file, o.file) {
		return ErrPoolWalletStorage
	}
	return nil
}
