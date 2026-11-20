// Copyright (c) 2026 The SLUG developers. ISC license.
package recoveryvault

import (
	"context"
	"sync"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/taytr-llc/slug/gymaccount"
	"github.com/taytr-llc/slugwallet/recovery"
	"github.com/taytr-llc/slugwallet/wallet"
)

const (
	MaxCurrentActions               = 128
	MaxCurrentManifestBytes         = 4096
	MaxCurrentCheckpointBytes       = 8192
	MaxCurrentStateBytes            = 2097152
	maxCurrentCommitBytes           = 12288
	maxCurrentTimeMS          int64 = 253402300799999
	currentMarkerFile               = "SLUG-CURRENT-RECOVERY.json"
	currentApplication              = "slug-hosted-current-recovery"
)

type CurrentBinding struct {
	Version         uint32  `json:"version"`
	HostedVaultID   string  `json:"hosted_vault_id"`
	VaultBinding    Binding `json:"vault_binding"`
	RetentionID     string  `json:"retention_id"`
	WalletOwnerID   string  `json:"wallet_owner_id"`
	SourceBindingID string  `json:"source_binding_id"`
}
type CurrentCheckpoint struct {
	Version          uint32            `json:"version"`
	Binding          CurrentBinding    `json:"binding"`
	Revision         uint32            `json:"revision"`
	CaptureID        string            `json:"capture_id"`
	ExpectedRevision uint32            `json:"expected_revision"`
	CapturedAtMS     int64             `json:"captured_at_ms"`
	CommittedAtMS    int64             `json:"committed_at_ms"`
	Manifest         recovery.Manifest `json:"manifest"`
	ManifestSHA256   string            `json:"manifest_sha256"`
}
type currentMarker struct {
	Application string           `json:"application"`
	Version     uint32           `json:"version"`
	Bindings    []CurrentBinding `json:"bindings"`
}
type currentPointer struct {
	AccountID string `json:"account_id"`
	Revision  uint32 `json:"revision"`
	CaptureID string `json:"capture_id"`
}
type currentMetadata struct {
	Version          uint32           `json:"version"`
	MarkerSHA256     string           `json:"marker_sha256"`
	Actions          uint32           `json:"actions"`
	ClockHighWaterMS int64            `json:"clock_high_water_ms"`
	Current          []currentPointer `json:"current"`
}

type currentLife struct {
	mu       sync.Mutex
	life     context.Context
	cancel   context.CancelFunc
	closing  bool
	active   sync.WaitGroup
	gate     chan struct{}
	closed   chan struct{}
	closeErr error
}

func newCurrentLife() currentLife {
	ctx, cancel := context.WithCancel(context.Background())
	return currentLife{life: ctx, cancel: cancel, gate: make(chan struct{}, 1), closed: make(chan struct{})}
}
func (l *currentLife) acquire(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, ErrConfig
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	l.mu.Lock()
	if l.closing {
		l.mu.Unlock()
		return nil, nil, ErrClosed
	}
	l.active.Add(1)
	l.mu.Unlock()
	child, cancel := context.WithTimeout(ctx, 30*time.Second)
	stop := context.AfterFunc(l.life, cancel)
	done := func() { stop(); cancel(); l.active.Done() }
	select {
	case l.gate <- struct{}{}:
	default:
		done()
		return nil, nil, ErrBusy
	}
	if err := child.Err(); err != nil {
		<-l.gate
		done()
		return nil, nil, err
	}
	return child, func() { <-l.gate; done() }, nil
}
func (l *currentLife) startClose() (bool, error) {
	l.mu.Lock()
	if l.closing {
		done := l.closed
		l.mu.Unlock()
		<-done
		return false, l.closeErr
	}
	l.closing = true
	l.cancel()
	l.mu.Unlock()
	return true, nil
}
func (l *currentLife) finishClose(err error) error {
	l.mu.Lock()
	l.closeErr = err
	close(l.closed)
	l.mu.Unlock()
	return err
}

type CurrentStore struct {
	owner      currentLife
	vault      *HostedVault
	path       string
	marker     currentMarker
	originals  []recovery.Manifest
	db         *leveldb.DB
	meta       currentMetadata
	actions    map[string]CurrentCheckpoint
	bytes      int
	poisoned   bool
	writeBatch func(*leveldb.Batch, *opt.WriteOptions) error
	now        func() time.Time
	sourcesMu  sync.Mutex
	sources    map[*CurrentSource]bool
}
type CurrentSource struct {
	owner     currentLife
	store     *CurrentStore
	token     string
	binding   CurrentBinding
	account   gymaccount.Account
	installed *wallet.Wallet
	epoch     EpochFence
	index     int
	capture   *wallet.CurrentRecoveryCapture
	committed map[string]*wallet.CurrentRecoveryCapture // at most 128 exact pointer identities
	exported  *PreparedCurrentExport                    // accessed with owner gate; Close after joining
}

func cloneCheckpoint(c CurrentCheckpoint) CurrentCheckpoint {
	c.Manifest = cloneManifest(c.Manifest)
	return c
}
