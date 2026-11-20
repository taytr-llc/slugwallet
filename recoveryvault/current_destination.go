// Copyright (c) 2026 The SLUG developers. ISC license.
package recoveryvault

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"
)

type CurrentDestinationPin struct {
	Version      uint32 `json:"version"`
	Path         string `json:"path"`
	ParentDevice string `json:"parent_device"`
	ParentInode  string `json:"parent_inode"`
}
type currentFileIdentity struct{ Device, Inode string }
type currentFileStamp struct {
	identity           currentFileIdentity
	size               int64
	modified           string
	regular, directory bool
}
type currentFileOps struct {
	create        func(*os.File, string) (*os.File, error)
	write         func(*os.File, []byte) (int, error)
	syncFile      func(*os.File) error
	closeFile     func(*os.File) error
	inspect       func(*os.File, string) (currentFileStamp, error)
	link          func(*os.File, string, string) error
	remove        func(*os.File, string) error
	syncDirectory func(*os.File) error
}

func currentDefaultOps() currentFileOps {
	return currentFileOps{currentCreate, func(f *os.File, b []byte) (int, error) { return f.Write(b) }, func(f *os.File) error { return f.Sync() }, func(f *os.File) error { return f.Close() }, currentInspect, currentLink, currentRemove, func(f *os.File) error { return f.Sync() }}
}

type CurrentDestination struct {
	mu           sync.Mutex
	pin          CurrentDestinationPin
	dir          *os.File
	name, temp   string
	ops          currentFileOps
	used, closed bool
	closeErr     error
	claimed      bool
	mayPublish   bool
}

func currentWithin(root, path string) bool {
	r, e := filepath.Rel(root, path)
	return e == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))
}
func validCurrentDestination(p CurrentDestinationPin) bool {
	return p.Version == Version1 && utf8.ValidString(p.Path) && len(p.Path) > 0 && len(p.Path) <= 2048 && filepath.IsAbs(p.Path) && filepath.Clean(p.Path) == p.Path && filepath.Base(p.Path) != "." && filepath.Base(p.Path) != string(filepath.Separator) && len(filepath.Base(p.Path)) <= 255 && !strings.ContainsAny(p.Path, "\x00\r\n\t") && canonicalHex(p.ParentDevice, 8) && canonicalHex(p.ParentInode, 8) && p.ParentInode != "0000000000000000"
}
func currentCheckedParent(path string, protected []string) (*os.File, currentFileStamp, error) {
	if len(protected) > 64 {
		return nil, currentFileStamp{}, ErrExport
	}
	dir, ancestors, err := currentWalk(filepath.Dir(path), true)
	if err != nil {
		return nil, currentFileStamp{}, ErrExport
	}
	fail := func() (*os.File, currentFileStamp, error) {
		if dir.Close() != nil {
			return nil, currentFileStamp{}, ErrCleanup
		}
		return nil, currentFileStamp{}, ErrExport
	}
	for _, root := range protected {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root || len(root) > 2048 || !utf8.ValidString(root) || strings.ContainsAny(root, "\x00\r\n\t") {
			return fail()
		}
		resolved, e := filepath.EvalSymlinks(root)
		if e != nil {
			if !os.IsNotExist(e) {
				return fail()
			}
			resolved = root
		}
		if currentWithin(resolved, path) {
			return fail()
		}
		fd, _, e := currentWalk(resolved, false)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return fail()
		}
		stamp, se := currentStampFile(fd)
		ce := fd.Close()
		if se != nil || ce != nil {
			return fail()
		}
		for _, id := range ancestors {
			if id == stamp.identity {
				return fail()
			}
		}
	}
	stamp, err := currentStampFile(dir)
	if err != nil || !stamp.directory {
		return fail()
	}
	return dir, stamp, nil
}
func OpenCurrentDestination(ctx context.Context, pin CurrentDestinationPin, protectedRoots []string) (*CurrentDestination, error) {
	if !currentPlatform() {
		return nil, ErrUnsupported
	}
	if ctx == nil || !validCurrentDestination(pin) {
		return nil, ErrConfig
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	dir, stamp, err := currentCheckedParent(pin.Path, protectedRoots)
	if err != nil {
		return nil, err
	}
	d := &CurrentDestination{pin: pin, dir: dir, name: filepath.Base(pin.Path), ops: currentDefaultOps()}
	fail := func(e error) (*CurrentDestination, error) { return nil, errors.Join(e, d.Close()) }
	if stamp.identity != (currentFileIdentity{pin.ParentDevice, pin.ParentInode}) {
		return fail(ErrConflict)
	}
	if _, err = currentInspect(dir, d.name); !os.IsNotExist(err) {
		if err == nil {
			return fail(ErrConflict)
		}
		return fail(ErrExport)
	}
	var nonce [24]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return fail(ErrExport)
	}
	d.temp = ".slug-current-recovery-" + hex.EncodeToString(nonce[:])
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	return d, nil
}
func (d *CurrentDestination) parentMatches() error {
	dir, _, err := currentWalk(filepath.Dir(d.pin.Path), true)
	if err != nil {
		return ErrExport
	}
	stamp, se := currentStampFile(dir)
	ce := dir.Close()
	if se != nil || ce != nil || !stamp.directory || stamp.identity != (currentFileIdentity{d.pin.ParentDevice, d.pin.ParentInode}) {
		return ErrExport
	}
	return nil
}
func (d *CurrentDestination) claim() error {
	if d == nil {
		return ErrConfig
	}
	if !d.mu.TryLock() {
		return ErrBusy
	}
	defer d.mu.Unlock()
	if d.closed {
		return ErrClosed
	}
	if d.claimed || d.used {
		return ErrConflict
	}
	if err := d.parentMatches(); err != nil {
		return err
	}
	d.claimed = true
	return nil
}
func (d *CurrentDestination) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return d.closeErr
	}
	d.closed = true
	if d.dir != nil {
		if err := d.dir.Close(); err != nil {
			d.closeErr = errors.Join(d.closeErr, ErrCleanup)
		}
		if d.closeErr == nil {
			d.dir = nil
		}
	}
	return d.closeErr
}

// publish is private. No caller can supply recovery bytes or its own authority.
// The caller already owns this destination's mutex before entering the fence.
func (d *CurrentDestination) publish(ctx context.Context, raw []byte, check func() error) (result error) {
	if d.closed || !d.claimed || d.used || len(raw) < 1 || len(raw) > 65536 {
		return ErrExport
	}
	d.used = true
	if err := d.parentMatches(); err != nil {
		return err
	}
	guard := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if check == nil {
			return ErrConflict
		}
		return check()
	}
	if err := guard(); err != nil {
		return err
	}
	f, err := d.ops.create(d.dir, d.temp)
	if err != nil {
		return ErrExport
	}
	if f == nil {
		return ErrExport
	}
	open, created, possible := true, true, false
	initial, se := currentStampFile(f)
	defer func() {
		if open {
			if d.ops.closeFile(f) != nil {
				result = errors.Join(result, ErrCleanup)
			}
		}
		if created {
			current, e := d.ops.inspect(d.dir, d.temp)
			if e != nil || current.identity != initial.identity || !current.regular {
				result = errors.Join(result, ErrCleanup)
			} else if d.ops.remove(d.dir, d.temp) != nil {
				result = errors.Join(result, ErrCleanup)
			} else if d.ops.syncDirectory(d.dir) != nil {
				result = errors.Join(result, ErrCleanup)
			}
		}
		if result != nil && possible {
			result = errors.Join(ErrExportUncertain, result)
		}
		if errors.Is(result, ErrCleanup) {
			d.closeErr = errors.Join(d.closeErr, result)
		}
	}()
	if se != nil || !initial.regular {
		return ErrExport
	}
	if f.Chmod(0600) != nil {
		return ErrExport
	}
	n, we := d.ops.write(f, raw)
	if we != nil {
		return ErrExport
	}
	if n != len(raw) {
		return io.ErrShortWrite
	}
	if d.ops.syncFile(f) != nil {
		return ErrExport
	}
	prepared, e := currentStampFile(f)
	if e != nil || !prepared.regular || prepared.identity != initial.identity || prepared.size != int64(len(raw)) {
		return ErrExport
	}
	e = d.ops.closeFile(f)
	open = false
	if e != nil {
		return ErrCleanup
	}
	if err = guard(); err != nil {
		return err
	}
	if err = d.parentMatches(); err != nil {
		return err
	}
	current, e := d.ops.inspect(d.dir, d.temp)
	if e != nil || current != prepared {
		return ErrExport
	}
	e = d.ops.link(d.dir, d.temp, d.name)
	if e != nil {
		if os.IsExist(e) {
			return ErrConflict
		}
		possible = true
		d.mayPublish = true
		return ErrExport
	}
	possible = true
	d.mayPublish = true
	published, e := d.ops.inspect(d.dir, d.name)
	if e != nil || published != prepared {
		return ErrExport
	}
	current, e = d.ops.inspect(d.dir, d.temp)
	if e != nil || current.identity != prepared.identity || !current.regular {
		return ErrCleanup
	}
	if d.ops.remove(d.dir, d.temp) != nil {
		return ErrCleanup
	}
	created = false
	if d.ops.syncDirectory(d.dir) != nil {
		return ErrExport
	}
	if err = d.parentMatches(); err != nil {
		return err
	}
	return guard()
}
