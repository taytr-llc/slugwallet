//go:build darwin || linux

// Copyright (c) 2026 The SLUG developers. ISC license.
package recoveryvault

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func filePin(t *testing.T, path string) CurrentDestinationPin {
	t.Helper()
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(parent, filepath.Base(path))
	f, _, err := currentWalk(parent, false)
	if err != nil {
		t.Fatal(err)
	}
	st, e := currentStampFile(f)
	ce := f.Close()
	if e != nil || ce != nil {
		t.Fatal("stamp")
	}
	return CurrentDestinationPin{1, path, st.identity.Device, st.identity.Inode}
}
func filePublish(t *testing.T, d *CurrentDestination, ctx context.Context, check func() error) error {
	t.Helper()
	if err := d.claim(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.publish(ctx, []byte("bounded private fixture bytes"), check)
}
func TestHostedCurrentDestinationFaultsAndPinnedParent(t *testing.T) {
	if !currentPlatform() {
		t.Skip("unsupported")
	}
	for _, fault := range []string{"none", "short-write", "file-sync", "exclusive-conflict", "lost-link-ack", "directory-sync", "postcheck", "cleanup"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			pin := filePin(t, filepath.Join(t.TempDir(), "recovery.json"))
			d, err := OpenCurrentDestination(ctx, pin, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			original := d.ops
			switch fault {
			case "short-write":
				d.ops.write = func(f *os.File, b []byte) (int, error) { return original.write(f, b[:1]) }
			case "file-sync":
				d.ops.syncFile = func(*os.File) error { return io.ErrClosedPipe }
			case "exclusive-conflict":
				if os.WriteFile(pin.Path, []byte("keep me"), 0600) != nil {
					t.Fatal("fixture")
				}
			case "lost-link-ack":
				d.ops.link = func(dir *os.File, a, b string) error {
					if e := original.link(dir, a, b); e != nil {
						return e
					}
					return io.ErrClosedPipe
				}
			case "directory-sync":
				d.ops.syncDirectory = func(*os.File) error { return io.ErrClosedPipe }
			case "cleanup":
				d.ops.remove = func(*os.File, string) error { return io.ErrClosedPipe }
			}
			checks := 0
			check := func() error {
				checks++
				if fault == "postcheck" && d.mayPublish {
					return context.Canceled
				}
				return nil
			}
			err = filePublish(t, d, ctx, check)
			if fault == "none" {
				if err != nil {
					t.Fatal(err)
				}
				st, e := os.Stat(pin.Path)
				if e != nil || st.Mode().Perm() != 0600 {
					t.Fatal("private output")
				}
			} else if err == nil {
				t.Fatal("fault accepted")
			}
			uncertain := fault == "lost-link-ack" || fault == "directory-sync" || fault == "postcheck" || fault == "cleanup"
			if errors.Is(err, ErrExportUncertain) != uncertain {
				t.Fatal("uncertainty classification", err)
			}
			if fault == "exclusive-conflict" {
				raw, _ := os.ReadFile(pin.Path)
				if string(raw) != "keep me" || !errors.Is(err, ErrConflict) {
					t.Fatal("overwrote destination")
				}
			}
			if fault == "cleanup" {
				if !errors.Is(d.Close(), ErrCleanup) || !errors.Is(d.Close(), ErrCleanup) {
					t.Fatal("cleanup failure laundered")
				}
			} else {
				names, e := os.ReadDir(filepath.Dir(pin.Path))
				if e != nil {
					t.Fatal(e)
				}
				for _, name := range names {
					if strings.HasPrefix(name.Name(), ".slug-current-") {
						t.Fatal("owned temporary leaked")
					}
				}
			}
		})
	}
	parent := t.TempDir()
	pin := filePin(t, filepath.Join(parent, "selected.json"))
	d, err := OpenCurrentDestination(context.Background(), pin, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if os.Rename(filepath.Dir(pin.Path), filepath.Dir(pin.Path)+"-moved") != nil {
		t.Fatal("rename")
	}
	defer os.Rename(filepath.Dir(pin.Path)+"-moved", filepath.Dir(pin.Path))
	if os.Mkdir(filepath.Dir(pin.Path), 0700) != nil {
		t.Fatal("replace")
	}
	defer os.RemoveAll(filepath.Dir(pin.Path))
	if filePublish(t, d, context.Background(), func() error { return nil }) == nil {
		t.Fatal("parent substitution")
	}
	if _, err = os.Stat(filepath.Join(filepath.Dir(pin.Path)+"-moved", "selected.json")); !os.IsNotExist(err) {
		t.Fatal("substituted route wrote old parent")
	}
}
func TestHostedCurrentDestinationRefusalsAndCloseJoin(t *testing.T) {
	parent := t.TempDir()
	pin := filePin(t, filepath.Join(parent, "chosen"))
	ctx := context.Background()
	if _, err := OpenCurrentDestination(ctx, pin, []string{filepath.Dir(pin.Path)}); err == nil {
		t.Fatal("managed root")
	}
	wrong := pin
	wrong.ParentInode = strings.Repeat("1", 16)
	if _, err := OpenCurrentDestination(ctx, wrong, nil); err == nil {
		t.Fatal("foreign parent")
	}
	if os.Symlink("missing", pin.Path) != nil {
		t.Fatal("symlink fixture")
	}
	if _, err := OpenCurrentDestination(ctx, pin, nil); !errors.Is(err, ErrConflict) {
		t.Fatal("symlink destination", err)
	}
	os.Remove(pin.Path)
	d, err := OpenCurrentDestination(ctx, pin, nil)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	write := d.ops.write
	d.ops.write = func(f *os.File, b []byte) (int, error) { close(entered); <-release; return write(f, b) }
	done := make(chan error, 1)
	go func() { done <- filePublish(t, d, ctx, func() error { return nil }) }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()
	select {
	case <-closed:
		t.Fatal("close abandoned active file")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = <-closed; err != nil {
		t.Fatal(err)
	}
}
