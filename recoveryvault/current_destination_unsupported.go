//go:build !darwin && !linux

// Copyright (c) 2026 The SLUG developers. ISC license.
package recoveryvault

import "os"

func currentPlatform() bool                               { return false }
func currentStampFile(*os.File) (currentFileStamp, error) { return currentFileStamp{}, ErrUnsupported }
func currentInspect(*os.File, string) (currentFileStamp, error) {
	return currentFileStamp{}, ErrUnsupported
}
func currentOpenRead(*os.File, string) (*os.File, error) { return nil, ErrUnsupported }
func currentCreate(*os.File, string) (*os.File, error)   { return nil, ErrUnsupported }
func currentLink(*os.File, string, string) error         { return ErrUnsupported }
func currentRemove(*os.File, string) error               { return ErrUnsupported }
func currentWalk(string, bool) (*os.File, []currentFileIdentity, error) {
	return nil, nil, ErrUnsupported
}
