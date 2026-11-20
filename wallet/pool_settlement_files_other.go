//go:build !darwin && !linux

// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import "os"

func poolPathInfo(string, bool) (os.FileInfo, error) { return nil, ErrPoolWalletStorage }
