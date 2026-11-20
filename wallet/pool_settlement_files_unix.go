//go:build darwin || linux

// Copyright (c) 2026 The SLUG developers. ISC license.
package wallet

import (
	"os"
	"syscall"
)

func poolPathInfo(path string, directory bool) (os.FileInfo, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, ErrPoolWalletStorage
	}
	mode := os.FileMode(0600)
	if directory {
		mode = 0700
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || info.Mode().Perm() != mode || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) || (!directory && stat.Nlink != 1) {
		return nil, ErrPoolWalletStorage
	}
	return info, nil
}
