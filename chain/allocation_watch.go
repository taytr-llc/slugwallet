// Copyright (c) 2026 The SLUG developers. ISC license.
package chain

// AllocationWatchClient returns this exact retained RPC backend. Readiness-only
// wrappers which embed RPCClient inherit this method, so guarded allocation
// watch registration retains concrete cancellation/shutdown semantics without
// replacing the installed chain owner or accepting a watch-success callback.
func (c *RPCClient) AllocationWatchClient() *RPCClient { return c }
