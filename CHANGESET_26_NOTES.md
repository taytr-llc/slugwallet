# Set 26 — restricted desktop wallet RPC

This wallet slice adds an opt-in immutable method allowlist for the new Go
local wallet pilot. `legacyrpc.Options.AllowedMethods == nil` preserves the
existing daemon's method set. A non-nil empty slice denies every method; a
non-empty slice is copied at server construction and matches exact method names.
The check precedes special shutdown dispatch, wallet handlers and node passthrough
on HTTP and WebSocket routes. WebSocket authentication by JSON command itself
requires `authenticate` in the list; HTTP upgrade authentication remains available.
Restricted HTTP accepts only POST `/`, without query strings or an Origin header.
The existing body and concurrency limits remain in force. The desktop opts out
of WebSockets with its existing zero-client limit.

The server also closes accepted HTTP connections during shutdown and serializes
new request admission against shutdown. This prevents requests accepted before
listener closure from reaching wallet handlers after the owner unloads its DB.
No wallet key, recovery, derivation, spend or consensus behavior changes here.

The paired desktop adapter uses actual authenticated loopback HTTP for address,
balance, transaction and UTXO operations. It exposes no generic RPC to the webview.
Its restricted method list excludes payment, key export/import, unlocking,
generic signing, password changes, node passthrough and shutdown. Gym signing and
retained recovery export use the in-process wallet APIs. The pilot is limited to
the published zero256 fixture and public fixture passwords; no real-wallet or
hosted-login product is enabled.

Validation before publication:

- Focused method allowlist HTTP/WebSocket and transport tests passed under the
  race detector (1.431 s), including immutable input, nil versus empty behavior,
  shutdown denial, unknown-method passthrough denial and authentication.
- The complete RPC suite, including the HTTP/WebSocket late-dispatch shutdown
  regressions (including an accepted partial HTTP body), passed under the race
  detector (final frozen source: 1.402 s).
- All six runtime modules build; legacy RPC vet, gofmt and diff checks pass.
- Desktop adapter and normal-PoW lifecycle evidence live in the paired chain
  change-set report. This wallet change does not claim that those gates have
  already passed.

The wallet workflow intentionally retains reviewed activated chain revision
`11664083bd87d33b7a127d7950cf170561543c3f`: this wallet-only RPC change
needs no newer chain runtime API. The set 26 branch triggers the same complete
six-module, race and normal-PoW gates, now including the legacy RPC race suite.
No workflow success is claimed before observing it.
