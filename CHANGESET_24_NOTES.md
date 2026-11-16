# Change set 24: retained fixture recovery and wallet gym signing

This change implements the approved 24-word English BIP39 phrase, with no extra
BIP39 passphrase, plus SLUG recovery metadata. It remains a disposable public
fixture profile. The existing full-node wallet foundation and upstream source
pin are unchanged. No hosted account, real wallet, production prospect target,
wallet RPC secret endpoint, public service, or Railway wallet deployment is added.

## Creation, storage and derivation

`Loader.CreateNewRecoveryWallet(pubPass, privPass, entropy, birthday)` creates the
explicit profile. `Wallet.ExportRecovery(ctx)` returns a caller-owned
`recovery.Export` after unlock; `Loader.RestoreRecoveryWallet(pubPass, privPass,
export)` creates a new empty wallet and restores advertised address cursors before
commit. Original entropy is encrypted by the existing private crypto key in the
same transaction as wallet creation, together with a digest of the authenticated
public manifest. Creation callback failure rolls the entire initialization back
and releases the local database handle. Failed creation does not remove a file or
silently retry over existing data.

Address-manager schema 9 is reserved for recovery-enabled wallets. New binaries
require the explicit derivation marker and both encrypted payloads under9.
Removing all retention fields therefore fails, rather than selecting legacy
paths. Old binaries reject the higher mandatory schema. Legacy wallets remain
schema 8; their migration list and historical nonstandard BIP32 derivation are
unchanged. All derivation sites select the persisted mode. An independent
leading-zero hardened-account vector distinguishes standard and legacy results.

The supported inventory is account 0 in scopes 44/49/84/86, coin type 0, including the
existing mixed scope 49 address schema. A consistent committed database snapshot
supplies both branch cursors; private export/signing does not wait for
`newAddrMtx` or perform remote work. Every advertised cursor is at most 4096.
Issuance and extension refuse the next unsupported index, including invalid-child
skips. Restore validates an owned copy of the four account descriptors and checks
exact final cursors. Extra accounts, imported keys/scripts, extra scopes and
malformed rows fail export instead of producing a partial backup. The narrow
account-row and outer-address length decoders now check disk lengths before
allocation/slicing. Recovery inventory requires exact scope schemas, existing
buckets, bounded default-account rows and fixed-size chain-address records
before decoding; missing namespaces and malformed imported/script rows fail.

Private-passphrase rotation retains the material under the existing encryption
hierarchy. Locked, wrong-password, legacy, watch-only, malformed or mismatched
states return no recovery material. Neutering the master private key and
converting a retained-recovery wallet to watch-only are explicitly refused,
because keeping entropy would contradict the erasure operation. No secure disk
page erasure or guaranteed Go-string zeroization is claimed.

## Identity, signing and boundaries

The fixed fixture gym path is m/1397511495'/1'/0'. Public identity is available
while locked. The context-aware private lease holds unlock only for bounded
local key derivation and exact admission signing, then releases it before the
worker performs network/Argon work. The pinned worker callback checks enrollment
identity; signing accepts no arbitrary path, raw message or private-key output.
The authority continues to enforce work, freshness, D68 birth and D69 eligibility.

The versioned export includes chain/profile, standard BIP32, account schemas and
current branch high-water indexes, genesis scan start, root public key and gym
identity. A phrase and its current manifest are the recovery unit. An older
export cannot describe addresses issued afterward beyond normal discovery gaps.
Restoration reconstructs keys/history through chain rescan; it does not delete
or revoke the old wallet, transfer a fighter, export registry receipts or confer
exclusive ownership.

## Verification

The independent Python oracle uses official BIP39 word/vector sources and
separate BIP32/secp256k1/address derivation. Fixtures include the official
leading-zero hardened-account case. No implementation output was copied into
cryptographic expectations. Only published deterministic test material is used.

Local verification:

- Recovery manager normal tests: 0.847 s: mandatory version/old-binary rejection,
  missing/corrupt fields and lengths, encrypted payload access, erasure refusal,
  imported-script/account rejection and branch capacity.
- Wallet recovery normal tests: 27.379 s: independent standard address and legacy
  divergence, atomic failure, later reopen/export, password rotation, fresh
  restore/cursor continuation, corrupted retention refusal, missing-all-fields
  reopen refusal and foreign/cheap profile refusal before wallet I/O.
- Recovery and gym wallet race tests pass in 254.097 s. Address-manager recovery
  race tests pass in 2.231 s after the final malformed watch-only length guards.
  The separate watch-only/cancelled export race test passes in 9.817 s. Additional
  private-operation/signing race coverage additionally passes in 76.553 s.
- Tagged recovery codec and wallet profile guards pass in 0.298 s/4.753 s. Independent recovery,
  network-encoding and foundation address oracles pass.
- The normal production-PoW retained recovery gate passes in 72.94 s (package
  73.354 s): all four independent scope/high-water vectors; legacy receive index 25
  funding and maturity; a confirmed RPC spend; close/reopen and retained export;
  fresh restoration from that file alone; exact balances, signed history and
  gym identity; identical/fresh gym authorization and schema 4 admission/replay;
  a second confirmed 10.5 SLUG spend that must consume first-spend change.
  The original database is closed and renamed before fresh restore. No live
  chain, real wallet or operator key is accessed. Evidence is retained beside
  the checkouts in set24-wallet-recovery-smoke.log and its companion report.
- All six runtime module builds, complete normal tests and vet pass. Root
  module normal suite wall time 110.919 s; wallet 109.211 s, address manager 4.544 s and
  recovery codec 1.829 s. Nested transaction-author/rules/sizes, walletdb and
  transaction-manager suites pass. Gofmt and diff checks are clean. Local
  aggregate evidence is set24-wallet-local-checks.json beside the checkouts.
  This broad suite preceded the final corruption-only scope/address guards.
  After those guards, full address-manager normal/race tests pass in 2.823 s/6.633 s;
  focused wallet creation/export/reopen/restore/signing tests pass in 20.610 s,
  and wallet/address-manager vet plus root-module build pass. Independent final
  review confirms the reported corruption paths are closed.
- CI now watches the recovery branch, checks every independent oracle and the
  cheap-profile refusal, and runs both foundation and retained-material
  production-PoW gates. Remote CI has not yet run on a committed set 24 revision.

The normal chain currently rejects witness transactions because the inherited
witness deployments are inactive. Address derivation support alone does not mean
spending that address type is enabled. This change does not alter consensus;
normal-PoW recovery spending evidence must use an active script type and retain
explicit independent vectors for the other supported scopes.

## Remaining product work

D48 normal hosted login, provider/custody and account authorization, secure UI
reveal/export, real issuance/derivation decisions and fighter transfer remain.
The new APIs are library-only and cannot be used to justify real custody or
universal external-wallet compatibility. Deployment of any real custody surface
requires its own concrete design and approval.
