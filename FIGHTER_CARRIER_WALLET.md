# Fighter carrier wallets — schemas14/15 and allocation2

Set73 engineering contract, November19,2026. This fixes the purpose-limited
wallet/allocator/journal codecs and state machine for the Phase-A candidate.
FIGHTER_TRANSFER_CARRIER.md governs public carrier bytes. Public ownership and
cutoff authority are separate; these wallet records do not establish ownership.
Independent sizing/references and implementation qualification remain required.
A sizing failure requires an explicit pre-implementation contract correction,
never a silently relaxed parser. Old Set72/schema13 bytes remain unchanged.

## 1. Canonical grammar and digest domains

All objects below are compact UTF-8 JSON with exactly the listed member order, required members, no insignificant whitespace, duplicate/unknown members, trailing values, floats, exponent notation or negative zero. Strings use the canonical Go JSON encoding; new scalar strings are bounded ASCII, so arbitrary Unicode/control/HTML-escape variants are absent. Nested inherited manifests use their existing canonical codec. Arrays are required and non-null; optional objects use explicit JSON `null` only where listed. An omitted member is not null. Parse size/count/string limits precede DTO allocation, then exact re-encoding and semantic checks. A whole state token walk has maximum nesting16,8192 objects and262144 JSON tokens. Arrays are permitted only at their typed paths: records≤128, inputs≤16, invalid_indices≤127, cursor arrays exactly8 and inherited manifest accounts exactly4; there is no free-form JSON payload. Raw hex strings are bounded by their exact byte caps before decoding; all other strings use the field grammar below.

`ID` means64 lowercase hex decoding to32 bytes and not all-zero. `H` is64 lowercase hex and may be all-zero unless its meaning explicitly requires an ID. All public gym keys are66 lowercase hex, canonical compressed valid secp256k1 points. `T` is an integer Unix-millisecond sample1..253402300799999; zero occurs only in an explicitly absent/pre-completion timestamp. Counts/revisions/indices use uint32 unless a narrower bound appears; increment overflow refuses before mutation. Session generation is1..9007199254740991 for hosted authorization and0 for the restored local owner. Booleans must be JSON booleans, not0/1. Monetary values are integer atoms0..2100000000000000 with checked sums; positive values are required except explicit zero outputs/sentinels. JSON transaction IDs/hashes are display order. Binary outpoint keys/tuple ordering are hash wire bytes followed by index LE32; no BIP69 substitution for the carrier.

For these new wallet objects only, `J(D,V,x)=SHA256(ASCII(D)||00||ASCII(V)||00||canonical(x))`; no length prefix. This follows the inherited allocation/wallet-storage convention, not the separately defined public-core statement domain. Raw-file hashes and raw-transaction hashes are plain SHA256. Transaction IDs remain double-SHA256 over their inherited serialization. Domains:

| Object | D | V |
|---|---|---|
| AllocationBinding2 | `SLUG hosted allocation binding` | `v2` |
| AllocationRequest2 | `SLUG hosted allocation request` | `v2` |
| AllocationReservation2 | `SLUG hosted allocation reservation` | `v2` |
| HostedGuard2 | `SLUG hosted allocation wallet guard` | `v2` |
| AllocationLink2 | `SLUG hosted allocation wallet record` | `v2` |
| RestoredGuard | `SLUG restored carrier wallet guard` | `v1` |
| Carrier identity wrapper `{journal_id,pin}` | `SLUG fighter carrier binding` | `v1` |
| CarrierRequest | `SLUG fighter carrier request` | `v1` |
| Input array | `SLUG fighter carrier owned inputs` | `v1` |
| CarrierReview | `SLUG fighter carrier review` | `v1` |
| CarrierPreparation | `SLUG fighter carrier preparation` | `v1` |
| CarrierSignedPackage | `SLUG fighter carrier signed package` | `v1` |

The public TransferID, FundingDigest and gym authorization digest are **only** the fixed binary domains in the carrier chapter. A private RequestID or JSON digest never substitutes for them. Generated identities are preselected before irreversible setup/selection; no constructor adopts expected identity from a marker.

## 2. Manager schemas and exact guard bytes

**Schema14** is fresh hosted allocation2. Manager key `main/hostedallocationguardv2` contains `HostedGuard2`, ordered:

`version, state, inventory_id, authority_id, account_id, wallet_owner_id, source_binding_id, ownership_pin_id, carrier_journal_id, withdrawal_journal_id, initial_manifest_sha256, binding_id`.

Version=2. All identity fields are ID; initial manifest hash is H. State is `locked` with binding_id exactly `""`, or `bound` with the exact AllocationBinding2 digest. No third state, nullable member or reused schema13 key. Locked mode permits only empty allocator local state and unsigned empty carrier/exclusion state; it cannot prepare/sign/disclose any allocation. Binding is one-time, under the independently expected original binding and only while empty. Schema13 and14 keys cannot coexist. The new manager must reject generic old open, allocation, derive, signing and import APIs before mutation/cache use.

`AllocationBinding2`, ordered:

`version, inventory_id, authority_id, account_id, principal_id, provision_id, hosted_vault_id, retention_id, wallet_owner_id, source_binding_id, ownership_pin_id, carrier_journal_id, withdrawal_journal_id, manager_schema, max_allocations, max_bytes, max_plan_attempts, max_branch_index, initial_manifest`.

Version=2; manager_schema=14; bounds exactly1024,4194304,128,4096. All identity fields are ID. Initial manifest is the existing Phase-A version1/profile1 public fixture manifest with default zero issued cursors, unchanged root/gym derivation and mixed49 schema. Only the published zero256/incrementing256 identities are supported. Guard scalars and manifest hash must equal this binding, not just its hash. The eventual carrier and withdrawal journal IDs are retained from the original setup intent; app identity is independently checked before the corresponding wallet owner is opened.

**Schema15** is explicitly activated from a fully completed schema12 file restore. Manager key `main/restoredcarrierguard` contains `RestoredGuard`, ordered:

`version, state, manager_schema, wallet_owner_id, carrier_journal_id, ownership_pin_id, original_manifest_sha256, original_manifest, activation_tip_hash, activation_tip_height, activation_cursors`.

Version=1,state=`ready`,schema=15; IDs as above. Original manifest is exact imported version1 bytes, hash H. Tip hash is nonzero H and height0..2147483647. activation_cursors is exactly8 uint32 values0..4096 in44ext,44int,49ext,49int,84ext,84int,86ext,86int order, copied from the audited ready12 wallet. The immutable original cursor floor must not exceed activation cursors. Original `recoverypub`, encrypted retention, Phase-A progress/invalid-child/scanner records are preserved byte-for-byte by activation; completion and ledger audits remain required on open. No schema14 inventory/account/vault fields are invented for15.

Activation requires an unloaded original Loader with no backend/session owner, exact separately supplied original manifest, complete12 audit and a fresh app-journal setup intent. One DB transaction rechecks that snapshot and writes15 version, this guard and empty carrier/exclusion metadata. Acknowledged activation then opens a new15 manager; an old cached12 manager cannot survive the switch. Commit uncertainty poisons the owner; exact matching15 reopen reconciles it, rather than initializing again. After established READY, missing journal or guard refuses. Backup Verify never invokes activation. All15 live allocation/sync uses window0 and explicitly audited active inventory; original12 behavior remains unchanged.

## 3. Allocation2 registry and wallet-local link

External inventory marker `SLUG-HOSTED-TRANSFER-ALLOCATION.json` is canonical JSON plus one LF (total≤8192 bytes), ordered `application,version,inventory_id,binding`; application=`slug-hosted-transfer-allocation-inventory`,version=2,binding=AllocationBinding2. Directory contains only that marker and its `db` directory. LevelDB keys are exactly `meta` and `allocation/` followed by64-lowerhex AllocationID (75 bytes). No extra namespace is accepted. Marker SHA is over the complete marker file including LF. Mutations use sync batches; poisoned outcomes require audited reopen.

Metadata order is `version,marker_sha256,revision,allocations,clock_high_water_ms,active_allocation_id,cursors`. Version=2; allocations0..1024; revision0..UINT32_MAX; clock0 only if empty; active ID is empty or the single reserved newest row; cursors exactly8 values≤4096. Initial cursors are zero. Each Reserve increments allocations and revision and advances its authoritative cursor ceiling immediately; terminal acknowledgment increments revision, never allocations. Full audit checks row sequence, clock order, exact counts, logical bytes and every cursor transition. Clock rollback refuses. Repeated exact lookup/ack is byte-preserving, with no new timestamp/revision.

`AllocationRequest2`, ordered:

`version,kind,consumer_id,purpose,branch,withdrawal_binding_id,recipient,recipient_script,amount_atoms,fee_rate_atoms_per_kb,fee_ceiling_atoms,min_confirmations,input_purpose,change_purpose,account,tx_version,input_sequence,lock_time,sighash_type,carrier_binding_id,ownership_pin_id,prior_state_id,recipient_gym,funding_digest,escrow_atoms,commit_fee_atoms,spend_fee_atoms,min_change_atoms`.

Version=2; AllocationID=consumer_id for withdrawals/carriers; receive/recipient keep Set72's exact ID rules. Closed kinds:

- `pool_recipient`/`receive`: exact Set72 nonfinancial scalar rules, purpose84/branch0; every new carrier field is empty string or0.
- `withdrawal_change`: exact Set72 withdrawal request/economic rules and purpose84/branch1, including original v1 withdrawal binding; every new carrier field is empty/0. The old v1 draft codec is unchanged.
- `carrier_return`: purpose84/branch1; withdrawal_binding_id,recipient,recipient_script empty; amount_atoms,fee_rate_atoms_per_kb,fee_ceiling_atoms zero. Min confirmations1,input/change purpose84,account0,tx_version1,input_sequence4294967295,lock_time0,sighash_type1. Carrier binding,ownership pin,prior state,recipient gym,funding digest are exact nonempty values from the owned funding preparation. Escrow500000,commit fee10000,spend fee10000,min change1000. The recipient gym is distinct from the pinned sender gym. Unknown kinds or nonzero unused fields refuse.

`AllocationReservation2` order is the Set72 ordered reservation with version2 and Request2:
`version,sequence,allocation_id,binding_id,request,purpose,branch,start_index,end_index,selected_index,invalid_indices,address,script,reserved_at_ms`.

Sequence1..1024; IDs exact. `0≤start<end≤4096`, `end−start≤128`, selected=end−1. Invalid indices are exactly the ascending contiguous prefix `[start,selected)`, maximum127 entries, each independently verified invalid BIP32 children; selected must derive successfully. Address is canonical native84 mainnet,ASCII≤90; script is exact44 lowerhex chars for `0014`+20 bytes and must match the address and path. Purpose/branch equal request; reserved_at_ms=T. No preburning128 children when the first valid index is earlier.

Registry row order: `reservation,reservation_digest,phase,completed_at_ms,wallet_record_digest,preparation_digest`. Phase is `reserved` (time0 and terminal digests empty), `consumed` or `burned` (time≥reserved time). Terminal wallet_record_digest is exact Link2 digest. Preparation digest is empty for receive/recipient and all burns; for consumed withdrawal it is the unchanged v1 withdrawal draft digest, and for consumed carrier the CarrierPreparation digest. No signature is stored in this allocation registry. Precharge the largest terminal row/meta before Reserve. Reserved/burned ranges stay in export ceilings.

Schema14 wallet top bucket is `slug-hosted-allocation-v2`, containing exactly `meta` and `records`. Meta order: `version,guard_sha256,completed_sequence,cursors`, version2. Record keys are decoded32-byte AllocationID. `AllocationLink2` order:

`version,inventory_id,binding_id,sequence,allocation_id,reservation_digest,request_digest,outcome,purpose,branch,start_index,end_index,selected_index,invalid_indices,address,script,cursors_before,cursors_after,consumer_kind,consumer_binding_id,consumer_id,preparation_digest`.

Version2; outcome consumed/burned; first range/path/cursor rules exactly match the reservation and manager. Only the affected cursor may change, from start to end. Consumer kind is exact Request2 kind. Receive/recipient consumer_binding_id and preparation_digest are empty; other binding is its exact withdrawal/carrier binding. ConsumerID always equals request.consumer_id. Consumed financial link requires exact preparation digest; burn requires empty. This single link is the durable invalid-child encoding; do not create a second independently mutable list. Same-DB cursor/address/link/preparation/input reservations commit together. In-memory caches are installed only on commit.

## 4. Carrier identity, wallet storage and shared spend exclusions

`CarrierPin`, ordered:

`version,owner_mode,manager_schema,network,genesis,wallet_profile,root_public_key,gym_public_key,gym_id,wallet_owner_id,ownership_pin_id,account_authority_id,account_id,allocation_binding_id,original_manifest_sha256`.

Version1; network/genesis/profile and root/gym exactly Phase-A. Root public key is the canonical inherited public root string≤128 ASCII bytes. GymID is the inherited exact64 lowerhex. Hosted mode=`hosted`,schema14,account IDs and allocation binding nonempty, original_manifest_sha256 empty. Restored mode=`restored`,schema15,account IDs/allocation binding empty, original_manifest_sha256 exact imported manifest hash. Wallet owner and ownership pin are ID in both. `CarrierBindingID=J(binding,v1,{journal_id,pin})`, with that exact wrapper order. JournalID is the preselected original ID; no scope adopts request fields.

Wallet top bucket `slug-fighter-carrier-v1` contains exactly `meta` and `records`. Meta order: `version,state,journal_id,binding_id,identity_sha256,record_count,active_request_id`; version1; state `unbound` permits only empty binding/hash,count0,empty active ID and no records, or `ready` requires exact binding and SHA256(canonical CarrierPin). Hosted creation may remain unbound until the vault/enrollment binding exists. Establishing ready requires the original setup intent plus an exact complete empty app journal. Restored activation can establish ready atomically because its identity is already fixed. Subsequent opens never repair absence. Record keys are decoded32-byte RequestIDs, count≤128; sequence is contiguous1..count. Exactly one prepared/retained record may match active_request_id; complete/abandoned are terminal and never active. No active record means the field is empty.

Wallet record order: `version,sequence,request_id,binding_id,state,preparation,preparation_digest,signed_package_digest,commit_txid,spend_txid`. State is `prepared`, `retained`, `complete` or `abandoned`. Prepared/abandoned have empty signed package/transaction fields; retained/complete have all exact values from the app signed commit. Preparation is never rewritten after publication. Abandon only from prepared after joined signing and concrete audited app abandonment; historical abandoned rows remain. Retain is idempotent only for the exact package; it does not queue a transaction. Privileged `Complete(ctx,requestID,packageDigest)` is called only while the concrete adapter holds the exact audited app complete-state reconciliation lease. It changes retained→complete and clears the active ID, retaining all exclusions; a crash before this mirror is reconciled on reopen and blocks a new request meanwhile.

Same-wallet top bucket `slug-purpose-exclusions-v1` contains exactly `meta` and `inputs`. Meta order: `version,manager_schema,carrier_journal_id,withdrawal_journal_id,entry_count`; schema14 requires both IDs, schema15 requires empty withdrawal ID. Each binary36-byte outpoint key maps to ordered `version,owner_kind,request_id,binding_id,preparation_digest,state`, with owner_kind `withdrawal` or `carrier`, state prepared/retained, other fields exact. No nullable/empty owner. Schema15 cannot introduce withdrawal entries. Count≤4224 (128 withdrawals×16 plus128 carriers×17). Each value≤512 bytes; total key/value bytes including metadata≤4194304. Audit is bidirectional with wallet records, not merely “every app record has a wallet row.” Extra/dangling/overlapping rows refuse.

New-mode withdrawals and carriers atomically acquire their input rows together with prepared records; their signers admit only their own exact owner/digest. Carrier normal preparation reserves≤16 native84 inputs; retention additionally reserves known commit index0 before broadcast. Recovery preparation reserves only the already known commit index0, not its spent funding inputs. Recovery and normal carrier requests therefore cannot spend the same escrow concurrently. Key matching uses bounded public derivation/known-path metadata; it does not unlock or run KDF per child. Private key access is limited to the final typed reconstruction/signing lease and cleared afterward. No reservation expires automatically. Generic selection/PSBT/signing routes refuse14/15; new owned withdrawal and carrier routes consult this shared index. Existing9/13 selection functions/namespace formats remain unchanged.

## 5. Exact request, preparation and native review

`CarrierRequest`: `version,request_id,kind,ownership_pin_id,prior_state_id,recipient_gym,commit_txid`.

Version1; kind `transfer`, `recover_reveal` or `recover_refund`. Transfer has empty commit_txid. Recovery has exact actual commit TxID; prior state/recipient must be resolved and crosschecked from its locator and independently verified history. Pin/prior/request are ID and recipient is valid/distinct. RequestDigest uses the JSON request domain; TransferID uses only the public binary intent. No user-selected fee, output script, funding path, schema or arbitrary signature hash.

`OwnedInput`: `txid,output_index,atoms,script,branch,index,block_hash,block_height,coinbase` (same meanings as the existing bounded withdrawal input). TxID/block hash H, output index uint32, atoms positive, script exactly44 native P2WPKH hex; branch0/1,index0..4095,block height0..2147483647,coinbase Boolean. Transfer inputs1..16 are distinct and in the carrier's36-wire-byte lexicographic order. Their complete canonical array has InputDetailsDigest. Selection is the inherited descending amount / displayed TxID / numeric output-index tie-break, taking the first sufficient prefix≤16 for total≥511000; only the final transaction/tuple order is wire-outpoint order. Eligibility is≥1 confirmation,100 coinbase maturity, owned native84 and no existing locks/exclusions. No new selection during signing or retry.

`ReturnPath`: `address,script,branch,index`; branch1 for a new transfer, canonical supported address/script, index≤4095. Recovered return must match actual commit output2 within the original export-covered native84 range (branch0 or1 is permitted when verifying an external otherwise valid carrier; our writer always1). It is not a new allocation. Native review shows the exact recorded script/address and both roles.

`NewFunding`: `inputs,total_input_atoms,funding_digest,allocation_id,reservation_digest,return_path,commit_change_atoms`.
Inputs and sum exact; funding digest from public tuple; allocation ID=request ID; reservation digest H. Change=sum−510000≥1000. On schema14 reservation digest identifies AllocationReservation2; on schema15 it is empty because the same wallet transaction advances the guarded internal cursor and records this preparation. The schema15 private owned plan remains bounded128 raw children and records that range in `RestoredAllocation` below.

`RestoredAllocation`: `start_index,end_index,selected_index,invalid_indices,cursors_before,cursors_after`. Same range/hole/8-cursor rules as Link2; only84 internal changes. It is non-null only for a new transfer on15. It is part of the prepared record and commits atomically with the address and exclusions; aborted transactions disclose no address/cache. Schema15 has no standalone external reservation/burn. A committed preparation later abandoned retains its consumed range unchanged; an aborted atomic preparation has no range to release. No absent-row inference resolves an uncertain commit. No external inventory or fake account link is created.

`RecoveryFunding`: `commit_raw,commit_txid,commit_block_hash,commit_height,commit_position,funding_digest,transfer_id,funding_public_key,funding_branch,funding_index,return_path,gym_authorization`.

Actual commit raw is lowercase hex of≤4096 bytes, passes the fixed template and actual ownership replay. Block identity/position is the dated canonical observation used for preparation, not timeless finality. Funding pubkey is exactly the first actual input witness's compressed key, proven by its prevout. Branch/index and return path are matched **only** within the immutable original export's native84 external/internal bounds; no derived lookahead or later allocation rescue. Gym authorization is exactly128 lowerhex chars of the specified low-S r||s and must reconstruct the unique committed P2SH program. Reconstructing an already committed intent is separate from authorizing a new funding tuple. No caller path, copied private draft or old app journal is accepted as authority.

`CarrierReview`, ordered:

`version,request_id,kind,binding_id,ownership_pin_id,prior_state_id,sender_gym,recipient_gym,transfer_id,funding_digest,input_details_digest,input_count,total_input_atoms,return_address,return_script,return_branch,return_index,commit_change_atoms,escrow_atoms,commit_fee_atoms,spend_fee_atoms,total_fee_atoms,returned_atoms,commit_txid`.

Transfer review: commit_txid empty (depends on later gym signature), input count1..16, input details digest exact, sum/change exact, escrow500000, fees10000/10000,total20000,returned490000. Recovery review: actual commit TxID, funding digest/TransferID exact, input_details_digest empty,input_count1,total_input_atoms500000,commit_change_atoms0,escrow500000,commit_fee_atoms0,spend_fee_atoms10000,total_fee_atoms10000,returned490000. The historical commit fee is not charged again. The review kind distinguishes reveal from refund, and display must explain refund does not transfer ownership. Economic fields are fixed, not caller setters. ReviewDigest covers the entire object. A native ReviewID binds this digest plus original process/session/view, independent from durable RequestID.

`CarrierPreparation`: `version,binding_id,request,prepared_at_ms,tip_hash,tip_height,ownership_head_digest,new_funding,restored_allocation,recovery_funding,review,review_digest`.

Version1,T,exact dated tip and independently verified complete ownership head. Transfer requires NewFunding and no RecoveryFunding; schema15 additionally RestoredAllocation, schema14 null. Recovery requires RecoveryFunding and null NewFunding/RestoredAllocation. The review is a deterministic projection; every redundant field must agree. PreparationDigest is J over this full object. It may reference reservation digest, but not wallet link digest, preventing a cycle; the local link references PreparationDigest afterward. Preparing and disclosing a review requires the original capability. New blocks alone do not invalidate review; changed relevant ownership/funding/spend state does.

`CarrierAuthorizationRequest`: `version,binding_id,request_id,review_digest,ownership_pin_id,prior_state_id,sender_gym,recipient_gym,funding_digest`. Version1; all fields must equal the retained preparation/review and the concrete original wallet/vault identity. This is the only new-transfer gym-signing input, never a caller digest. The typed public intent is reconstructed from pin/prior/recipient/funding; sender is checked against the independently verified predecessor. The concrete adapter must retain the original reviewed operation and relevant ownership lease; parsing this DTO alone grants no signing capability. The vault enforces FighterTransfer before opening only its gym envelope and again before signature disclosure. Restored signing uses the fixed retained gym path with no hosted token substitution.

## 6. Exact signed package and app journal

`RawTransaction`: `raw,txid,raw_sha256`; raw lowercase hex, TxID recomputed from exact bytes, SHA256 recomputed. New commit serialization≤4096 bytes (fixed grammar maximum2560), unsigned≤1024 (maximum814); standard authored reveal/refund≤512 (maxima452/400). The public replay accepts its separate≤10000 scriptSig grammar; do not reject public malleated evidence merely because it exceeds this writer bound.

`CarrierSignedPackage`: `version,review_digest,transfer_id,gym_authorization,commit,spend,spend_kind`.

Version1,signature r||s128hex; commit/spend RawTransaction non-null. A new request has a signed commit and reveal; recovery retains the actual public commit and newly signed reveal/refund. spend_kind=`reveal` or `refund` and matches request. Both spend templates return to **the exact commit output2 script**, never a newly selected/replacement address. Validate full transaction grammar, signatures, owned paths and reviewed economics. Transfer Sign returns both signed legs only after native approval, typed gym authorization, bounded owned-input recheck and exact final original capability check. Neither goes to a wallet rebroadcast queue. Recovery dispatch cannot send the retained old commit again as a newly approved leg.

`CarrierAuthorization`: `mode,action_id,review_id,view_id,generation,authorized_at_ms`. Hosted mode original IDs/generation/T from the account/native action; restored mode uses independently fresh local action/review/view IDs and generation0. Neither contains a session token. It is local approval evidence, not public ownership evidence or a fresh authority when parsed. Reopen requires a new authorization for retry.

`CarrierDispatch`: `attempt,authorization,intent_at_ms,result,result_at_ms,error`.
Attempt1..UINT32_MAX; result `pending`,`acknowledged`,`unknown`,`rejected`; pending has time0/error empty. Terminal time≥intent. Error is empty or a closed code `unavailable`,`not_observed`,`rejected`,`cancelled`,`outcome_unknown`; no raw RPC error. Acknowledgement means delivery only. Only latest bounded attempt per leg is retained, with increasing counter/clock; no claim of a complete network-attempt transcript.

`CarrierObservation`: `observed_at_ms,state,expected_txid,observed_txid,node_tip,node_height,block_hash,block_height,transaction_index,confirmations,transfer_id,raw_sha256,error`.
State `unknown`,`not_observed`,`mempool`,`canonical`,`conflict`. Unknown has empty chain/transaction observations and zero numeric observations except its sample time. Not-observed/mempool have exact fresh tip, no block fields; mempool has exact observed raw hash and transaction ID. Canonical/conflict have actual block/position plus exact raw/semantic identity supplied by the original concrete replay/node adapter. Block heights≤2147483647,positions/counts uint32. Canonical confirmations=tip−block+1 only for a block on that observed chain; conflict uses0 rather than fictional depth. `expected_txid` is always the locally retained leg; public spend representation may have a different observed TxID only after validating the same exact semantic spend/commit. No observation alone advances fighter finality. Error empty or `unavailable`,`not_observed`,`conflict`; absence of data never becomes a false empty owner set.

Journal marker file `SLUG-FIGHTER-CARRIER-JOURNAL.json`, canonical+LF≤4096 bytes, order `application,version,journal_id,pin,binding_id`, application=`slug-fighter-carrier-journal`,version1. State file `state.json` is compact canonical JSON **without LF**, ordered `application,version,journal_id,binding_id,clock_high_water_ms,records`. Records array≤128 sorted contiguous sequence, RequestIDs unique. Keys/IDs/binding must match independently expected setup and wallet owner. Directory entries are exactly this marker, `state.json`, `LOCK`, and at most one `.state-<64-lowerhex-nonzero>.tmp`. Files are private regular0600 files under the pinned directory; symlinks, hardlink aliases, unknown entries and oversized state/stage files refuse. The stage contains one bounded canonical next state and has no dispatch authority until its rename/publication succeeds. On reopen, only the visible state is authoritative; an orphan stage is audited for exact identity and discarded by the exclusive writable owner, never adopted as approval. A read-only audit cannot remove it. Descriptor-relative nofollow/alias/exclusive lock rules, staged sync+rename+directory-sync and sticky uncertainty use the existing reviewed walletwithdraw ownership pattern; the old files are not reused.

`CarrierOperation`, ordered:

`version,sequence,request_id,revision,created_at_ms,updated_at_ms,stage,request,request_digest,preparation,preparation_digest,signed_package,signed_package_digest,sign_authorization,commit_dispatch,spend_dispatch,commit_observation,spend_observation`.

Optional objects preparation/signed package/authorization/two dispatches/two observations are explicit null only before available. Stages: `intent`,`prepared`,`signed`,`commit_dispatching`,`commit_observed`,`spend_dispatching`,`complete`,`abandoned`. Intent has null preparation/package/sign authorization/dispatch; Prepared has exact preparation and null package/authorization/dispatch; Signed and later retain all exact signed package/authorization. A recovery request proceeds signed→spend_dispatching with commit_dispatch permanently null. New transfer commit must be observed by exact bytes on the original owned node before spend dispatch (mempool or canonical suffices, separately dated); acknowledgement alone is insufficient. Each dispatch stage is durably published before its network call. `complete` means the exact authorized spend is observed by the owned node or semantically validated canonical replay; it is not fighter checkpoint finality. All signed rows/exclusions remain retained after complete. Abandoned is allowed only from intent/prepared with no signed/uncertain signed commit, joined signer and exact original authorized abandon publication; its immutable request and any preparation remain.

Clock samples and per-record revisions increase monotonically, equal old timestamps allowed only for exact replay. No automatic signed abandonment, old-row eviction, latest-ID lookup, regenerated transaction or replacement token. Conflict observations retain existing obligations and prevent unsupported new actions; they do not overwrite signed bytes. Journal state audit checks every nullable combination, request/preparation/review/package digest, exact transaction validity, chronological counters and wallet correspondence. It never infers absence from a failed write.

## 7. Atomicity, recovery and bounds

New transfer order: app intent→preselect sufficient funding→hosted Reserve (or15 owned bounded plan)→wallet atomic consumed path/preparation/input exclusions→hosted acknowledgment→exact watch→review→native approval→typed gym signing→scratch signed pair→app atomic signed-package publication under original FighterTransfer fence→wallet retained funding+escrow exclusions→dispatch. New14 no-change is not a branch: change≥1000 is mandatory; insufficiency must refuse before Reserve. A lost unconsumed live plan is burned explicitly, then its app intent is abandoned before a new RequestID. Unknown DB commit is audited, not burned speculatively. Consumed exact preparation resumes without selecting/signing again until a fresh review/authorization.

For commit-only recovery, the new15 owner first audits public commit/funding/predecessor and matches both funding and recorded output2 return keys inside the original file's inventory. It never allocates another return path. It reserves that known escrow outpoint with preparation, reviews reveal/refund, signs scratch and publishes the one-spend package before dispatch. No former hosted journal/approval is recreated. Generic original12 Verify has no route to this owner.

The app journal is sole signed dispatch authority. Wallet prepared inputs remain reserved across a crash before wallet retention, so the signed-journal/retain gap cannot free coins. Reopen holds concrete journal and wallet owners, checks both directions and reconciles only exact saved identities/digests; no caller boolean or deserialized callback authorizes retention/abandonment. Account fences contain only final bounded checks/commits with preacquired opaque leases; wallet/node/manager locks, signing, KDF/Argon, joins and bulk encoding occur outside them. Changes to the relevant predecessor, source pin, owned funding or original view refuse publication without changing the prepared identity; an unrelated new replay head/block alone does not invalidate the economic review. Stop/reset joins admitted work; cleanup uncertainty retains poisoned owners and original files.

| Object/resource | Hard candidate bound |
|---|---|
| Allocation binding / marker including LF |8192 bytes |
| Hosted14 guard / restored15 guard |2048 /8192 bytes |
| Allocation2 request / reservation+row / local link |4096 /8192 /8192 bytes |
| External/local allocation registry |1024 rows,4194304 logical key+value bytes each; independent count and byte bounds |
| Allocation sync batch |24576 bytes, including final row, key and metadata; precharge terminal before Reserve |
| Carrier request / review |1024 /4096 bytes |
| Carrier preparation / wallet record |16384 /24576 bytes |
| Wallet carrier state |128 rows,4194304 logical bytes including keys and metadata |
| Shared exclusions |4224 rows,512 bytes/value,4194304 logical bytes including36-byte keys/meta |
| Signed package / app operation |12288 /49152 bytes |
| App state including all JSON framing |8388608 bytes;128 operations; no partial truncation |
| New decoded inputs |16; visited credit rows4096; single previous tx4MiB; aggregate decoded previous bytes16MiB |
| Recovery key match |≤8192 original-export-covered native84 raw attempts,≤128 per step; cancellation between children |
| Action working budget |32MiB non-Argon, accounted across live owned records, incoming decode, selected tx buffers and staging; fail capacity before a simultaneous copy exceeds it |
| Action / concrete RPC call |30s /5s; recovery scan is resumable bounded steps, never a single unbounded unlock/scan |

Byte ceilings are independent admission limits, not a promise all object maxima fit simultaneously. Conservative writer arithmetic:16-input commit is814 stripped+1746 marker/witness bytes=2560; standard reveal452/refund400. Sixteen bounded input objects fit within8192 bytes; an8192-hex-character recovered commit plus bounded identity/path/review fields must stay within the16384 preparation cap.128×49152=6291456 leaves over2MiB for outer journal framing under8MiB.128×24576 plus record keys/meta is under4MiB.4224×(36+512)=2314752 plus metadata is under4MiB. The independent sizing producer must recompute exact maxima from these field grammars before adoption; no product-produced golden or claim of already-run sizing is made here. Change a cap only through a reviewed pre-execution successor.

Qualification must bind independent canonical bytes/digests, exact nullable/stage cases and byte boundaries; actual injected crash/close/reset evidence is separate from modeled vectors. Required controls include14/15 refusal by old constructors, preservation of original12 imports, no recovery return redirection, wire-outpoint vs withdrawal ordering, no signs before review, no commit-only durable pair, mutual exclusions, lost acknowledgment, burn after lost plan, typed hold refusal, fresh actual file-only restored transfer and independent commit-only reveal/refund with all old journals absent. This chapter adds no production custody, provider/MFA, arbitrary transaction signer or checkpoint authority.
