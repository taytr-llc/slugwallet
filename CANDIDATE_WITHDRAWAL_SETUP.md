# Candidate withdrawal wallet setup addendum

This additive setup contract preserves frozen CANDIDATE_WITHDRAWALS.md and its draft/transaction bytes.

After normal-profile, retained fixture identity, wallet lifetime, and exact binding argument checks, OpenCandidateWithdrawals returns ErrWithdrawalNotFound only when the candidate top-level namespace is absent. An existing namespace with missing/malformed metadata, records, or indexes remains ErrWithdrawalCorrupt; an exact binding mismatch remains fail-closed. Open never creates or repairs storage.

Add `func (s *CandidateWithdrawals) Empty(ctx context.Context) (bool, error)`. It enters the same fail-fast handle/lifetime gate, performs the complete existing profile/binding/record/reservation audit from one wallet DB snapshot, and reports true only if there are zero operation records, no active operation, and empty prepared/retained indexes. On any error it returns false with that error. It never mutates storage.

The concrete app adapter uses Open plus Empty only for the immutable original INIT binding before its own READY marker exists. It must refuse to adopt a populated wallet namespace without READY. Missing established app journal/READY state is not authorization to initialize or reset wallet state. Empty is a structural setup predicate, not authorization, not a general transaction-state replacement, and not exposed through RPC or the webview.
