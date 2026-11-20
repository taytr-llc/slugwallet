"""Adopted bounded progress arithmetic, separate from stable v1 derivation.

No scanner, database, invalid-child proof or completion authority is modeled.
The frozen Phase-A recovery contract adopts greedy ordered128 packing and
the236-byte progress codec. No scanner, database or readiness is simulated.
Producer execution still requires the independent root-created source lock.
"""
import struct

CURSOR_LIMIT = 4096
LOOKAHEAD = 20
STEP_LIMIT = 128
SCOPES = tuple((purpose, 0, branch) for purpose in (44, 49, 84, 86) for branch in (0, 1))
CURSORS = (0, 1, 4076, 4077, 4095, 4096)


def cursor(value):
    if type(value) is not int or not 0 <= value <= CURSOR_LIMIT:
        raise ValueError("cursor_out_of_range")
    return value


def initial(imported):
    if len(imported) != 8:
        raise ValueError("eight_branches_required")
    return [{"purpose": purpose, "coin": coin, "branch": branch,
             "imported_next": cursor(n), "issued_next": n, "derived_next": 0,
             "target_next": min(n + LOOKAHEAD, CURSOR_LIMIT)}
            for (purpose, coin, branch), n in zip(SCOPES, imported)]


def packed(records):
    # Adopted fixed layout: 3 + 8*7 unsigned little-endian words =236 bytes.
    # ready remains ZERO: deriving addresses cannot assert chain completion.
    words = [1, 0, sum(row["derived_next"] for row in records)]
    for row in records:
        words += [row[k] for k in ("purpose", "coin", "branch", "imported_next",
                                  "issued_next", "derived_next", "target_next")]
    raw = struct.pack("<" + "I" * len(words), *words)
    if len(raw) != 236:
        raise ValueError("progress_layout")
    return raw.hex()


def step(records):
    result = [dict(x) for x in records]
    budget, segments = STEP_LIMIT, []
    for index, row in enumerate(result):
        start = row["derived_next"]
        count = min(budget, row["target_next"] - start)
        if count:
            row["derived_next"] += count
            segments.append({"branch_record": index, "start": start,
                             "end_exclusive": row["derived_next"]})
            budget -= count
        if budget == 0:
            break
    return result, {"raw_attempts": STEP_LIMIT-budget, "segments": segments}


def plan(imported):
    records = initial(imported)
    total = sum(row["target_next"] for row in records)
    steps = (total + STEP_LIMIT - 1) // STEP_LIMIT
    select = {1, 2, 31, 32, 33, steps-1, steps}
    snapshots, runs = [], []
    first = {"records": [dict(x) for x in records], "progress_hex": packed(records)}
    for number in range(1, steps+1):
        records, work = step(records)
        if not 1 <= work["raw_attempts"] <= STEP_LIMIT:
            raise ValueError("step_budget")
        if runs and runs[-1]["raw_attempts"] == work["raw_attempts"]:
            runs[-1]["count"] += 1
        else:
            runs.append({"raw_attempts": work["raw_attempts"], "count": 1})
        if number in select:
            snapshots.append({"step": number, **work,
                              "records": [dict(x) for x in records],
                              "progress_hex": packed(records)})
    if sum(x["derived_next"] for x in records) != total:
        raise ValueError("incomplete_derivation")
    return {"imported": list(imported), "initial": first, "total_raw_attempts": total,
            "step_count": steps, "step_attempt_runs": runs, "selected_steps": snapshots,
            "derivation_complete": True, "wallet_ready": False,
            "final_progress_hex": packed(records)}


def discovered(record, index):
    if type(index) is not int or not 0 <= index < record["derived_next"]:
        raise ValueError("not_derived")
    result = dict(record)
    result["issued_next"] = max(record["issued_next"], index+1)
    result["target_next"] = min(result["issued_next"]+LOOKAHEAD, CURSOR_LIMIT)
    return result


def generate_progress(input_lock_sha256):
    plans = [{"name": "uniform_"+str(n), **plan([n]*8)} for n in CURSORS]
    plans.append({"name": "mixed_boundary_cursors", **plan([0,1,4076,4077,4095,4096,0,1])})
    discovery = []
    for imported, used in [(0,0),(0,19),(1,0),(1,20),(4076,4095),(4077,4095),(4095,4095),(4096,4095)]:
        old = initial([imported]*8)[5]  # native84 internal, original coin0.
        old["derived_next"] = old["target_next"]
        new = discovered(old, used)
        discovery.append({"name": f"imported_{imported}_used_{used}", "used_index": used,
                          "before": old, "after": new,
                          "additional_raw_attempts": new["target_next"]-old["derived_next"],
                          "requires_historical_rescan": new["target_next"]>old["target_next"]})
    invalid = []
    for value in (-1,4097):
        try:
            initial([value]*8)
        except ValueError as error:
            invalid.append({"cursor":value,"model_error":str(error)})
        else:
            raise ValueError("out_of_range_cursor_accepted")
    return {"version":1,"status":"adopted-bounded-progress-model",
            "input_lock_sha256":input_lock_sha256,
            "cursor_limit":CURSOR_LIMIT,"lookahead":LOOKAHEAD,"step_raw_attempt_limit":STEP_LIMIT,
            "packing_policy":"root-approved-greedy128-ordered-scopes-branches",
            "scope_order":[{"purpose":p,"coin":c,"branch":b}for p,c,b in SCOPES],
            "plans":plans,"discoveries":discovery,"invalid_cursors":invalid,
            "limits":["The exact progress policy/codec is bound by contract-review.json and its frozen contract copy.",
                      "Every modeled raw child is valid; no synthetic invalid child is represented as a cryptographic proof.",
                      "Raw attempts count skips in the eventual scanner, but skip-proof vectors need separate reviewed input.",
                      "Completed derivation leaves ready=0 and does not establish a canonical tip or complete history.",
                      "Historical-rescan indication is adopted scheduling arithmetic, not block or wallet verification.",
                      "No profile2 oracle or 65536-index allowance is used."]}
