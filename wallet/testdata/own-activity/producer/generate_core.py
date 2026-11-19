#!/usr/bin/env python3
"""SOURCE ONLY: independent Set70 core vectors, execute only after root lock.

The public input lock predates this source. Outputs derive from Python framing,
integer arithmetic and an explicit legacy-bucket model, never new Go output.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct

from transaction_model import (MONEY, Refusal, compact, fields, output_address,
                               parse_transaction, project_record, require, serialize)
from storage_model import Store, be32, be64, capture, display

LOCK = "177734937ccfeaf12c6618fbd15d757b86a9a85731b06460b9a8d3e1269c2ee0"
CONTRACT = "71bff8b11210aab89e324fc96d296a41e3a0248c5ae6e2293face8e51de51138"
HERE = Path(__file__).resolve().parent
STAMP = 1795121237000


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(label):
    return hashlib.sha256(label.encode()).digest()


def load_inputs(root):
    raw = (root / "input-lock.json").read_bytes()
    require(sha(raw) == LOCK)
    lock = json.loads(raw)
    for row in lock["files"]:
        value = (root / row["path"]).read_bytes()
        require(len(value) == row["bytes"] and sha(value) == row["sha256"])
    require(sha((root / "contract/WALLET_ACTIVITY.md").read_bytes()) == CONTRACT)
    return lambda name: json.loads((root / name).read_bytes())


def tx_record(raw, credits, debits, block=None, recorded=STAMP):
    tx = parse_transaction(raw)
    return {"txid": tx["txid"], "raw_hex": raw.hex(), "recorded_at_ms": recorded,
            "block": block, "credits": credits, "debits": debits}


def simple(name, output_values, script, owned, debit_values, input_count=1,
           coinbase=False, witness=None):
    inputs = [{"previous_hash": digest(name+"/"+str(i)), "previous_index": i,
               "script": b"", "sequence": 0xffffffff,
               "witness": [] if witness is None else copy.deepcopy(witness[i])}
              for i in range(input_count)]
    if coinbase:
        inputs = [{"previous_hash": bytes(32), "previous_index": 0xffffffff,
                   "script": b"\x01\x01", "sequence": 0xffffffff, "witness": []}]
    tx = {"version": 2, "inputs": inputs,
          "outputs": [{"atoms": amount, "script": script} for amount in output_values],
          "has_witness": witness is not None, "lock_time": 0}
    raw = serialize(tx)
    credits = [{"index": i, "atoms": output_values[i], "change": change}
               for i, change in sorted(owned)]
    debits = [{"index": i, "atoms": amount} for i, amount in enumerate(debit_values)]
    return tx_record(raw, credits, debits)


def make_transactions(read):
    prior = read("independent/wallet-withdrawal-v1.json")
    prior_by_name = {c["name"]: c for c in prior["cases"]}
    actual = read("public/set68-result.json")
    require(actual["height"] == 110)
    actual_by_fixture = {c["fixture"]: c for c in actual["results"]}
    positives = []

    def add(name, origin, record, height=110):
        expected = project_record(record, height)
        positives.append({"name": name, "origin": origin, "capture_height": height,
                          "record": record, "expected": expected})

    # Recheck inherited independent addresses rather than trusting a new Go
    # address encoder. Input+change/recipient fields are old immutable inputs.
    for case in prior["cases"]:
        draft = case["draft"]
        require(output_address(bytes.fromhex(draft["recipient_script"])) == draft["recipient"])
        require(output_address(bytes.fromhex(draft["change"]["script"])) == draft["change"]["address"])
        raw = bytes.fromhex(case["expected_signed"]["raw_hex"])
        tx = parse_transaction(raw)
        require(tx["txid"] == case["expected_signed"]["txid"])
        credits = []
        change = draft["change"]
        for i, row in enumerate(tx["outputs"]):
            if row["script"].hex() == change["script"]:
                credits.append({"index": i, "atoms": row["atoms"], "change": True})
        debits = [{"index": i, "atoms": row["atoms"]} for i, row in enumerate(draft["inputs"])]
        record = tx_record(raw, credits, debits)
        add("prior/"+case["name"], "previous independent raw fixture; supplied local metadata is modeled", record)
        require(positives[-1]["expected"]["item"]["fee_atoms"] == draft["fee_atoms"])

    for fixture in ("zero256", "incrementing256"):
        author = actual_by_fixture[fixture]
        draft = author["operation"]["draft"]
        old = prior_by_name[fixture+"-original-to-84"]
        live = read("public/legacy-live-"+fixture+".json")
        confirmed = read("public/legacy-confirmed-"+fixture+".json")
        original = read("public/legacy-original-"+fixture+".json")
        raw = bytes.fromhex(confirmed["hex"])
        require(raw.hex() == old["expected_signed"]["raw_hex"] == live["hex"])
        require(author["expected_fee_atoms"] == 141 == old["draft"]["fee_atoms"])
        require(confirmed["txid"] == old["expected_signed"]["txid"])
        block = {"height": 110, "hash": actual["block"], "time_ms": confirmed["blocktime"]*1000}
        credits = [{"index": draft["change"]["output_index"], "atoms": draft["change"]["atoms"], "change": True}]
        debits = [{"index": i, "atoms": row["atoms"]} for i, row in enumerate(draft["inputs"])]
        add("actual/"+fixture+"/own-confirmed", "actual author wallet raw/time/block and locked integer prevouts/change",
            tx_record(raw, credits, debits, block, confirmed["timereceived"]*1000))
        add("actual/"+fixture+"/own-unconfirmed", "actual author wallet old unconfirmed raw/time; no mempool proof",
            tx_record(raw, credits, debits, None, live["timereceived"]*1000), 109)
        prev = draft["inputs"][0]
        require(original["txid"] == prev["txid"])
        pool_block = {"height": prev["block_height"], "hash": prev["block_hash"], "time_ms": original["blocktime"]*1000}
        add("actual/"+fixture+"/pool-payout", "actual old recipient raw/time; owned amount from locked original payout prevout",
            tx_record(bytes.fromhex(original["hex"]), [{"index": prev["output_index"], "atoms": prev["atoms"], "change": False}], [], pool_block, original["timereceived"]*1000))
        other = "incrementing256" if fixture == "zero256" else "zero256"
        other_legacy = read("public/legacy-confirmed-"+other+".json")
        other_draft = actual_by_fixture[other]["operation"]["draft"]
        require(other_draft["recipient_script"] == prev["script"])
        other_block = {"height": 110, "hash": actual["block"], "time_ms": other_legacy["blocktime"]*1000}
        add("actual-raw/"+fixture+"/incoming", "actual reciprocal raw/recipient; first-seen time explicitly modeled as zero",
            tx_record(bytes.fromhex(other_legacy["hex"]), [{"index": other_draft["recipient_output_index"], "atoms": 100000000, "change": False}], [], other_block, 0))

    script = bytes.fromhex(prior_by_name["zero256-original-to-84"]["draft"]["recipient_script"])
    modeled = [
        ("self-payment", simple("self", [100000000, 99999900], script, [(0,False),(1,True)], [200000000])),
        ("partial-inputs", simple("partial", [300000000], script, [(0,False)], [200000000], 2)),
        ("known-zero-fee", simple("zero-fee", [100000000], script, [(0,False)], [100000000])),
        ("coinbase", simple("coinbase", [1000000000], script, [(0,False)], [], coinbase=True)),
        ("zero-credit", simple("zero-credit", [0], script, [(0,False)], [])),
        ("empty-witness-element", simple("empty-element", [100], script, [(0,False)], [], witness=[[b""]])),
        ("mixed-empty-witness-stacks", simple("mixed-stacks", [100], script, [(0,False)], [], 2, witness=[[b""],[]])),
        ("maximum-witness-items", simple("maximum-witness", [100], script, [(0,False)], [], 32, witness=[[b""]*128 for _ in range(32)])),
        ("maximum-counts", simple("max-counts", [1]*256, script, [(0,False)], [100], 256)),
    ]
    unknown = simple("unknown-script", [100,0], script, [(0,False)], [])
    parsed = parse_transaction(bytes.fromhex(unknown["raw_hex"]))
    parsed["outputs"][1]["script"] = b"\x6a\x01x"
    unknown = tx_record(serialize(parsed), unknown["credits"], unknown["debits"])
    modeled.append(("unknown-output-address", unknown))
    public_key=bytes.fromhex(prior_by_name["zero256-original-to-84"]["signature_evidence"][0]["public_key"])
    for name,nonaddress_script in [("bare-pubkey",bytes([len(public_key)])+public_key+b"\xac"),
                                   ("one-of-one-multisig",b"\x51"+bytes([len(public_key)])+public_key+b"\x51\xae")]:
        value=simple(name,[100],script,[(0,False)],[])
        tx=parse_transaction(bytes.fromhex(value["raw_hex"]))
        tx["outputs"][0]["script"]=nonaddress_script
        value=tx_record(serialize(tx),value["credits"],value["debits"])
        modeled.append((name,value))
    for name, record in modeled:
        add("modeled/"+name, "modeled local consistency/grammar case; no valid spend or chain claim", record)

    base = next(x["record"] for x in positives if x["name"] == "actual/zero256/own-confirmed")
    negatives = []

    def negative(name, change, record=None, height=110, layer="record-semantics"):
        value = copy.deepcopy(base if record is None else record)
        change(value)
        try:
            project_record(value, height)
        except Refusal as e:
            negatives.append({"name": name, "record": value, "capture_height": height,
                              "expected": "reject", "category": e.category,"layer":layer})
        else:
            raise AssertionError("negative accepted: "+name)

    negative("wrong-txid", lambda r:r.update(txid="0"*64))
    negative("uppercase-raw", lambda r:r.update(raw_hex=r["raw_hex"].upper()),layer="fixture-parser-only")
    negative("trailing-raw", lambda r:r.update(raw_hex=r["raw_hex"]+"00"))
    negative("no-owned-facts", lambda r:r.update(credits=[],debits=[]))
    negative("credit-amount", lambda r:r["credits"][0].update(atoms=1))
    negative("duplicate-credit", lambda r:r["credits"].append(copy.deepcopy(r["credits"][0])))
    negative("credit-index", lambda r:r["credits"][0].update(index=256))
    negative("duplicate-debit", lambda r:r["debits"].append(copy.deepcopy(r["debits"][0])))
    negative("debit-index", lambda r:r["debits"][0].update(index=256))
    negative("negative-debit", lambda r:r["debits"][0].update(atoms=-1))
    negative("debit-money-bound", lambda r:r["debits"][0].update(atoms=MONEY+1))
    overflow=simple("debit-accumulation",[100],script,[(0,False)],[50,50],2)
    negative("debit-checked-accumulation",lambda r:r.update(debits=[{"index":0,"atoms":MONEY},{"index":1,"atoms":1}]),overflow)
    negative("known-negative-fee", lambda r:r["debits"][0].update(atoms=0))
    negative("block-beyond-tip", lambda r:r["block"].update(height=111))
    negative("negative-time", lambda r:r.update(recorded_at_ms=-1))
    negative("extra-field", lambda r:r.update(extraneous=True),layer="fixture-parser-only")
    negative("wrong-change-type", lambda r:r["credits"][0].update(change=1),layer="fixture-parser-only")
    coinbase = dict(modeled)["coinbase"]
    negative("coinbase-debit", lambda r:r.update(debits=[{"index":0,"atoms":1}]), coinbase)
    return positives, negatives, script, base


def raw_controls(script):
    base = simple("raw-base", [100], script, [(0,False)], [])
    raw = bytes.fromhex(base["raw_hex"])
    parsed = parse_transaction(raw)
    controls = []

    def add(name, value):
        try:
            parse_transaction(value)
        except Refusal as e:
            controls.append({"name":name,"raw_hex":value.hex(),"expected":"reject","category":e.category})
        else:
            raise AssertionError("raw negative accepted: "+name)

    add("nonminimal-input-count", raw[:4]+b"\xfd\x01\x00"+raw[5:])
    add("input-count-257", raw[:4]+compact(257))
    inputs_end = 4+1+32+4+1+4
    add("zero-output-count", raw[:inputs_end]+b"\x00"+b"\0"*4)
    add("output-count-257", raw[:inputs_end]+compact(257))
    add("unknown-witness-flag", raw[:4]+b"\x00\x02"+raw[4:])
    tx=copy.deepcopy(parsed);tx["has_witness"]=True
    add("empty-all-stacks", serialize(tx))
    tx["inputs"][0]["witness"]=[b""]*129
    add("witness-items-per-input", serialize(tx))
    tx=copy.deepcopy(parsed);tx["has_witness"]=True
    tx["inputs"]=[]
    for i in range(33):
        tx["inputs"].append({"previous_hash":digest("witness/"+str(i)),"previous_index":i,
                             "script":b"","sequence":0xffffffff,
                             "witness":[b""]*(128 if i<32 else 1)})
    add("witness-items-total",serialize(tx))
    tx=copy.deepcopy(parsed);tx["inputs"][0]["script"]=b"x"*10241
    add("signature-script-capacity",serialize(tx))
    tx=copy.deepcopy(parsed);tx["outputs"][0]["script"]=b"x"*10241
    add("output-script-capacity",serialize(tx))
    add("raw-byte-capacity",b"\0"*262145)
    tx=copy.deepcopy(parsed);tx["inputs"].append(copy.deepcopy(tx["inputs"][0]))
    add("duplicate-previous-outpoint",serialize(tx))
    tx=copy.deepcopy(parsed);other=copy.deepcopy(tx["inputs"][0])
    other["previous_hash"],other["previous_index"]=bytes(32),0xffffffff
    tx["inputs"].append(other)
    add("mixed-coinbase-prevout",serialize(tx))
    tx=copy.deepcopy(parsed);tx["outputs"][0]["atoms"]=-1
    add("negative-output",serialize(tx))
    tx=copy.deepcopy(parsed);tx["outputs"]=[{"atoms":MONEY,"script":script},{"atoms":1,"script":script}]
    add("output-total-money",serialize(tx))
    add("truncated-compactsize",raw[:4]+b"\xfd")
    tx=copy.deepcopy(parsed);tx["has_witness"]=True;tx["inputs"][0]["witness"]=[b"ab"]
    add("truncated-witness",serialize(tx)[:-5])
    add("declared-witness-item-capacity",raw[:4]+b"\0\1"+raw[4:-4]+compact(1)+compact(262145)+raw[-4:])
    return controls


def empty_store():
    return {name:{} for name in ("m","t","b","c","d","u","mc","mi")}


def put(store,bucket,key,value):
    store[bucket][key.hex()]=value.hex()


def add_block(store,height,block_hash,hashes):
    put(store,"b",be32(height),block_hash+be64(STAMP//1000)+be32(len(hashes))+b"".join(hashes))


def add_record(store,record):
    tx=parse_transaction(bytes.fromhex(record["raw_hex"]))
    h=bytes.fromhex(record["txid"])[::-1]
    block=record["block"]
    if block is None:
        prefix,bucket=h,"m"
    else:
        bh=bytes.fromhex(block["hash"])[::-1]
        prefix,bucket=h+be32(block["height"])+bh,"t"
        key=be32(block["height"]).hex()
        existing=bytes.fromhex(store["b"][key]) if key in store["b"] else None
        hashes=[] if existing is None else [existing[i:i+32] for i in range(44,len(existing),32)]
        require(existing is None or existing[:32]==bh)
        hashes.append(h)
        add_block(store,block["height"],bh,hashes)
    put(store,bucket,prefix,be64(record["recorded_at_ms"]//1000)+bytes.fromhex(record["raw_hex"]))
    for credit in record["credits"]:
        put(store,"mc" if block is None else "c",prefix+be32(credit["index"]),be64(credit["atoms"])+bytes([2 if credit["change"] else 0]))
    for debit in record["debits"]:
        previous=tx["inputs"][debit["index"]]
        op=previous["previous_hash"]+be32(previous["previous_index"])
        prior_block=be32(1)+digest("modeled previous block")
        # Use the actual old payout incidence when already present.
        matches=[bytes.fromhex(k) for k in store["c"] if bytes.fromhex(k)[:32]==previous["previous_hash"] and bytes.fromhex(k)[-4:]==be32(previous["previous_index"])]
        prior_key=matches[0] if matches else previous["previous_hash"]+prior_block+be32(previous["previous_index"])
        if block is None:
            put(store,"u",op,prior_key[32:68])
            put(store,"c",prior_key,be64(debit["atoms"])+b"\0")
        else:
            debit_key=prefix+be32(debit["index"])
            put(store,"d",debit_key,be64(debit["atoms"])+prior_key)
            put(store,"c",prior_key,be64(debit["atoms"])+b"\x01"+debit_key)
    return prefix


def make_storage(positives,script):
    by_name={p["name"]:p["record"] for p in positives}
    cases=[]

    def add(name,store,height,valid=True):
        value={"name":name,"origin":"modeled legacy DB layout using locked public raw records where named",
               "height":height,"buckets":copy.deepcopy(store)}
        try:
            result=capture(store,height)
        except Refusal as e:
            require(not valid)
            value.update(expected="reject",category=e.category)
        else:
            require(valid)
            value.update(expected=result)
        cases.append(value)

    add("empty",empty_store(),110)
    actual=empty_store()
    for name in ("actual/zero256/pool-payout","actual/zero256/own-confirmed","actual-raw/zero256/incoming"):
        add_record(actual,copy.deepcopy(by_name[name]))
    add("actual-shaped-zero256",actual,110)
    unmined=empty_store(); base=copy.deepcopy(by_name["actual/zero256/own-unconfirmed"])
    add_record(unmined,base)
    parsed=parse_transaction(bytes.fromhex(base["raw_hex"]));parsed["lock_time"]=1
    competing=tx_record(serialize(parsed),copy.deepcopy(base["credits"]),copy.deepcopy(base["debits"]))
    add_record(unmined,competing)
    first=parsed["inputs"][0]
    put(unmined,"mi",first["previous_hash"]+be32(first["previous_index"]),bytes.fromhex(base["txid"])[::-1]+bytes.fromhex(competing["txid"])[::-1])
    add("competing-unmined-mi-ignored",unmined,110)

    for count in (256,257):
        store=empty_store(); hashes=[]
        for i in range(count):
            record=simple("same-height/"+str(i),[100],script,[(0,False)],[])
            record["block"]={"height":100,"hash":display(digest("sameheight")),"time_ms":STAMP}
            add_record(store,record);hashes.append(bytes.fromhex(record["txid"])[::-1])
        add_block(store,100,digest("sameheight"),list(reversed(hashes)))
        add("within-height-"+str(count),store,110)

    long=empty_store()
    # All 5000 block metadata entries exist, but only the newest selected t
    # records are populated. Old missing/unindexed data must not be audited.
    for h in range(1,5001):
        if h>=4745:
            record=simple("long/"+str(h),[100],script,[(0,False)],[])
            record["block"]={"height":h,"hash":display(digest("block/"+str(h))),"time_ms":STAMP}
            add_record(long,record)
        else:
            add_block(long,h,digest("block/"+str(h)),[digest("old unaudited tx/"+str(h))])
    put(long,"t",bytes(68),b"intentionally malformed old unindexed value")
    add("long-history-5000-blocks",long,5000)

    # One unmined record shadows an exact older mined occurrence.
    precedence=copy.deepcopy(actual)
    add_record(precedence,copy.deepcopy(by_name["actual/zero256/own-unconfirmed"]))
    # Restore the old mined debit's previous-credit backlink after making the
    # unmined record: this case selects only the unmined occurrence, whose u
    # path must be unspent. Remove the older debit to make unaudited status clear.
    for k in list(precedence["d"]):
        del precedence["d"][k]
    add("unmined-precedence",precedence,110)

    parent=simple("unmined-parent",[1000],script,[(0,False)],[])
    child=simple("unmined-child",[900],script,[(0,True)],[1000])
    tx=parse_transaction(bytes.fromhex(child["raw_hex"]))
    tx["inputs"][0]["previous_hash"]=bytes.fromhex(parent["txid"])[::-1]
    tx["inputs"][0]["previous_index"]=0
    child=tx_record(serialize(tx),child["credits"],child["debits"],recorded=STAMP+1000)
    dependency=empty_store();add_record(dependency,parent);add_record(dependency,child)
    dependency["u"]={};dependency["c"]={}
    add("unmined-parent-credit",dependency,110)

    def bad(name,template,mutate,height=110):
        store=copy.deepcopy(template);mutate(store);add(name,store,height,False)

    ukey=next(iter(unmined["u"]))
    ckey=next(iter(unmined["c"]))
    bad("short-present-u",unmined,lambda s:s["u"].update({ukey:"00"}))
    bad("long-present-u",unmined,lambda s:s["u"].update({ukey:s["u"][ukey]+"00"}))
    bad("missing-u-credit",unmined,lambda s:s["c"].pop(ckey))
    bad("spent-u-credit",unmined,lambda s:s["c"].update({ckey:(be64(2970000000)+b"\x01"+bytes(72)).hex()}))
    bad("malformed-fallback-mc",dependency,lambda s:s["mc"].update({(bytes.fromhex(parent["txid"])[::-1]+be32(0)).hex():"00"}))
    dkey=next(iter(actual["d"]))
    bad("mined-debit-amount",actual,lambda s:s["d"].update({dkey:(be64(1)+bytes.fromhex(s["d"][dkey])[8:]).hex()}))
    previous_key=bytes.fromhex(actual["d"][dkey])[8:].hex()
    bad("mined-debit-backlink",actual,lambda s:s["c"].update({previous_key:(bytes.fromhex(s["c"][previous_key])[:9]+bytes(72)).hex()}))
    tkey=next(iter(actual["t"]))
    bad("missing-selected-t",actual,lambda s:s["t"].pop(tkey))
    bad("malformed-selected-t",actual,lambda s:s["t"].update({tkey:"00"}))
    bkey=max(actual["b"])
    bad("duplicate-block-txid",actual,lambda s:s["b"].update({bkey:(bytes.fromhex(s["b"][bkey])[:40]+be32(2)+bytes.fromhex(s["b"][bkey])[44:76]*2).hex()}))
    bad("block-count-capacity",actual,lambda s:s["b"].update({bkey:(bytes.fromhex(s["b"][bkey])[:40]+be32(4097)).hex()}))
    bad("block-length",actual,lambda s:s["b"].update({bkey:s["b"][bkey]+"00"}))
    bad("block-beyond-sync",actual,lambda s:None,109)
    over=empty_store()
    for i in range(4097):
        put(over,"m",digest("unmined metadata/"+str(i)),be64(STAMP//1000))
    add("unmined-count-capacity",over,110,False)
    target=bytes.fromhex(base["txid"])[::-1]
    def excess_credit(store):
        put(store,"mc",target+be32(0),be64(100000000)+b"\0")
        put(store,"mc",target+be32(2),be64(1)+b"\0")
    bad("credit-prefix-excess",unmined,excess_credit)
    selected_mc=(target+be32(base["credits"][0]["index"])).hex()
    bad("bad-selected-credit-flags",unmined,lambda s:s["mc"].update({selected_mc:(be64(base["credits"][0]["atoms"])+b"\x04").hex()}))

    for count in (256,257):
        store=empty_store();hashes=[]
        for i in range(count):
            record=simple("unmined-boundary/"+str(i),[100],script,[(0,False)],[])
            add_record(store,record);hashes.append(bytes.fromhex(record["txid"])[::-1])
        add("unmined-boundary-"+str(count),store,110)
        if count==256:
            for height in range(1,34):
                add_block(store,height,digest("duplicate-block/"+str(height)),hashes)
            add("repeated-old-ids-visit-capacity",store,110,False)
    return cases


def raw_budget_controls(base):
    # Compact precharge witnesses: previously_captured_bytes is a modeled
    # accumulator, not a claim that this fixture contains 8 MiB of history.
    store=empty_store();value=copy.deepcopy(base);value["block"]=None
    add_record(store,value)
    h=bytes.fromhex(value["txid"])[::-1];key=h.hex()
    raw_len=len(value["raw_hex"])//2
    cases=[]
    for name,remaining,corrupt in [("exact-remaining-budget",raw_len,False),
                                    ("one-byte-over-remaining",raw_len-1,False),
                                    ("capacity-before-corrupt-parse",raw_len-1,True),
                                    ("corrupt-with-sufficient-budget",raw_len,True)]:
        buckets=copy.deepcopy(store)
        if corrupt:
            row=bytearray.fromhex(buckets["m"][key]);row[8+4]=0;row[8+5]=2
            buckets["m"][key]=bytes(row).hex()
        result={"name":name,"origin":"modeled raw-budget accumulator/precharge boundary",
                "previously_captured_bytes":8388608-remaining,"remaining_raw_bytes":remaining,
                "txid":value["txid"],"buckets":buckets}
        try:
            record=Store(buckets).record(h,None,remaining)
        except Refusal as e:
            result.update(expected="reject",category=e.category)
        else:
            result.update(expected="accept",record=record)
        if name=="exact-remaining-budget":
            require(result["expected"]=="accept")
        else:
            require(result["expected"]=="reject")
            require(result["category"]==("corrupt" if name=="corrupt-with-sufficient-budget" else "capacity"))
        cases.append(result)
    return cases


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute",action="store_true")
    parser.add_argument("--inputs",type=Path,default=HERE.parent/"reference-inputs")
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--approved-producer-lock",type=Path,required=True)
    parser.add_argument("--approved-lock-sha256",required=True)
    args=parser.parse_args()
    if not args.execute:
        raise SystemExit("Refusing execution without explicit --execute and reviewed lock SHA")
    lock_raw=args.approved_producer_lock.read_bytes()
    require(sha(lock_raw)==args.approved_lock_sha256)
    producer_lock=json.loads(lock_raw)
    own={"transaction_model.py","storage_model.py","generate_core.py","core-case-plan.json"}
    require(own <= set(producer_lock["sources"]))
    for name in own:
        require(sha((HERE/name).read_bytes())==producer_lock["sources"][name])
    require(producer_lock["input_lock_sha256"]==LOCK)
    read=load_inputs(args.inputs)
    positives,negatives,script,base=make_transactions(read)
    report={"version":1,"input_lock_sha256":LOCK,"contract_sha256":CONTRACT,
            "scope":"independent supplied local wallet-record semantics; no signatures, work, canonicality or completeness proof",
            "transactions":{"positives":positives,"negatives":negatives,"raw_cases":raw_controls(script)},
            "storage":make_storage(positives,script),"raw_budget_controls":raw_budget_controls(base)}
    with args.output.open("xb") as f:
        f.write(json.dumps(report,indent=2,ensure_ascii=False).encode()+b"\n")


if __name__=="__main__":
    main()
