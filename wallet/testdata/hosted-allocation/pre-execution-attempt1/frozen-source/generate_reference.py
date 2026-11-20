#!/usr/bin/env python3
"""Review-gated Set72 independent allocation bytes/state/capacity producer.

No product-code import, wallet database, network, node or private fixture data.
The final adopted contract and every source/input must be root-locked before
ANY derivation, state-model or sizing routine executes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True

HERE=Path(__file__).resolve().parent
SOURCES={'common.py','public_derivation.py','allocation_model.py','sizing_model.py',
         'generate_reference.py','case-plan.json','README.md','sizing.py'}
H=lambda raw:hashlib.sha256(raw).hexdigest()


def safe_path(root,name):
    rel=Path(name)
    if rel.is_absolute() or not rel.parts or any(x in ('..','.') for x in rel.parts):raise ValueError('unsafe relative path')
    p=root
    for part in rel.parts:
        p=p/part
        if p.is_symlink():raise ValueError('symlink input')
    if not p.is_file() or root not in p.resolve().parents:raise ValueError('input outside root')
    return p


def guard(args):
    if not args.execute:raise ValueError('explicit --execute required')
    raw=args.approved_producer_lock.read_bytes()
    if H(raw)!=args.approved_lock_sha256:raise ValueError('approved lock hash mismatch')
    lock=json.loads(raw)
    if lock.get('approved_by')!='root' or lock.get('execution_authorized') is not True or lock.get('final_contract_reviewed') is not True:
        raise ValueError('root approval/final grammar missing')
    if set(lock['sources'])!=SOURCES:raise ValueError('source set mismatch')
    for name in SOURCES:
        if H(safe_path(HERE,name).read_bytes())!=lock['sources'][name]:raise ValueError('producer source changed')
    if H(args.contract.read_bytes())!=lock['contract_sha256']:raise ValueError('adopted contract changed')
    iraw=args.input_lock.read_bytes()
    if H(iraw)!=lock['input_lock_sha256']:raise ValueError('input lock changed')
    ilock=json.loads(iraw);craw=safe_path(args.input_lock.parent.resolve(),ilock['catalog']).read_bytes()
    if H(craw)!=ilock['catalog_sha256']:raise ValueError('catalog changed')
    catalog=json.loads(craw);root=args.inputs.resolve(strict=True);read={};total=0
    if len(catalog['files'])!=ilock['input_count'] or len(catalog['files'])>128:raise ValueError('input count')
    for row in catalog['files']:
        name=row['path']
        if name in read:raise ValueError('duplicate input')
        path=safe_path(root,name);raw=path.read_bytes()
        if len(raw)!=row['bytes'] or H(raw)!=row['sha256']:raise ValueError('input changed '+name)
        total+=len(raw);read[name]=path
    if total!=ilock['input_bytes'] or total>16*1024*1024:raise ValueError('input byte count')
    recipe=json.loads(read[ilock['recipe']].read_bytes())
    if H(read[ilock['recipe']].read_bytes())!=ilock['recipe_sha256']:raise ValueError('recipe changed')
    if recipe['fixture_order']!=['zero256','incrementing256']:raise ValueError('fixture order')
    return recipe,read,H(iraw),H(args.approved_producer_lock.read_bytes()),lock['contract_sha256']


def generate(recipe,paths,input_hash,producer_hash,contract_hash):
    # Imports occur after guard; module bodies perform no model executions.
    from common import canonical,own,need,Rejected
    from allocation_model import AllocationModel,audit,binding,domain,wallet_guard,decode_row,request
    from public_derivation import load_oracle,PublicDerivation,address_for_script
    from sizing_model import sizes
    def read(name):return json.loads(paths[name].read_bytes())
    current=read(recipe['paths']['current']);addresses=read(recipe['paths']['addresses'])
    old=load_oracle(paths[recipe['paths']['old_oracle']])
    transactions=read(recipe['paths']['withdrawals'])['cases']
    expected=[];derivations=[];overlaps=[]
    for i,name in enumerate(recipe['fixture_order']):
        source=current['expected_bindings'][i];v=source['vault_binding'];initial=current['original_manifests'][i]
        b=dict(version=1,inventory_id=recipe['inventory_ids'][name],authority_id=v['authority_id'],
               account_id=v['account_id'],principal_id=v['principal_id'],provision_id=v['provision_id'],
               hosted_vault_id=source['hosted_vault_id'],retention_id=source['retention_id'],
               wallet_owner_id=source['wallet_owner_id'],source_binding_id=source['source_binding_id'],
               manager_schema=13,max_allocations=1024,max_bytes=4194304,max_plan_attempts=128,
               max_branch_index=4096,initial_manifest=initial)
        expected.append(binding(b,initial))
        a=next(x for x in addresses['cases'] if x['name']==name)
        need(a['manifest']==initial,'prior_manifest')
        d=PublicDerivation(old,a);overlaps.append(d.verify_overlap(a));derivations.append(d)
    for case in transactions:
        d=case['draft'];raw=canonical(d)
        need(raw.decode()==case['canonical_draft'],'prior_draft')
        need(H(b'SLUG candidate withdrawal draft\x00v1\x00'+len(raw).to_bytes(4,'little')+raw)==case['draft_digest'],'prior_digest')
        need(address_for_script(bytes.fromhex(d['recipient_script']))==d['recipient'],'prior_address')
    def ident(n):return '%064x'%(recipe['operation_sequence_start']+n)
    def req(kind,op,draft=None):
        r=dict(version=1,kind=kind,consumer_id=op,purpose=84,branch=0,withdrawal_binding_id='',
               recipient='',recipient_script='',amount_atoms=0,fee_rate_atoms_per_kb=0,
               fee_ceiling_atoms=0,min_confirmations=0,input_purpose=0,change_purpose=0,
               account=0,tx_version=0,input_sequence=0,lock_time=0,sighash_type=0)
        if draft:
            r.update(consumer_id=draft['operation_id'],branch=1,withdrawal_binding_id=draft['binding_id'],
                     recipient=draft['recipient'],recipient_script=draft['recipient_script'],amount_atoms=draft['amount_atoms'],
                     fee_rate_atoms_per_kb=1000,fee_ceiling_atoms=100000,min_confirmations=1,input_purpose=84,
                     change_purpose=84,account=0,tx_version=1,input_sequence=4294967295,lock_time=0,sighash_type=1)
        return request(r,op)
    now=recipe['base_ms'];states=[];transitions=[];nextid=0
    def allocate(model,kind='receive',draft=None):
        nonlocal nextid
        nextid+=1;op=ident(nextid);row,changed=model.reserve(op,req(kind,op,draft),now+nextid*10)
        need(changed);return op,row
    def record(name,model,origin,faults=None):
        value=model.snapshot();audit(value,model.binding,model.derive)
        states.append(dict(name=name,origin=origin,fault_trace=faults or [],snapshot=value,
                           host_bytes=model.database_bytes(),local_bytes=model.local_bytes()))
    def ready_pool(i,derive=None):
        m=AllocationModel(expected[i],derive or derivations[i].child);op,_=allocate(m,'pool_recipient')
        m.consume(op);m.acknowledge(op,now+nextid*10+1);return m
    for i,fixture in enumerate(recipe['fixture_order']):
        m=AllocationModel(expected[i],derivations[i].child);record(fixture+'/empty-bound',m,'modeled empty owned inventory')
        pool,_=allocate(m,'pool_recipient');record(fixture+'/pool-reserved',m,'modeled ordering; old public index0 derivation')
        m.consume(pool);record(fixture+'/pool-local-before-ack',m,'modeled known local commit/lost acknowledgment')
        m.acknowledge(pool,now+nextid*10+1);record(fixture+'/pool-complete',m,'modeled complete pool prefix')
        op,row=allocate(m);record(fixture+'/receive-reserved',m,'modeled reservation expands recovery before disclosure')
        m.consume(op);m.acknowledge(op,now+nextid*10+1);record(fixture+'/receive-complete',m,'modeled receive, independently derived index1')
        before=canonical(m.snapshot());replayed,changed=m.reserve(op,row['reservation']['request'],now)
        need(not changed and canonical(m.snapshot())==before)
        transitions.append(dict(name=fixture+'/same-id-replay',allocation_id=op,request=row['reservation']['request'],changed=False,row=replayed))
        burn,_=allocate(m);m.consume(burn,'burned');m.acknowledge(burn,now+nextid*10+1)
        record(fixture+'/burned-receive',m,'modeled burned path remains in recovered prefix')
        for case in transactions:
            if case['fixture']!=fixture or not case['name'].startswith(fixture+'-'):continue
            m=ready_pool(i);op,_=allocate(m,'withdrawal_change',case['draft'])
            need(m.rows[-1]['reservation']['script']==case['draft']['change']['script'],'old_change_script')
            m.consume(op,'consumed',case['draft_digest']);m.acknowledge(op,now+nextid*10+1)
            record(fixture+'/'+case['name'],m,'unchanged independent Set68 draft digest/path; allocation identities modeled')
        faults=[[0,1],[0,2]];m=ready_pool(i,derivations[i].with_injected_invalid(faults));op,_=allocate(m)
        m.consume(op);m.acknowledge(op,now+nextid*10+1)
        record(fixture+'/injected-invalid-prefix',m,'explicit modeled invalid-child injection; not natural BIP32 observation',faults)
        case=next(c for c in transactions if c['name']==fixture+'-original-to-84')
        m=ready_pool(i);op,_=allocate(m,'withdrawal_change',case['draft']);record(fixture+'/withdrawal-plan-lost-reserved',m,'crashed private plan is absent; new selection forbidden')
        m.consume(op,'burned');m.acknowledge(op,now+nextid*10+1)
        record(fixture+'/withdrawal-plan-lost-burned',m,'explicit Burn only; app intent still needs user Abandon/new OperationID')
    # One finite 1024-row boundary, using actual public derivation and exact IDs.
    m=ready_pool(0)
    while len(m.rows)<1024:
        op,_=allocate(m);m.consume(op);m.acknowledge(op,now+nextid*10+1)
    record('zero256/count-capacity-1024',m,'modeled full count; no reclaimed capacity')
    try:allocate(m)
    except Rejected as error:need(error.code=='capacity')
    else:raise AssertionError('1025th allocation accepted')
    negatives=[]
    original=next(x for x in states if x['name']=='zero256/receive-complete')['snapshot']
    changes=[('meta-revision',['meta','revision'],0),('head-regression',['meta','cursors'],[0]*8),
             ('missing-local-link',['local_links'],[]),('foreign-row-binding',['rows',1,'reservation','binding_id'],'f'*64),
             ('duplicate-sequence',['rows',1,'reservation','sequence'],1),('false-invalid-child',['rows',1,'reservation','invalid_indices'],[0]),
             ('wrong-local-digest',['rows',1,'wallet_record_digest'],'f'*64),('guard-schema-alias',['guard','state'],'locked'),
             ('bool-count',['meta','allocations'],True),('wrong-local-end',['local_links',1,'end_index'],3),
             ('clock-regression',['rows',1,'reservation','reserved_at_ms'],1),('unknown-row-field',['rows',1,'extra'],0)]
    for name,path,value in changes:
        bad=own(original);target=bad
        for part in path[:-1]:target=target[part]
        target[path[-1]]=value
        try:audit(bad,expected[0],derivations[0].child)
        except Rejected as error:category=error.code
        else:raise AssertionError('storage mutation accepted '+name)
        negatives.append(dict(name=name,expected_binding=expected[0],snapshot=bad,expected='reject',category=category))
    raw_cases=[];raw=canonical(original['rows'][1])
    variants=[('canonical',raw,True),('lf',raw+b'\n',False),('space',b' '+raw,False),
              ('duplicate',raw[:-1]+b',"phase":"consumed"}',False),('null',b'null',False),
              ('trailing',raw+b'{}',False),('missing-field',raw.replace(b'"phase":"consumed",',b'',1),False)]
    for name,value,valid in variants:
        try:decode_row(value,expected[0],derivations[0].child)
        except Rejected:need(not valid)
        else:need(valid)
        raw_cases.append(dict(name=name,raw_hex=value.hex(),valid=valid))
    sizing=sizes(original,expected[0])
    return dict(version=1,scope='independent proposed allocation codec/state model; no capabilities, IO or production ownership proof',
                contract_sha256=contract_hash,input_lock_sha256=input_hash,producer_lock_sha256=producer_hash,
                overlap=dict(public_native84_addresses=sum(overlaps),old_drafts=len(transactions)),
                bindings=[dict(binding=b,canonical_utf8=canonical(b).decode(),binding_id=domain('binding',b),
                               locked_guard=wallet_guard(False,b),bound_guard=wallet_guard(True,b)) for b in expected],
                states=states,transitions=transitions,storage_negatives=negatives,raw_cases=raw_cases,sizing=sizing,
                lifecycle=[dict(name='receive-reply-lost-after-ack',permitted='fresh exact-ID redisplay with new action/View and proof/watch'),
                           dict(name='reserved-withdrawal-plan-lost',permitted='explicit Burn; then user Abandon before new OperationID'),
                           dict(name='local-withdrawal-commit-lost-ack',permitted='recover exact saved draft; no reselect or second allocation'),
                           dict(name='missing-wallet-export',permitted='exact surviving inventory reserved head; no payment-journal restoration')])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true');parser.add_argument('--approved-producer-lock',type=Path,required=True)
    parser.add_argument('--approved-lock-sha256',required=True);parser.add_argument('--input-lock',type=Path,required=True)
    parser.add_argument('--inputs',type=Path,required=True);parser.add_argument('--contract',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    values=guard(args);result=generate(*values)
    # Recheck every immutable source/input after bounded model work too.
    if guard(args)[2:]!=values[2:]:raise ValueError('binding changed during generation')
    raw=(json.dumps(result,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode()
    if len(raw)>32*1024*1024:raise ValueError('reference size exceeded')
    with args.output.open('xb') as stream:stream.write(raw)
    print(json.dumps(dict(bytes=len(raw),sha256=H(raw),states=len(result['states']),negatives=len(result['storage_negatives']))))


if __name__=='__main__':main()
