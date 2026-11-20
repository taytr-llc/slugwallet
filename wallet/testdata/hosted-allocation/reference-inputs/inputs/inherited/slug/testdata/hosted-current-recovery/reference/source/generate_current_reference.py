#!/usr/bin/env python3
"""SOURCE ONLY until explicit execution with a reviewed source/input lock.

Current recovery byte/CAS/audit reference. Old public identities and cursor
observations are inputs; new authority/retention/source IDs are modeled recipe
values, never claims of a real retained envelope or an installed wallet.
"""
import argparse
import json
from pathlib import Path

from common import (FIXTURES, ISSUER, TIME_MAX, Rejected, canonical, hex64,
                    need, own, packed, principal_id, sha)
from current_model import (ACCOUNT, BINDING, CHECKPOINT, CURRENT, CurrentModel,
                           audit, binding_hash, bindings_checked, checkpoint,
                           current_binding, export_model, manifest, parse_checkpoint)

HERE = Path(__file__).resolve().parent
CONTRACT = '92b247a5c3f47e637ed0dbf09d08c8f580a881cc80ff114a4c22d2e119572a86'
OWN_SOURCES = {'common.py', 'current_model.py', 'generate_current_reference.py',
               'current-case-plan.json'}


def guarded_inputs(args):
    need(args.execute, 'execution_not_authorized')
    approved = args.approved_producer_lock.read_bytes()
    need(sha(approved) == args.approved_lock_sha256, 'producer_lock')
    producer = json.loads(approved)
    need(producer.get('approved_by') == 'root' and
         producer.get('execution_authorized') is True, 'execution_not_authorized')
    need(OWN_SOURCES <= set(producer['sources']), 'producer_lock')
    for name in OWN_SOURCES:
        need(sha((HERE/name).read_bytes()) == producer['sources'][name], 'producer_source')
    input_raw = args.input_lock.read_bytes()
    need(sha(input_raw) == producer['input_lock_sha256'], 'input_lock')
    lock = json.loads(input_raw)
    need(lock['contract_sha256'] == CONTRACT, 'input_contract')
    catalog_path = args.input_lock.parent/lock['catalog']
    catalog_raw = catalog_path.read_bytes()
    need(sha(catalog_raw) == lock['catalog_sha256'], 'input_catalog')
    catalog = json.loads(catalog_raw)
    root = args.inputs.resolve()
    paths = {}
    total = 0
    need(len(catalog['files']) == lock['file_count'] <= 256, 'input_count')
    for row in catalog['files']:
        name = row['path']
        path = (root/name).resolve()
        need(not Path(name).is_absolute() and root in path.parents and name not in paths, 'input_path')
        raw = path.read_bytes()
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'input_bytes')
        total += len(raw)
        paths[name] = path
    need(total == lock['input_bytes'], 'input_count')
    need(args.recipe in paths, 'input_recipe')
    recipe_raw = paths[args.recipe].read_bytes()
    need(sha(recipe_raw) == lock['recipe_sha256'], 'input_recipe')
    recipe = json.loads(recipe_raw)
    need(recipe['fixture_order'] == list(FIXTURES), 'input_recipe')
    need(sha(paths[recipe['paths']['contract']].read_bytes()) == CONTRACT, 'input_contract')
    def read(name):
        need(name in paths, 'unlocked_input')
        return json.loads(paths[name].read_bytes())
    return recipe, read, sha(input_raw), sha(approved)


def input_bindings(recipe, read):
    """Derive independently from common literal inputs, not provider outputs."""
    original, actual, bindings = [], [], []
    old = read(recipe['paths']['old_recovery'])
    old_by_name = {row['name']: row for row in old['cases']}
    ids = recipe['ids']
    for fixture in FIXTURES:
        observed = read(recipe['paths']['actual_manifests'][fixture])
        initial = own(observed)
        inherited = own(old_by_name[fixture]['export']['manifest'])
        for value in (initial, inherited):
            for row in value['accounts']:
                row['next_external'] = row['next_internal'] = 0
        need(initial == inherited, 'inherited_identity')
        initial = manifest(initial, inherited)
        observed = manifest(observed, initial)
        for row in observed['accounts']:
            want = 1 if row['purpose'] == 84 else 0
            need(row['next_external'] == want and row['next_internal'] == want, 'old_actual_inventory')
        base = dict(version=1, authority_id=ids['authority'], account_id=ids['accounts'][fixture],
                    principal_id=principal_id(ISSUER, fixture), provision_id=ids['provisions'][fixture],
                    network=initial['network'], genesis=initial['genesis'], profile=initial['profile'],
                    root_public_key=initial['root_public_key'], gym_public_key=initial['gym_public_key'],
                    gym_id=initial['gym_id'])
        binding = dict(version=1, hosted_vault_id=ids['vault'], vault_binding=base,
                       retention_id=ids['retentions'][fixture], wallet_owner_id=ids['wallets'][fixture],
                       source_binding_id=ids['source_binding'])
        original.append(initial); actual.append(observed); bindings.append(binding)
    return original, actual, bindings_checked(bindings, original)


def request(recipe, bindings, index, ident, expected, at, value):
    capture = '%064x' % (recipe['sequence_starts']['capture']+ident)
    hex64(capture, True)
    return dict(binding=own(bindings[index]), capture_id=capture,
                expected_revision=expected, captured_at_ms=at, manifest=own(value))


def binding_cases(bindings, originals):
    positives, negatives = [], []
    for index, fixture in enumerate(FIXTURES):
        b = current_binding(bindings[index], originals[index])
        positives.append(dict(name=fixture, binding=b, canonical_utf8=canonical(b).decode(),
                              preimage_hex=(b'SLUG hosted current recovery binding\0v1\0'+canonical(b)).hex(),
                              binding_sha256=binding_hash(b)))
        for name in CURRENT:
            if name == 'vault_binding':
                continue
            bad = own(b)
            bad[name] = 2 if name == 'version' else 'f'*64
            negatives.append(dict(name=fixture+'/cross-'+name, expected_binding=b, supplied=bad,
                                  original=originals[index], expected='reject'))
        for name in BINDING:
            bad = own(b)
            value = bad['vault_binding'][name]
            bad['vault_binding'][name] = value+1 if type(value) is int else value+'x'
            negatives.append(dict(name=fixture+'/cross-vault-'+name, expected_binding=b,
                                  supplied=bad, original=originals[index], expected='reject'))
        for name in ('hosted_vault_id', 'wallet_owner_id'):
            bad = own(b); bad[name] = '0'*64
            negatives.append(dict(name=fixture+'/zero-'+name, expected_binding=b,
                                  supplied=bad, original=originals[index], expected='reject'))
        bad = own(b); bad['source_binding_id'] = 'A'*64
        negatives.append(dict(name=fixture+'/uppercase-hash', expected_binding=b, supplied=bad,
                              original=originals[index], expected='reject'))
    for case in negatives:
        try:
            value = current_binding(case['supplied'], case['original'])
            need(value == case['expected_binding'], 'conflict')
        except Rejected as error:
            case['category'] = error.code
        else:
            raise AssertionError('binding negative accepted: '+case['name'])
    return dict(positives=positives, negatives=negatives)


def manifest_cases(originals, actual):
    result = []
    for index, fixture in enumerate(FIXTURES):
        candidates = [('default', originals[index], 'inherited zero-cursor DefaultAccounts'),
                      ('old-actual-1-1', actual[index], 'old-source actual public inventory')]
        for branch in range(8):
            for amount in (1, 4095, 4096):
                value = own(originals[index])
                value['accounts'][branch//2]['next_external' if branch % 2 == 0 else 'next_internal'] = amount
                candidates.append(('branch-%d-%d' % (branch, amount), value,
                                   'modeled one-branch cursor; inherited immutable identity'))
        for label, value, origin in candidates:
            value = manifest(value, originals[index])
            raw = canonical(value)
            result.append(dict(name=fixture+'/'+label, origin=origin, manifest=value,
                               canonical_utf8=raw.decode(), manifest_sha256=sha(raw)))
    return result


def transition_cases(recipe, originals, actual, bindings):
    base = recipe['base_ms']
    empty = CurrentModel(bindings, originals)
    initial = CurrentModel(bindings, originals)
    first_requests = []
    first_rows = []
    for index in range(2):
        req = request(recipe, bindings, index, index+1, 0, base+index*1000, actual[index])
        row, created = initial.commit(index, req, base+index*1000+100)
        need(created)
        first_requests.append(req); first_rows.append(row)
    advanced = audit(packed(initial.marker(),32768,True), initial.entries(), bindings, originals)
    value = own(actual[0]); value['accounts'][0]['next_external'] = 1
    req3 = request(recipe, bindings, 0, 3, 1, base+2000, value)
    advanced.commit(0, req3, base+2100)
    req4 = request(recipe, bindings, 1, 4, 1, base+2000, actual[1])
    advanced.commit(1, req4, base+2100)
    capacity = CurrentModel(bindings, originals)
    capacity_commands = []
    for seq in range(128):
        index = seq % 2
        req = request(recipe, bindings, index, 100+seq, seq//2, base+seq, actual[index])
        row, created = capacity.commit(index, req, base+seq)
        need(created)
        capacity_commands.append(dict(index=index, request=req, now_ms=base+seq,
                                      checkpoint_sha256=sha(canonical(row))))
    models = {'empty':empty, 'initial-both':initial, 'advanced-both':advanced, 'capacity-128':capacity}
    states = [dict(name=name, state=model.snapshot()) for name, model in models.items()]
    for model in models.values():
        restored = audit(packed(model.marker(),32768,True), model.entries(), bindings, originals)
        need(restored.snapshot() == model.snapshot())
    cases = []
    def add(name, state, index, req, now, expected):
        start = models[state]
        model = audit(packed(start.marker(),32768,True), start.entries(), bindings, originals)
        case = dict(name=name, initial_state=state, index=index, request=own(req), now_ms=now,
                    expected=expected)
        before = model.snapshot()
        try:
            row, created = model.commit(index, req, now)
        except Rejected as error:
            need(expected == 'reject', 'unexpected_model_refusal')
            need(model.snapshot() == before, 'rejected_mutation')
            case['category'] = error.code
        else:
            need(expected == ('created' if created else 'replayed'), 'unexpected_model_acceptance')
            case.update(checkpoint=row, canonical_utf8=canonical(row).decode(),
                        checkpoint_sha256=sha(canonical(row)), meta=model.meta(),
                        meta_utf8=canonical(model.meta()).decode())
        cases.append(case)
    add('first-zero', 'empty', 0, first_requests[0], base+100, 'created')
    add('first-incrementing', 'empty', 1, first_requests[1], base+1100, 'created')
    add('same-cursors-new-action', 'initial-both', 1, req4, base+2100, 'created')
    add('old-id-replay-after-later', 'advanced-both', 0, first_requests[0], base+9000, 'replayed')
    add('replay-at-capacity', 'capacity-128', 0, capacity_commands[0]['request'], base+9000, 'replayed')
    add('129th-action', 'capacity-128', 0,
        request(recipe,bindings,0,228,64,base+129,actual[0]), base+129, 'reject')
    fresh = request(recipe,bindings,0,20,1,base+2000,actual[0])
    add('global-clock-equality', 'initial-both', 0,
        request(recipe,bindings,0,21,1,base+1000,actual[0]), base+1100, 'created')
    add('time-maximum', 'initial-both', 0,
        request(recipe,bindings,0,22,1,TIME_MAX,actual[0]), TIME_MAX, 'created')
    for name, field, value in [('expected-revision','expected_revision',0),
                               ('capture-time-regression','captured_at_ms',base-1),
                               ('time-zero','captured_at_ms',0),
                               ('time-overflow','captured_at_ms',TIME_MAX+1),
                               ('capture-id-zero','capture_id','0'*64),
                               ('capture-id-uppercase','capture_id','A'*64)]:
        bad = own(fresh); bad[field] = value
        add(name,'initial-both',0,bad,base+3000,'reject')
    add('commit-before-capture','initial-both',0,fresh,base+1999,'reject')
    lower = own(fresh); lower['captured_at_ms'] = base+1000
    add('commit-before-global-highwater','initial-both',0,lower,base+1099,'reject')
    for field, value in [('expected_revision',1),('captured_at_ms',base+1)]:
        bad=own(first_requests[0]);bad[field]=value
        add('reused-id-changed-'+field,'advanced-both',0,bad,base+9000,'reject')
    bad=own(first_requests[0]);bad['manifest']['accounts'][0]['next_external']=1
    add('reused-id-changed-manifest','advanced-both',0,bad,base+9000,'reject')
    for branch in range(8):
        high = own(actual[0])
        key='next_external' if branch%2==0 else 'next_internal'
        high['accounts'][branch//2][key]=2
        model=CurrentModel(bindings,originals)
        model.commit(0,request(recipe,bindings,0,500+branch,0,base,high),base)
        state='branch-%d-baseline'%branch
        models[state]=model;states.append(dict(name=state,state=model.snapshot()))
        low=own(high);low['accounts'][branch//2][key]=1
        add('branch-%d-regression'%branch,state,0,
            request(recipe,bindings,0,600+branch,1,base+1,low),base+1,'reject')
    bad=own(fresh);bad['manifest']['accounts'][0]['next_external']=4097
    add('cursor-4097','initial-both',0,bad,base+3000,'reject')
    bad=own(fresh);bad['manifest']['accounts'][1]['internal_type']='p2sh-p2wpkh'
    add('mixed49-internal-mutation','initial-both',0,bad,base+3000,'reject')
    return states, cases, capacity_commands, models, first_rows[0]


def storage_negatives(models, bindings, originals):
    template = models['advanced-both'].snapshot()
    cases=[]
    def mutate(name, fn):
        state=own(template);fn(state)
        try:
            audit(state['marker_file_utf8'].encode(),state['entries'],bindings,originals)
        except Rejected as error:
            cases.append(dict(name=name, expected='reject',category=error.code,
                              marker_file_utf8=state['marker_file_utf8'],entries=state['entries']))
        else:
            raise AssertionError('store negative accepted: '+name)
    def edit_meta(state, fn):
        row=next(r for r in state['entries'] if r['key']=='meta')
        value=json.loads(bytes.fromhex(row['value_hex']));fn(value)
        row['value_hex']=canonical(value).hex()
    def edit_action(state,index,revision,fn):
        for row in state['entries']:
            if row['key']=='meta':continue
            value=json.loads(bytes.fromhex(row['value_hex']))
            if (value['binding']['vault_binding']['account_id']==bindings[index]['vault_binding']['account_id']
                    and value['revision']==revision):
                fn(value);row['value_hex']=canonical(value).hex();return
        raise AssertionError('missing modeled action')
    def edit_marker(state,fn):
        value=json.loads(state['marker_file_utf8']);fn(value)
        state['marker_file_utf8']=packed(value,32768,True).decode()
    mutate('missing-meta',lambda s:s['entries'].__setitem__(slice(None),[r for r in s['entries'] if r['key']!='meta']))
    mutate('missing-action',lambda s:s['entries'].pop(0))
    mutate('unknown-key',lambda s:s['entries'].append(dict(key='unknown',value_hex='7b7d')))
    mutate('duplicate-key',lambda s:s['entries'].append(own(s['entries'][0])))
    mutate('wrong-marker-digest',lambda s:edit_meta(s,lambda m:m.__setitem__('marker_sha256','0'*64)))
    mutate('wrong-count',lambda s:edit_meta(s,lambda m:m.__setitem__('actions',3)))
    mutate('wrong-highwater',lambda s:edit_meta(s,lambda m:m.__setitem__('clock_high_water_ms',m['clock_high_water_ms']+1)))
    mutate('pointer-wrong-owner',lambda s:edit_meta(s,lambda m:m['current'].reverse()))
    mutate('dangling-current',lambda s:edit_meta(s,lambda m:m['current'][0].__setitem__('capture_id','e'*64)))
    mutate('current-not-latest',lambda s:edit_meta(s,lambda m:m['current'][0].__setitem__('revision',1)))
    mutate('marker-wrong-order',lambda s:edit_marker(s,lambda m:m['bindings'].reverse()))
    mutate('marker-duplicate-binding',lambda s:edit_marker(s,lambda m:m['bindings'].__setitem__(1,own(m['bindings'][0]))))
    mutate('marker-foreign-wallet',lambda s:edit_marker(s,lambda m:m['bindings'][0].__setitem__('wallet_owner_id','d'*64)))
    mutate('action-id-key-mismatch',lambda s:edit_action(s,0,2,lambda a:a.__setitem__('capture_id','e'*64)))
    mutate('duplicate-own-revision',lambda s:edit_action(s,0,2,lambda a:a.update(revision=1,expected_revision=0)))
    mutate('own-revision-gap',lambda s:edit_action(s,0,2,lambda a:a.update(revision=3,expected_revision=2)))
    mutate('wrong-manifest-hash',lambda s:edit_action(s,0,2,lambda a:a.__setitem__('manifest_sha256','0'*64)))
    mutate('capture-clock-regression',lambda s:edit_action(s,0,2,lambda a:a.__setitem__('captured_at_ms',original_time(models)-1)))
    mutate('commit-clock-regression',lambda s:edit_action(s,0,2,lambda a:a.update(captured_at_ms=original_time(models),committed_at_ms=original_time(models))))
    def regress(a):
        a['manifest']['accounts'][2]['next_internal']=0
        a['manifest_sha256']=sha(canonical(a['manifest']))
    mutate('cursor-regression-valid-digest',lambda s:edit_action(s,0,2,regress))
    return cases


def original_time(models):
    return min(r['captured_at_ms'] for r in models['initial-both'].actions.values())


def raw_cases(row, binding, original):
    raw=canonical(row)
    pairs=[('canonical',raw,True),('leading-space',b' '+raw,False),
           ('terminal-lf',raw+b'\n',False),('invalid-utf8',raw+b'\xff',False),
           ('over-cap',b' '*8193,False),('top-null',b'null',False),
           ('reordered',canonical(dict(reversed(list(row.items())))),False)]
    pairs += [('duplicate-version',raw.replace(b'{',b'{"version":1,',1),False),
              ('escaped-duplicate',raw.replace(b'{',b'{"\\u0076ersion":1,',1),False)]
    for label, replacement in [('float',b'1.0'),('exponent',b'1e0'),('negative-zero',b'-0'),
                               ('negative',b'-1'),('bool',b'true'),('null-field',b'null'),
                               ('version-overflow',b'4294967296')]:
        pairs.append((label,raw.replace(b'"version":1',b'"version":'+replacement,1),False))
    for label, change in [('missing-field',lambda v:v.pop('capture_id')),
                          ('unknown-field',lambda v:v.__setitem__('extra',1)),
                          ('case-alias',lambda v:v.__setitem__('Version',v.pop('version'))),
                          ('null-binding',lambda v:v.__setitem__('binding',None))]:
        value=own(row);change(value);pairs.append((label,canonical(value),False))
    result=[]
    for name, value, valid in pairs:
        try:
            parsed=parse_checkpoint(value,binding,original)
        except Rejected as error:
            need(not valid,'positive_raw_refused');category=error.code
        else:
            need(valid and parsed==row,'negative_raw_accepted');category='accept'
        result.append(dict(name=name,valid=valid,raw_hex=value.hex(),category=category,
                           fixture_serialization_only=False))
    return result


def lifecycle_cases():
    faults=['none','held','stale_view','cancel_before_fence','destination_exists',
            'missing_callback','late_callback','create','write','file_sync','link_unknown',
            'cancel_after_link','unlink','directory_sync','postcheck','outer_error',
            'double_callback','swallowed_write']
    result=[dict(name=fault,input=dict(fault=fault,cleanup_failure=False),
                 expected=export_model(fault)) for fault in faults]
    for fault in ('write','link_unknown','outer_error'):
        result.append(dict(name=fault+'-cleanup-failure',
                           input=dict(fault=fault,cleanup_failure=True),
                           expected=export_model(fault,True)))
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true')
    parser.add_argument('--inputs',type=Path,required=True)
    parser.add_argument('--input-lock',type=Path,required=True)
    parser.add_argument('--recipe',default='fixture-recipe.json')
    parser.add_argument('--approved-producer-lock',type=Path,required=True)
    parser.add_argument('--approved-lock-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    recipe,read,input_sha,producer_sha=guarded_inputs(args)
    need(not args.output.exists(),'output_exists')
    originals,actual,bindings=input_bindings(recipe,read)
    states,transitions,capacity,models,first=transition_cases(recipe,originals,actual,bindings)
    report=dict(version=1,contract_sha256=CONTRACT,input_lock_sha256=input_sha,
                producer_lock_sha256=producer_sha,
                scope='Independent supplied public bytes and arithmetic only; model IDs do not authenticate accounts, stores, wallet ownership, retention or file effects.',
                fixture_order=list(FIXTURES),original_manifests=originals,
                old_actual_manifests=actual,expected_bindings=bindings,
                bindings=binding_cases(bindings,originals),
                manifests=manifest_cases(originals,actual),states=states,
                transitions=transitions,capacity_commands=capacity,
                storage_negatives=storage_negatives(models,bindings,originals),
                raw_cases=raw_cases(first,bindings[0],originals[0]),
                export_lifecycle=lifecycle_cases())
    # The only generated-output write is exclusive, after every assertion.
    # A wrapper owns failed-attempt logs; this script never overwrites a corpus.
    with args.output.open('xb') as output:
        output.write(json.dumps(report,indent=2,ensure_ascii=False,allow_nan=False).encode('utf8')+b'\n')


if __name__=='__main__':
    main()
