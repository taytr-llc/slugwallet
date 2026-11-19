"""Frozen-input public fixture generator. Never reads current Go or wallet data."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import transaction_model as M

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent/'reference-inputs'
J=lambda v:json.dumps(v,separators=(',',':'),ensure_ascii=False).encode()
H=lambda b:hashlib.sha256(b).hexdigest()
DOMAIN=b'SLUG candidate withdrawal draft\x00v1\x00'

def inputs_checked():
    lock=json.loads((ROOT/'input-lock.json').read_bytes())
    for path,entry in lock['files'].items():
        data=(ROOT/path).read_bytes()
        assert H(data)==entry['sha256'] and len(data)==entry['bytes'],path
    producer=json.loads((HERE/'producer-lock.json').read_bytes())
    for path,digest in producer['sources'].items():
        assert H((HERE/path).read_bytes())==digest,path
    assert H((ROOT/'input-lock.json').read_bytes())==producer['input_lock_sha256']
    assert H((HERE.parent/'frozen/wallet-v1.md').read_bytes())==producer['wallet_contract_sha256']

def wallet_draft(name, model, recipient, tip):
    inputs=[]
    for c in model['inputs']:
        inputs.append(dict(txid=c['txid'],output_index=c['index'],atoms=c['atoms'],script=c['script'],branch=c.get('branch',0),index=c.get('path_index',0),block_hash=c.get('block_hash',tip['before_tip']),block_height=c.get('block_height',tip['before_height']),coinbase=c.get('coinbase',False)))
    change=model['consumed_change'];recipient_index=next(i for i,o in enumerate(model['outputs']) if o['role']=='recipient')
    chindex=model['change_index'];change_atoms=0 if chindex<0 else model['outputs'][chindex]['atoms']
    d=dict(version=1,binding_id=H(b'public Set68 independent wallet binding'),operation_id=H(b'public Set68 operation:'+name.encode()),recipient=recipient['address'],recipient_script=recipient['script_pub_key'],amount_atoms=model['recipient_atoms'],recipient_output_index=recipient_index,fee_rate_atoms_per_kb=1000,fee_ceiling_atoms=100000,min_confirmations=1,tip_hash=tip['before_tip'],tip_height=tip['before_height'],tx_version=1,input_sequence=4294967295,lock_time=0,sighash_type=1,inputs=inputs,total_input_atoms=sum(c['atoms'] for c in model['inputs']),change=dict(address=change['address'],script=change['script'],index=int(change['path'].split('/')[-1]),output_index=chindex,atoms=change_atoms),fee_atoms=model['fee_atoms'],unsigned_tx_hex=model['unsigned_hex'])
    raw=J(d);assert len(raw)<=16384
    return d,raw, H(DOMAIN+len(raw).to_bytes(4,'little')+raw)

def build():
    inputs_checked()
    fixtures={x['name']:x for x in json.loads((ROOT/'public/fixture-recovery-v1.json').read_bytes())['cases']}
    original=json.loads((ROOT/'public/original-set61-payout.json').read_bytes())['batches'][0]
    baseline=json.loads((ROOT/'public/legacy-payout-baseline-zero256.json').read_bytes())
    assert baseline['before_height']==baseline['after_height']==109 and baseline['before_tip']==baseline['after_tip']
    assert baseline['transaction']['txid']==original['txid'] and baseline['transaction']['hex']==original['raw']
    cases=[]
    def addr(f,purpose,branch=0,index=0):
        path=f"m/{purpose}'/0'/0'/{branch}/{index}"
        return next(a for a in fixtures[f]['addresses'] if a['path']==path)
    def add(name,fixture,recipient,amount,coins=None,provenance='original canonical payout output; new withdrawal is a prospective model'):
        seed=bytes.fromhex(fixtures[fixture]['seed'])
        own,secret=M.native(seed,0,0);change,_=M.native(seed,1,0)
        assert own['script']==addr(fixture,84)['script_pub_key'] and change['script']==addr(fixture,84,1)['script_pub_key']
        if coins is None:
            index=next(i for i,p in enumerate(original['payments']) if p['script']==own['script'])
            coins=[dict(txid=original['txid'],index=index,atoms=original['payments'][index]['atoms'],script=own['script'])]
        model=M.prepare(coins,amount,recipient['script_pub_key'],change)
        draft,canonical,digest=wallet_draft(name,model,recipient,baseline)
        signed=M.sign(model,{own['script']:secret})
        assert signed['txid']==model['txid']
        cases.append(dict(name=name,fixture=fixture,provenance=provenance,request=dict(version=1,operation_id=draft['operation_id'],recipient=draft['recipient'],amount_atoms=amount),draft=draft,canonical_draft=canonical.decode(),draft_digest=digest,expected_signed=dict(version=1,operation_id=draft['operation_id'],draft_digest=digest,txid=signed['txid'],raw_hex=signed['raw_hex']),signed_sha256=signed['raw_sha256'],signature_evidence=signed['signatures']))
    for fixture,other in [('zero256','incrementing256'),('incrementing256','zero256')]:
        for purpose in [44,49,84,86]:
            add(f'{fixture}-original-to-{purpose}',fixture,addr(other,purpose),100000000)
        own=addr(fixture,84);coin=next(p for p in original['payments'] if p['script']==own['script_pub_key'])
        fee=M.estimated_fee(1,bytes.fromhex(addr(other,84)['script_pub_key']))
        for remainder in [0,1,293,294]:
            add(f'{fixture}-change-remainder-{remainder}',fixture,addr(other,84),coin['atoms']-fee-remainder)
    own=addr('zero256',84)
    for n in [1,2,3,15,16]:
        coins=[dict(txid=H(b'public synthetic Set68 outpoint:'+str(i).encode()),index=256 if i%2 else 1,atoms=1000000,script=own['script_pub_key']) for i in range(n)]
        # Require all supplied equally-valued coins without relying on their
        # input order; final BIP69 order is separately pinned by serialization.
        add(f'synthetic-{n}-inputs','zero256',addr('incrementing256',84),(n-1)*1000000+500000,coins,'synthetic owned UTXO serialization model; not a chain observation')
    recipient=addr('zero256',84,1)
    fee=M.estimated_fee(1,bytes.fromhex(recipient['script_pub_key']))
    coins=[dict(txid=H(b'public synthetic identical output roles'),index=0,atoms=200000000+fee,script=own['script_pub_key'])]
    add('identical-recipient-and-change','zero256',recipient,100000000,coins,'synthetic identical recipient/change serialization; not a chain observation')
    # Explicit tie ordering: displayed txid first and numeric vout, not LE
    # vout byte ordering. Extra smallest coin is not selected.
    tx=H(b'public synthetic same-parent ties')
    coins=[dict(txid=tx,index=i,atoms=1000000,script=own['script_pub_key']) for i in [256,1,2]]
    coins.append(dict(txid=H(b'public synthetic smaller'),index=0,atoms=1,script=own['script_pub_key']))
    add('same-parent-numeric-index-ties','zero256',addr('incrementing256',84),1500000,coins,'synthetic selection and BIP69 tie ordering; not a chain observation')
    add('same-parent-all-three-bip69','zero256',addr('incrementing256',84),2500000,coins,'synthetic final BIP69 vout1,2,256 ordering; not a chain observation')
    negative=[]
    positive=cases[2]
    mutations=[('wrong_amount',['amount_atoms'],positive['draft']['amount_atoms']+1),('wrong_recipient_index',['recipient_output_index'],1-positive['draft']['recipient_output_index']),('wrong_fee',['fee_atoms'],positive['draft']['fee_atoms']+1),('fee_exceeds_ceiling',['fee_atoms'],100001),('wrong_fee_rate',['fee_rate_atoms_per_kb'],1001),('wrong_version',['tx_version'],2),('nonfinal_sequence',['input_sequence'],4294967294),('wrong_locktime',['lock_time'],1),('wrong_sighash',['sighash_type'],2),('wrong_change_index',['change','output_index'],-1),('wrong_binding',['binding_id'],'0'*64),('wrong_input_scope_branch',['inputs',0,'branch'],2),('duplicate_outpoint',['inputs'],[positive['draft']['inputs'][0]]*2)]
    for name,path,value in mutations:
        d=copy.deepcopy(positive['draft']);target=d
        for part in path[:-1]:target=target[part]
        target[path[-1]]=value;negative.append(dict(name=name,draft=d,expected='reject'))
    raw=bytes.fromhex(positive['expected_signed']['raw_hex'])
    malformed=[('trailing_byte',raw+b'\x00'),('wrong_transaction_version',(2).to_bytes(4,'little')+raw[4:]),('truncated_witness',raw[:-5]+raw[-4:]),('changed_witness_pubkey',raw[:-5]+bytes([raw[-5]^1])+raw[-4:])]
    # First output starts after version, marker/flag, one count, native input,
    # and one output count for this exact one-input fixture.
    output_at=4+2+1+41+1
    changed=bytearray(raw);changed[output_at]^=1
    malformed.append(('changed_recipient_value',bytes(changed)))
    signed_negative=[dict(name=name,case=positive['name'],raw_hex=value.hex(),expected='reject') for name,value in malformed]
    return dict(version=1,scope='Public fixture unsigned/signed transactions independently derived before runtime outputs; synthetic cases explicitly labeled',cases=cases,negative_drafts=negative,negative_signed=signed_negative)

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():raise SystemExit('refuse to replace existing corpus')
    value=build();raw=json.dumps(value,indent=2,ensure_ascii=False).encode()+b'\n';a.output.write_bytes(raw)
    print(json.dumps(dict(cases=len(value['cases']),negative_drafts=len(value['negative_drafts']),bytes=len(raw),sha256=H(raw))))
if __name__=='__main__':main()
