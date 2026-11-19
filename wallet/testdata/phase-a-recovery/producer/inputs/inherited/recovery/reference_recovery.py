#!/usr/bin/env python3
"""Independent fixed-profile fixture generation; imports no SLUG Go code."""
import hashlib,json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'oracle'))
import reference as r
GYM_PATH="m/1397511495'/1'/0'"

def tagged_hash(tag,data):
 h=r.sha256(tag.encode());return r.sha256(h+h+data)

def witness(version,program,hrp="slug"):
 data=[version];acc=bits=0
 for b in program:
  acc=(acc<<8)|b;bits+=8
  while bits>=5:
   bits-=5;data.append((acc>>bits)&31)
 if bits:data.append((acc<<(5-bits))&31)
 expanded=[ord(c)>>5 for c in hrp]+[0]+[ord(c)&31 for c in hrp]
 check=r.polymod(expanded+data+[0]*6)^(1 if version==0 else 0x2bc830a3)
 return hrp+'1'+''.join(r.BECH32[v] for v in data+[(check>>(5*(5-i)))&31 for i in range(6)])

def address(key,purpose,branch):
 pub=r.public_key(key.scalar);payload=r.hash160(pub)
 if purpose==44:return r.base58check(b'\x53'+payload),'76a914'+payload.hex()+'88ac'
 if purpose==49 and branch==0:
  redeem=b'\x00\x14'+payload;h=r.hash160(redeem)
  return r.base58check(b'\x47'+h),'a914'+h.hex()+'87'
 if purpose==86:
  x,y=r.point_multiply(key.scalar)
  if y&1:y=r.P-y
  tweak=int.from_bytes(tagged_hash('TapTweak',x.to_bytes(32,'big')),'big')
  if tweak>=r.N:raise ValueError('invalid taproot tweak')
  out=r.point_add((x,y),r.point_multiply(tweak)) if tweak else (x,y)
  program=out[0].to_bytes(32,'big')
  return witness(1,program),'5120'+program.hex()
 return witness(0,payload),'0014'+payload.hex()

def verify_bip86():
 text=(ROOT/'oracle/sources/bip-0086.mediawiki').read_text()
 phrase=re.search(r'mnemonic = (.+)',text).group(1)
 seed=r.mnemonic_to_seed(phrase,'')
 cases=re.findall(r"address = (m/[^\n]+)\n(?:[^\n]*\n)*?internal_key = (\w+)\noutput_key   = (\w+)\nscriptPubKey = (\w+)\naddress      = (\w+)",text)
 if len(cases)!=3:raise AssertionError('BIP86 vector count')
 for path,internal,output,script,expected_address in cases:
  key=r.derive_path(seed,path)
  if r.public_key(key.scalar)[1:].hex()!=internal:raise AssertionError('BIP86 internal key')
  _,derived_script=address(key,86,0)
  if derived_script!=script or script!='5120'+output:raise AssertionError('BIP86 tweak/script')
  if witness(1,bytes.fromhex(output),'bc')!=expected_address:raise AssertionError('BIP86 address')

def generate():
 r.verify_official_vectors()
 verify_bip86()
 cases=[]
 for name,entropy in [('zero256',bytes(32)),('incrementing256',bytes(range(32))),('official-leading-zero-account',bytes.fromhex('68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c'))]:
  phrase=r.mnemonic_from_entropy(entropy);seed=r.mnemonic_to_seed(phrase,'')
  gym=r.gym_identity(seed,GYM_PATH,r.SLUG_NETWORK,r.SLUG_GENESIS)
  accounts=[];keys=[]
  for purpose,external,internal in [(44,'p2pkh','p2pkh'),(49,'p2sh-p2wpkh','p2wpkh'),(84,'p2wpkh','p2wpkh'),(86,'p2tr','p2tr')]:
   accounts.append({'purpose':purpose,'coin':0,'account':0,'external_type':external,'internal_type':internal,'next_external':26 if purpose==84 else 0,'next_internal':27 if purpose==84 else 0})
   for branch,index in [(0,0),(1,0)]+([(0,25),(1,26)] if purpose==84 else []):
    path=f"m/{purpose}'/0'/0'/{branch}/{index}"
    key=r.derive_path(seed,path);addr,script=address(key,purpose,branch)
    keys.append({'path':path,'public_key':r.public_key(key.scalar).hex(),'address':addr,'script_pub_key':script})
  manifest={'version':1,'profile':'slug-phase-a-fixture-bip39-v1','network':r.SLUG_NETWORK,'genesis':r.SLUG_GENESIS,'derivation':'bip32-standard-v1','scan_from_height':0,'root_public_key':r.ExtendedPrivate.master(seed).serialize(True,True),'gym_path':GYM_PATH,'gym_public_key':gym['public_key'],'gym_id':gym['gym_id'],'accounts':accounts}
  cases.append({'name':name,'entropy':entropy.hex(),'seed':seed.hex(),'export':{'version':1,'mnemonic':phrase,'manifest':manifest},'addresses':keys})
 return {'fixture_only':True,'cases':cases}

if __name__=='__main__':
 expected=json.dumps(generate(),indent=2)+'\n';path=ROOT/'recovery_v1.json'
 if sys.argv[1:]==['--check']:
  if path.read_text()!=expected:raise SystemExit('recovery fixture differs')
  print('Independent BIP39/BIP32 checks and three fixed-profile recovery fixtures passed.')
 elif not sys.argv[1:]:path.write_text(expected)
 else:raise SystemExit('usage: reference_recovery.py [--check]')
