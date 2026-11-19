"""Independent integer cryptography and wire serialization; public fixture keys only.
No project/runtime imports. Ed25519 (RFC8032), secp256k1/RFC6979 and BIP143.
"""
import hashlib,hmac,struct
from functools import lru_cache
H=lambda b:hashlib.sha256(b).digest()
D=lambda b:H(H(b))
u32=lambda n:struct.pack('<I',n)
u64=lambda n:struct.pack('<Q',n)
def varint(n):
    assert 0<=n<2**64
    return bytes([n]) if n<253 else b'\xfd'+struct.pack('<H',n) if n<65536 else b'\xfe'+u32(n) if n<2**32 else b'\xff'+u64(n)
def blob(b):return varint(len(b))+b
# Extended Edwards coordinates: formulas operate only over this fixed field.
Q=2**255-19;L=2**252+27742317777372353535851937790883648493
ED_D=(-121665*pow(121666,Q-2,Q))%Q;SQRT_M1=pow(2,(Q-1)//4,Q)
def ed_recover(y,sign):
    if y>=Q:raise ValueError('noncanonical point')
    xx=(y*y-1)*pow(ED_D*y*y+1,Q-2,Q)%Q;x=pow(xx,(Q+3)//8,Q)
    if x*x%Q!=xx:x=x*SQRT_M1%Q
    if x*x%Q!=xx or (x==0 and sign):raise ValueError('not curve point')
    if x&1!=sign:x=Q-x
    return (x,y,1,x*y%Q)
ED_BASE=ed_recover(4*pow(5,Q-2,Q)%Q,0);ED_ZERO=(0,1,1,0)
def ed_add(p,q):
    x,y,z,t=p;X,Y,Z,T=q;a=(y-x)*(Y-X)%Q;b=(y+x)*(Y+X)%Q;c=2*ED_D*t*T%Q;d=2*z*Z%Q
    e=(b-a)%Q;f=(d-c)%Q;g=(d+c)%Q;h=(b+a)%Q
    return(e*f%Q,g*h%Q,f*g%Q,e*h%Q)
def ed_mul(p,n):
    r=ED_ZERO
    while n:
        if n&1:r=ed_add(r,p)
        p=ed_add(p,p);n>>=1
    return r
def ed_enc(p):
    x,y,z,t=p;i=pow(z,Q-2,Q);x=x*i%Q;y=y*i%Q
    return (y|((x&1)<<255)).to_bytes(32,'little')
def ed_dec(b):
    if len(b)!=32:raise ValueError('point length')
    n=int.from_bytes(b,'little');return ed_recover(n&((1<<255)-1),n>>255)
def ed_parts(seed):
    assert len(seed)==32;a=bytearray(hashlib.sha512(seed).digest());a[0]&=248;a[31]&=63;a[31]|=64
    return int.from_bytes(a[:32],'little'),bytes(a[32:])
@lru_cache(maxsize=8)
def ed_public(seed):return ed_enc(ed_mul(ED_BASE,ed_parts(seed)[0]))
@lru_cache(maxsize=512)
def ed_sign(seed,message):
    a,prefix=ed_parts(seed);pub=ed_public(seed);r=int.from_bytes(hashlib.sha512(prefix+message).digest(),'little')%L;R=ed_enc(ed_mul(ED_BASE,r));k=int.from_bytes(hashlib.sha512(R+pub+message).digest(),'little')%L
    return R+((r+k*a)%L).to_bytes(32,'little')
@lru_cache(maxsize=1024)
def ed_verify(pub,msg,sig):
    try:
        if len(sig)!=64:return False
        A=ed_dec(pub);R=ed_dec(sig[:32]);s=int.from_bytes(sig[32:],'little')
        if s>=L or ed_enc(ed_mul(A,L))!=ed_enc(ED_ZERO) or ed_enc(ed_mul(A,8))==ed_enc(ED_ZERO):return False
        k=int.from_bytes(hashlib.sha512(sig[:32]+pub+msg).digest(),'little')%L
        return ed_enc(ed_mul(ED_BASE,s))==ed_enc(ed_add(R,ed_mul(A,k)))
    except(ValueError,ZeroDivisionError):return False
P=2**256-2**32-977;N=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
G=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
def add(p,q):
    if p is None:return q
    if q is None:return p
    x,y=p;X,Y=q
    if x==X and (y+Y)%P==0:return None
    slope=((3*x*x)*pow(2*y,P-2,P) if p==q else (Y-y)*pow(X-x,P-2,P))%P
    z=(slope*slope-x-X)%P;return(z,(slope*(x-z)-y)%P)
def mul(n,p=G):
    r=None
    while n:
        if n&1:r=add(r,p)
        p=add(p,p);n>>=1
    return r
def compressed(p):return bytes([2|(p[1]&1)])+p[0].to_bytes(32,'big')
def pubkey(secret):return compressed(mul(secret))
def hash160(b):return hashlib.new('ripemd160',H(b)).digest()
def rfc6979(secret,digest):
    z=(int.from_bytes(digest,'big')%N).to_bytes(32,'big');x=secret.to_bytes(32,'big');v=b'\x01'*32;k=b'\0'*32
    f=lambda k,x:hmac.new(k,x,hashlib.sha256).digest()
    k=f(k,v+b'\0'+x+z);v=f(k,v);k=f(k,v+b'\x01'+x+z);v=f(k,v)
    while True:
        v=f(k,v);candidate=int.from_bytes(v,'big')
        if 1<=candidate<N:return candidate
        k=f(k,v+b'\0');v=f(k,v)
def der_num(n):
    b=n.to_bytes((n.bit_length()+7)//8,'big') or b'\0'
    if b[0]&128:b=b'\0'+b
    return b'\x02'+bytes([len(b)])+b
@lru_cache(maxsize=512)
def sign(secret,digest):
    k=rfc6979(secret,digest);r=mul(k)[0]%N;s=(pow(k,N-2,N)*(int.from_bytes(digest,'big')+r*secret))%N
    assert r and s;s=min(s,N-s);d=der_num(r)+der_num(s)
    return b'\x30'+bytes([len(d)])+d,r,s,k
@lru_cache(maxsize=512)
def verify(public,digest,r,s):
    if not(1<=r<N and 1<=s<N):return False
    w=pow(s,N-2,N);p=add(mul(int.from_bytes(digest,'big')*w%N),mul(r*w%N,public));return p is not None and p[0]%N==r
def outpoint(txid,index):return bytes.fromhex(txid)[::-1]+u32(index)
def txout(amount,script):return u64(amount)+blob(script)
def publication(coin,event_key,declaration_id):
    payload=b'SLUGSEED'+b'\x01'+bytes.fromhex(event_key)+bytes.fromhex(declaration_id)
    assert len(payload)==73
    carrier=b'\x6a\x49'+payload;pub=pubkey(1);keyhash=hash160(pub);change=b'\x00\x14'+keyhash
    assert bytes.fromhex(coin['script'])==change and coin['value_satoshis']>=1294
    op=outpoint(coin['outpoint']['txid'],coin['outpoint']['index']);seq=u32(0xffffffff)
    outputs=txout(0,carrier)+txout(coin['value_satoshis']-1000,change)
    scriptcode=b'\x76\xa9\x14'+keyhash+b'\x88\xac'
    pre=u32(2)+D(op)+D(seq)+op+blob(scriptcode)+u64(coin['value_satoshis'])+seq+D(outputs)+u32(0)+u32(1)
    dg=D(pre);sig,r,s,k=sign(1,dg);assert verify(G,dg,r,s)
    stripped=u32(2)+b'\x01'+op+b'\x00'+seq+b'\x02'+outputs+u32(0)
    witness=b'\x02'+blob(sig+b'\x01')+blob(pub)
    raw=u32(2)+b'\x00\x01'+stripped[4:-4]+witness+u32(0)
    return {'payload':payload.hex(),'carrier_script':carrier.hex(),'script_code':scriptcode.hex(),'bip143_preimage':pre.hex(),'bip143_digest':dg.hex(),'rfc6979_nonce':hex(k)[2:].zfill(64),'signature_der':sig.hex(),'signature_r':hex(r)[2:].zfill(64),'signature_s':hex(s)[2:].zfill(64),'stripped':stripped.hex(),'raw_tx':raw.hex(),'txid':D(stripped)[::-1].hex(),'wtxid':D(raw)[::-1].hex(),'raw_tx_digest':H(raw).hex()}
def merkle(txids,index=0):
    row=[bytes.fromhex(x)[::-1] for x in txids];branch=[];i=index
    assert row and 0<=i<len(row)
    while len(row)>1:
        if len(row)&1:row.append(row[-1])
        branch.append(row[i^1][::-1].hex());row=[D(row[j]+row[j+1]) for j in range(0,len(row),2)];i//=2
    return row[0][::-1].hex(),branch
def verify_merkle(txid,index,count,branch,root):
    if not(1<=count<=1000000 and 0<=index<count):return False
    h=bytes.fromhex(txid);i=index;n=count
    for b in branch:
        if n<=1:return False
        sibling=bytes.fromhex(b)
        if i==n-1 and n&1 and sibling!=h:return False
        h=D((sibling[::-1]+h[::-1]) if i&1 else (h[::-1]+sibling[::-1]))[::-1];i//=2;n=(n+1)//2
    return n==1 and h.hex()==root

def selftest():
    seed=bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
    pub=bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
    sig=bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
    assert ed_public(seed)==pub and ed_sign(seed,b'')==sig and ed_verify(pub,b'',sig) and not ed_verify(pub,b'x',sig)
    assert pubkey(1).hex()=='0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    for msg in [b'',b'Set45 independent public fixture',bytes(range(256))]:
        d=H(msg);s,r,v,k=sign(1,d);assert verify(G,d,r,v) and v<=N//2 and not verify(G,H(msg+b'x'),r,v)
if __name__=='__main__':selftest();print('independent crypto self-check passed')

class Reader:
 def __init__(self,b):self.b=b;self.p=0
 def take(self,n):
  if n<0 or self.p+n>len(self.b):raise ValueError('short wire')
  r=self.b[self.p:self.p+n];self.p+=n;return r
 def num(self,n):return int.from_bytes(self.take(n),'little')
 def vi(self):
  n=self.num(1)
  if n<253:return n
  width={253:2,254:4,255:8}[n];v=self.num(width)
  if v<{253:253,254:65536,255:2**32}[n]:raise ValueError('nonminimal varint')
  return v
 def string(self):return self.take(self.vi())
def parse_tx(reader):
 start=reader.p;version=reader.num(4);n=reader.vi();witness=False
 if n==0:
  if reader.num(1)!=1:raise ValueError('witness flag')
  witness=True;n=reader.vi()
 if not(1<=n<=1000000):raise ValueError('input count')
 inputs=[];ins=[]
 for _ in range(n):
  h=reader.take(32);i=reader.num(4);script=reader.string();seq=reader.num(4);ins.append(h+u32(i)+blob(script)+u32(seq));inputs.append(dict(txid=h[::-1].hex(),index=i,script=script.hex(),sequence=seq))
 no=reader.vi()
 if not(1<=no<=1000000):raise ValueError('output count')
 outputs=[];outs=[]
 for _ in range(no):
  value=reader.num(8);script=reader.string();outputs.append(dict(value=value,script=script.hex()));outs.append(txout(value,script))
 witnesses=[]
 if witness:
  for _ in range(n):
   count=reader.vi()
   if count>1000000:raise ValueError('witness count')
   witnesses.append([reader.string().hex() for _ in range(count)])
  if not any(witnesses):raise ValueError('superfluous witness encoding')
 locktime=reader.num(4);stripped=u32(version)+varint(n)+b''.join(ins)+varint(no)+b''.join(outs)+u32(locktime);full=reader.b[start:reader.p]
 return dict(version=version,inputs=inputs,outputs=outputs,witness=witnesses,locktime=locktime,raw=full,stripped=stripped,txid=D(stripped)[::-1].hex(),wtxid=D(full)[::-1].hex())
def parse_block(data):
 if not(81<=len(data)<=4000000):raise ValueError('block byte bound')
 r=Reader(data);header=r.take(80);n=r.vi()
 if not(1<=n<=1000000):raise ValueError('tx count')
 txs=[parse_tx(r)for _ in range(n)]
 if r.p!=len(data):raise ValueError('block trailing bytes')
 root,_=merkle([x['txid'] for x in txs])
 if root!=header[36:68][::-1].hex():raise ValueError('block merkle')
 if any(x['witness'] for x in txs):
  commitments=[bytes.fromhex(x['script'])[6:38]for x in txs[0]['outputs']if x['script'].startswith('6a24aa21a9ed')and len(x['script'])>=76]
  w=txs[0]['witness']
  if not commitments or len(w)!=1 or len(w[0])!=1 or len(w[0][0])!=64:raise ValueError('coinbase witness')
  wr,_=merkle(['00'*32]+[x['wtxid'] for x in txs[1:]])
  if commitments[-1]!=D(bytes.fromhex(wr)[::-1]+bytes.fromhex(w[0][0])):raise ValueError('witness commitment')
 return header,txs
