"""Proposed Set72 ordered byte/state model. No I/O, account or opaque authority.

A derivation callback here is an independent reference-math seam ONLY, never
an implementation API or a caller attestation. Injected invalid-child cases
are explicitly labeled model faults by the generator.
"""
from common import Rejected, canonical, exact, hex64, integer, need, own, parse, sha, TIME_MAX
from public_derivation import address_for_script

BRANCH_MAX = 4096
ROWS_MAX = 1024
DB_MAX = 4194304
ROW_MAX = META_MAX = 4096
BATCH_MAX = 12288
BINDING = ('version','inventory_id','authority_id','account_id','principal_id','provision_id',
           'hosted_vault_id','retention_id','wallet_owner_id','source_binding_id','manager_schema',
           'max_allocations','max_bytes','max_plan_attempts','max_branch_index','initial_manifest')
MANIFEST = ('version','profile','network','genesis','derivation','scan_from_height','root_public_key',
            'gym_path','gym_public_key','gym_id','accounts')
ACCOUNT = ('purpose','coin','account','external_type','internal_type','next_external','next_internal')
REQUEST = ('version','kind','consumer_id','purpose','branch','withdrawal_binding_id','recipient',
           'recipient_script','amount_atoms','fee_rate_atoms_per_kb','fee_ceiling_atoms',
           'min_confirmations','input_purpose','change_purpose','account','tx_version',
           'input_sequence','lock_time','sighash_type')
RESERVATION = ('version','sequence','allocation_id','binding_id','request','purpose','branch',
               'start_index','end_index','selected_index','invalid_indices','address','script','reserved_at_ms')
ROW = ('reservation','reservation_digest','phase','completed_at_ms','wallet_record_digest','draft_digest')
MARKER = ('application','version','inventory_id','binding')
META = ('version','marker_sha256','revision','allocations','clock_high_water_ms','active_allocation_id','cursors')
GUARD = ('version','state','inventory_id','authority_id','account_id','wallet_owner_id',
         'source_binding_id','initial_manifest_sha256','binding_id')
LOCAL_META = ('version','guard_sha256','completed_sequence','cursors')
LINK = ('version','inventory_id','binding_id','sequence','allocation_id','reservation_digest',
        'request_digest','outcome','purpose','branch','start_index','end_index','selected_index',
        'invalid_indices','address','script','cursors_before','cursors_after','withdrawal_binding_id',
        'withdrawal_operation_id','draft_digest')
MONEY = 21000000*100000000


def limited(value, limit):
    need(len(canonical(value)) <= limit, 'capacity')
    return value


def domain(kind, value):
    return sha(('SLUG hosted allocation '+kind+'\x00v1\x00').encode()+canonical(value))


def initial_manifest(value, expected):
    out = exact(value, MANIFEST)
    need(out == expected and all(type(out[k]) is type(expected[k]) for k in MANIFEST), 'conflict')
    need(type(out['version']) is int and out['version'] == 1)
    need(type(out['accounts']) is list and len(out['accounts']) == 4)
    accounts = []
    for purpose, row in zip((44,49,84,86), out['accounts']):
        row = exact(row, ACCOUNT)
        need(type(row['purpose']) is int and row['purpose'] == purpose)
        for k in ('coin','account','next_external','next_internal'):
            integer(row[k],0,0)
        accounts.append(row)
    out['accounts'] = accounts
    return limited(out,4096)


def binding(value, expected_manifest):
    out = exact(value,BINDING)
    integer(out['version'],1,1)
    for k in BINDING[1:10]:
        hex64(out[k],True)
    for k,want in zip(BINDING[10:15],(13,1024,4194304,128,4096)):
        integer(out[k],want,want)
    out['initial_manifest'] = initial_manifest(out['initial_manifest'],expected_manifest)
    return out


def cursors(value):
    need(type(value) is list and len(value)==8)
    for x in value:
        integer(x,0,BRANCH_MAX)
    need(all(value[i]==0 for i in (0,1,2,3,6,7)), 'conflict')
    return list(value)


def payment_script(script):
    need(type(script) is str and len(script)%2==0 and script==script.lower())
    try:
        raw=bytes.fromhex(script)
    except ValueError:
        raise Rejected('invalid')
    need(raw.hex()==script)
    valid=((len(raw)==25 and raw[:3]==b'\x76\xa9\x14' and raw[-2:]==b'\x88\xac') or
           (len(raw)==23 and raw[:2]==b'\xa9\x14' and raw[-1:]==b'\x87') or
           (len(raw)==22 and raw[:2]==b'\x00\x14') or (len(raw)==34 and raw[:2]==b'\x51\x20'))
    need(valid)
    return raw


def request(value, allocation_id):
    out=exact(value,REQUEST)
    integer(out['version'],1,1);hex64(out['consumer_id'],True);hex64(allocation_id,True)
    integer(out['purpose'],84,84)
    need(out['kind'] in ('pool_recipient','receive','withdrawal_change'))
    if out['kind']!='withdrawal_change':
        integer(out['branch'],0,0);need(out['consumer_id']==allocation_id,'conflict')
        need(all(out[k]=='' for k in ('withdrawal_binding_id','recipient','recipient_script')))
        for k in REQUEST[8:]:integer(out[k],0,0)
    else:
        integer(out['branch'],1,1);hex64(out['withdrawal_binding_id'],True)
        need(type(out['recipient']) is str and 1<=len(out['recipient'])<=90 and out['recipient'].isascii())
        raw=payment_script(out['recipient_script'])
        need(out['recipient']==address_for_script(raw),'conflict')
        integer(out['amount_atoms'],1,MONEY)
        dust=3*(8+1+len(raw)+41+(107//4 if raw[:2] in (b'\x00\x14',b'\x51\x20') else 107))
        need(out['amount_atoms']>=dust)
        for k,want in zip(REQUEST[9:],(1000,100000,1,84,84,0,1,4294967295,0,1)):
            integer(out[k],want,want)
    return limited(out,2048)


def reservation(value, expected_binding, derive):
    out=exact(value,RESERVATION)
    integer(out['version'],1,1);integer(out['sequence'],1,ROWS_MAX)
    hex64(out['allocation_id'],True)
    need(out['binding_id']==domain('binding',expected_binding),'conflict')
    out['request']=request(out['request'],out['allocation_id'])
    integer(out['purpose'],84,84);integer(out['branch'],0,1)
    need((out['purpose'],out['branch'])==(out['request']['purpose'],out['request']['branch']),'conflict')
    integer(out['start_index'],0,BRANCH_MAX-1);integer(out['end_index'],1,BRANCH_MAX)
    need(out['start_index']<out['end_index']<=out['start_index']+128)
    integer(out['selected_index'],out['end_index']-1,out['end_index']-1)
    need(type(out['invalid_indices']) is list and len(out['invalid_indices'])<=127)
    for index in out['invalid_indices']:integer(index,0,BRANCH_MAX-1)
    need(out['invalid_indices']==list(range(out['start_index'],out['selected_index'])),'conflict')
    for index in out['invalid_indices']:need(derive(out['branch'],index) is None,'conflict')
    expected=derive(out['branch'],out['selected_index'])
    need(expected is not None and (out['address'],out['script'])==expected,'conflict')
    need(type(out['address']) is str and out['address'].isascii() and len(out['address'])<=90)
    need(type(out['script']) is str and len(out['script'])==44 and out['script'].startswith('0014'))
    if out['request']['kind']=='pool_recipient':
        need(out['sequence']==1 and out['start_index']==out['selected_index']==0,'conflict')
    else:
        need(out['sequence']>1,'conflict')
        if out['request']['kind']=='receive':need(out['start_index']>=1,'conflict')
    integer(out['reserved_at_ms'],1,TIME_MAX)
    return out


def local_link(value, res, expected_binding, before):
    out=exact(value,LINK)
    integer(out['version'],1,1)
    need(out['inventory_id']==expected_binding['inventory_id'] and out['binding_id']==res['binding_id'],'conflict')
    for k in ('sequence','allocation_id','purpose','branch','start_index','end_index','selected_index','invalid_indices','address','script'):
        need(type(out[k]) is type(res[k]) and out[k]==res[k],'conflict')
    need(out['reservation_digest']==domain('reservation',res),'conflict')
    need(out['request_digest']==domain('request',res['request']),'conflict')
    need(out['outcome'] in ('consumed','burned'))
    out['cursors_before']=cursors(out['cursors_before']);out['cursors_after']=cursors(out['cursors_after'])
    need(out['cursors_before']==before,'conflict')
    after=list(before);slot=4+res['branch'];need(after[slot]==res['start_index'],'conflict');after[slot]=res['end_index']
    need(out['cursors_after']==after,'conflict')
    req=res['request']
    if req['kind']=='withdrawal_change':
        need(out['withdrawal_binding_id']==req['withdrawal_binding_id'] and out['withdrawal_operation_id']==req['consumer_id'],'conflict')
        if out['outcome']=='consumed':hex64(out['draft_digest'])
        else:need(out['draft_digest']=='')
    else:need(all(out[k]=='' for k in ('withdrawal_binding_id','withdrawal_operation_id','draft_digest')))
    return limited(out,ROW_MAX)


def wallet_guard(bound, b):
    return dict(version=1,state='bound' if bound else 'locked',inventory_id=b['inventory_id'],
                authority_id=b['authority_id'],account_id=b['account_id'],wallet_owner_id=b['wallet_owner_id'],
                source_binding_id=b['source_binding_id'],initial_manifest_sha256=sha(canonical(b['initial_manifest'])),
                binding_id=domain('binding',b) if bound else '')


class AllocationModel:
    def __init__(self, b, derive):
        self.binding=binding(b,b['initial_manifest']);self.derive=derive
        self.rows=[];self.links=[];self.clock=0

    def marker(self):
        return dict(application='slug-hosted-allocation-inventory',version=1,inventory_id=self.binding['inventory_id'],binding=own(self.binding))

    def meta(self, rows=None):
        rows=self.rows if rows is None else rows
        ceilings=[0]*8;clock=0;active='';terminal=0
        for row in rows:
            r=row['reservation'];ceilings[4+r['branch']]=r['end_index']
            clock=max(clock,r['reserved_at_ms'],row['completed_at_ms'])
            if row['phase']=='reserved':active=r['allocation_id']
            else:terminal+=1
        return dict(version=1,marker_sha256=sha(canonical(self.marker())),revision=len(rows)+terminal,
                    allocations=len(rows),clock_high_water_ms=clock,active_allocation_id=active,cursors=ceilings)

    def local_meta(self, links=None):
        links=self.links if links is None else links
        return dict(version=1,guard_sha256=domain('wallet guard',wallet_guard(True,self.binding)),
                    completed_sequence=len(links),cursors=own(links[-1]['cursors_after']) if links else [0]*8)

    def database_bytes(self, rows=None):
        rows=self.rows if rows is None else rows
        return 4+len(canonical(self.meta(rows)))+sum(len('allocation/')+64+len(canonical(r)) for r in rows)

    def local_bytes(self, links=None):
        links=self.links if links is None else links
        return len('hostedallocationguard')+len(canonical(wallet_guard(True,self.binding)))+len('slug-hosted-allocation-v1')+len('records')+4+len(canonical(self.local_meta(links)))+sum(4+len(canonical(x)) for x in links)

    def check_capacity(self, rows, links):
        need(len(rows)<=ROWS_MAX and len(links)<=ROWS_MAX,'capacity')
        for row in rows:limited(row,ROW_MAX)
        for link in links:limited(link,ROW_MAX)
        limited(self.meta(rows),META_MAX);limited(self.local_meta(links),2048)
        need(self.database_bytes(rows)<=DB_MAX and self.local_bytes(links)<=DB_MAX,'capacity')
        if rows:need(len('allocation/')+64+len(canonical(rows[-1]))+4+len(canonical(self.meta(rows)))<=BATCH_MAX,'capacity')

    def reserve(self, allocation_id, req, now):
        req=request(req,allocation_id);integer(now,1,TIME_MAX)
        for row in self.rows:
            r=row['reservation']
            if r['allocation_id']==allocation_id:
                need(r['request']==req,'conflict');return own(row),False
            need((r['request']['kind'],r['request']['consumer_id'])!=(req['kind'],req['consumer_id']),'conflict')
        need(now>=self.clock,'clock')
        need(not self.meta()['active_allocation_id'],'busy');need(len(self.rows)<ROWS_MAX,'capacity')
        start=self.meta()['cursors'][4+req['branch']];selected=None
        for index in range(start,min(start+128,BRANCH_MAX)):
            address=self.derive(req['branch'],index)
            if address is not None:selected=(index,address);break
        need(selected is not None,'capacity')
        index,(address,script)=selected
        r=dict(version=1,sequence=len(self.rows)+1,allocation_id=allocation_id,binding_id=domain('binding',self.binding),
               request=req,purpose=84,branch=req['branch'],start_index=start,end_index=index+1,selected_index=index,
               invalid_indices=list(range(start,index)),address=address,script=script,reserved_at_ms=now)
        r=reservation(r,self.binding,self.derive)
        row=dict(reservation=r,reservation_digest=domain('reservation',r),phase='reserved',completed_at_ms=0,wallet_record_digest='',draft_digest='')
        # Precharge the legal maximum terminal row and local link BEFORE reserve.
        draft='f'*64 if req['kind']=='withdrawal_change' else ''
        future=self.make_link(r,'consumed',draft)
        terminal=own(row);terminal.update(phase='consumed',completed_at_ms=TIME_MAX,wallet_record_digest='f'*64,draft_digest=draft)
        self.check_capacity(self.rows+[terminal],self.links+[future])
        self.check_capacity(self.rows+[row],self.links)
        self.rows.append(row);self.clock=now
        return own(row),True

    def make_link(self, res, outcome, draft):
        before=self.local_meta()['cursors'];after=list(before);after[4+res['branch']]=res['end_index']
        req=res['request'];payment=req['kind']=='withdrawal_change'
        value=dict(version=1,inventory_id=self.binding['inventory_id'],binding_id=res['binding_id'],
                   sequence=res['sequence'],allocation_id=res['allocation_id'],reservation_digest=domain('reservation',res),
                   request_digest=domain('request',req),outcome=outcome,purpose=res['purpose'],branch=res['branch'],
                   start_index=res['start_index'],end_index=res['end_index'],selected_index=res['selected_index'],
                   invalid_indices=own(res['invalid_indices']),address=res['address'],script=res['script'],
                   cursors_before=before,cursors_after=after,withdrawal_binding_id=req['withdrawal_binding_id'] if payment else '',
                   withdrawal_operation_id=req['consumer_id'] if payment else '',draft_digest=draft)
        return local_link(value,res,self.binding,before)

    def consume(self, allocation_id, outcome='consumed', draft=''):
        need(outcome in ('consumed','burned'))
        row=next((x for x in self.rows if x['reservation']['allocation_id']==allocation_id),None)
        need(row is not None,'not_found');r=row['reservation']
        for old in self.links:
            if old['allocation_id']==allocation_id:
                need(old['outcome']==outcome and old['draft_digest']==draft,'conflict');return own(old),False
        need(row['phase']=='reserved' and r['sequence']==len(self.links)+1,'conflict')
        link=self.make_link(r,outcome,draft);self.check_capacity(self.rows,self.links+[link])
        self.links.append(link);return own(link),True

    def acknowledge(self, allocation_id, now):
        integer(now,1,TIME_MAX)
        row=next((x for x in self.rows if x['reservation']['allocation_id']==allocation_id),None)
        link=next((x for x in self.links if x['allocation_id']==allocation_id),None)
        need(row is not None and link is not None,'not_found')
        digest=domain('wallet record',link)
        if row['phase']!='reserved':
            need(row['wallet_record_digest']==digest and row['phase']==link['outcome'],'conflict');return own(row),False
        need(now>=self.clock,'clock')
        out=own(row);out.update(phase=link['outcome'],completed_at_ms=now,wallet_record_digest=digest,draft_digest=link['draft_digest'])
        staged=own(self.rows);staged[-1]=out;self.check_capacity(staged,self.links)
        self.rows=staged;self.clock=now;return own(out),True

    def head(self):
        meta=self.meta();value=own(self.binding['initial_manifest'])
        for i,row in enumerate(value['accounts']):
            row['next_external'],row['next_internal']=meta['cursors'][2*i:2*i+2]
        return dict(binding_id=domain('binding',self.binding),revision=meta['revision'],cursors=meta['cursors'],manifest=value,manifest_sha256=sha(canonical(value)))

    def snapshot(self):
        return dict(marker=self.marker(),meta=self.meta(),rows=own(self.rows),guard=wallet_guard(True,self.binding),
                    local_meta=self.local_meta(),local_links=own(self.links),head=self.head())


def audit(snapshot, expected_binding, derive, with_wallet=True):
    need(type(snapshot) is dict)
    need(snapshot['marker']==AllocationModel(expected_binding,derive).marker(),'conflict')
    rows=snapshot['rows'];need(type(rows) is list and len(rows)<=ROWS_MAX,'capacity')
    model=AllocationModel(expected_binding,derive);last=0;seen=set();consumers=set()
    links=snapshot.get('local_links',[]) if with_wallet else []
    if with_wallet:need(type(links) is list and len(links)<=len(rows),'conflict')
    for i,value in enumerate(rows):
        row=exact(value,ROW);limited(row,ROW_MAX)
        r=reservation(row['reservation'],expected_binding,derive);row['reservation']=r
        need(r['sequence']==i+1 and r['allocation_id'] not in seen,'conflict');seen.add(r['allocation_id'])
        consumer=(r['request']['kind'],r['request']['consumer_id']);need(consumer not in consumers,'conflict');consumers.add(consumer)
        need(r['start_index']==model.meta()['cursors'][4+r['branch']],'conflict')
        need(r['reserved_at_ms']>=last,'clock');last=r['reserved_at_ms']
        need(row['reservation_digest']==domain('reservation',r),'conflict')
        need(row['phase'] in ('reserved','consumed','burned'))
        if row['phase']=='reserved':
            integer(row['completed_at_ms'],0,0)
            need(i==len(rows)-1 and row['completed_at_ms']==0 and row['wallet_record_digest']==row['draft_digest']=='','conflict')
        else:
            integer(row['completed_at_ms'],last,TIME_MAX);last=row['completed_at_ms'];hex64(row['wallet_record_digest'])
            if row['phase']=='consumed' and r['request']['kind']=='withdrawal_change':hex64(row['draft_digest'])
            else:need(row['draft_digest']=='')
        if with_wallet:
            if i<len(links):
                link=local_link(links[i],r,expected_binding,model.local_meta()['cursors'])
                if row['phase']!='reserved':need(domain('wallet record',link)==row['wallet_record_digest'] and link['outcome']==row['phase'] and link['draft_digest']==row['draft_digest'],'conflict')
                model.links.append(link)
            else:need(row['phase']=='reserved','conflict')
        model.rows.append(row)
    model.clock=last
    need(canonical(exact(snapshot['meta'],META))==canonical(model.meta()),'conflict')
    if with_wallet:
        need(canonical(exact(snapshot['guard'],GUARD))==canonical(wallet_guard(True,expected_binding)),'conflict')
        need(canonical(exact(snapshot['local_meta'],LOCAL_META))==canonical(model.local_meta()),'conflict')
    model.check_capacity(model.rows,model.links)
    need(snapshot['head']==model.head(),'conflict')
    return model


def decode_row(raw, expected_binding, derive):
    value,checked_raw=parse(raw,ROW_MAX)
    row=exact(value,ROW);row['reservation']=reservation(row['reservation'],expected_binding,derive)
    need(canonical(row)==checked_raw)
    return row
