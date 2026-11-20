"""Conservative byte arithmetic, executed ONLY by the guarded core generator.

Maximum-width witnesses deliberately need not be valid derivation/state data.
They prove encoding bounds, never capabilities or semantic reachability.
"""
from common import canonical, own, TIME_MAX, need
from allocation_model import DB_MAX, ROW_MAX, BATCH_MAX, wallet_guard


def sizes(example, binding):
    row=own(example['rows'][-1]);r=row['reservation'];req=r['request']
    # All variable scalar fields are independently widened to their allowed
    # lexical maximum. Address/hex fields cannot contain JSON escape characters.
    req.update(kind='withdrawal_change',consumer_id='f'*64,branch=1,
               withdrawal_binding_id='f'*64,recipient='a'*90,recipient_script='f'*68,
               amount_atoms=2100000000000000,fee_rate_atoms_per_kb=1000,
               fee_ceiling_atoms=100000,min_confirmations=1,input_purpose=84,
               change_purpose=84,account=0,tx_version=1,input_sequence=4294967295,
               lock_time=0,sighash_type=1)
    r.update(sequence=1024,allocation_id='f'*64,binding_id='f'*64,branch=1,
             start_index=3968,end_index=4096,selected_index=4095,
             invalid_indices=list(range(3968,4095)),address='a'*90,script='f'*44,
             reserved_at_ms=TIME_MAX)
    row.update(reservation_digest='f'*64,phase='consumed',completed_at_ms=TIME_MAX,
               wallet_record_digest='f'*64,draft_digest='f'*64)
    local=own(example['local_links'][-1]);local.update(sequence=1024,allocation_id='f'*64,
               outcome='consumed',branch=1,start_index=3968,end_index=4096,selected_index=4095,
               invalid_indices=list(range(3968,4095)),address='a'*90,script='f'*44,
               cursors_before=[4096]*8,cursors_after=[4096]*8,withdrawal_binding_id='f'*64,
               withdrawal_operation_id='f'*64,draft_digest='f'*64)
    meta=own(example['meta']);meta.update(revision=2048,allocations=1024,
               clock_high_water_ms=TIME_MAX,active_allocation_id='f'*64,cursors=[4096]*8)
    lm=own(example['local_meta']);lm.update(completed_sequence=1024,cursors=[4096]*8)
    marker=example['marker'];guard=wallet_guard(True,binding)
    lengths={k:len(canonical(v)) for k,v in [('request',req),('reservation',r),('row',row),
              ('local_link',local),('meta',meta),('local_meta',lm),('guard',guard),('marker',marker)]}
    lengths['host_terminal_batch']=len('allocation/')+64+lengths['row']+4+lengths['meta']
    lengths['host_1024_worst']=1024*(len('allocation/')+64+lengths['row'])+4+lengths['meta']
    lengths['local_1024_worst']=1024*(4+lengths['local_link'])+4+lengths['local_meta']+len('hostedallocationguard')+lengths['guard']+len('slug-hosted-allocation-v1')+len('records')
    for name,limit in [('request',2048),('row',ROW_MAX),('local_link',ROW_MAX),('meta',4096),
                       ('local_meta',2048),('guard',2048),('marker',8191),('host_terminal_batch',BATCH_MAX)]:
        need(lengths[name]<=limit,'size_'+name)
    # Independent caps: it is NOT required that all maximum rows fit at once.
    accounting=dict(per_inventory=16*1024*1024,two_inventories=32*1024*1024,
                    local_namespace_cap=DB_MAX,host_namespace_cap=DB_MAX,
                    host_old_and_staged_max=2*DB_MAX,
                    local_audit_reference_max=DB_MAX,
                    residual_metadata_work=4*1024*1024)
    need(accounting['host_old_and_staged_max']+accounting['local_audit_reference_max']+
         accounting['residual_metadata_work']==accounting['per_inventory'])
    return dict(scope='conservative core codec/working allowance only; helper wire separately bounded',
                witness_semantics='synthetic maximum-width composition, not a valid wallet/authority/derivation',
                encoded_bytes=lengths,limits=dict(rows=1024,store_bytes=DB_MAX,row_bytes=ROW_MAX,batch_bytes=BATCH_MAX),
                logical_working_allowance=accounting,
                disclaimer='Logical reservations are not a claim about total interpreter or Go heap usage.')
