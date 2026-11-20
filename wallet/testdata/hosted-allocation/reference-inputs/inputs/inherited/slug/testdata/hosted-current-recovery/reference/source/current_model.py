"""Ordered current-recovery bytes and deterministic CAS model, never a capability."""
from common import (Rejected, canonical, exact, hex64, integer, need, own,
                    packed, parse, sha, text, TIME_MAX)

MANIFEST = ('version','profile','network','genesis','derivation','scan_from_height',
            'root_public_key','gym_path','gym_public_key','gym_id','accounts')
ACCOUNT = ('purpose','coin','account','external_type','internal_type','next_external','next_internal')
BINDING = ('version','authority_id','account_id','principal_id','provision_id','network',
           'genesis','profile','root_public_key','gym_public_key','gym_id')
CURRENT = ('version','hosted_vault_id','vault_binding','retention_id','wallet_owner_id','source_binding_id')
CHECKPOINT = ('version','binding','revision','capture_id','expected_revision','captured_at_ms',
              'committed_at_ms','manifest','manifest_sha256')
REQUEST = ('binding','capture_id','expected_revision','captured_at_ms','manifest')
MARKER = ('application','version','bindings')
META = ('version','marker_sha256','actions','clock_high_water_ms','current')
POINTER = ('account_id','revision','capture_id')


def manifest(value, original):
    out = exact(value, MANIFEST)
    need(out['version'] == 1 and type(out['version']) is int)
    need(type(out['accounts']) is list and len(out['accounts']) == 4)
    for key in MANIFEST[:-1]:
        need(out[key] == original[key] and type(out[key]) is type(original[key]), 'conflict')
    rows = []
    for row, initial in zip(out['accounts'], original['accounts']):
        row = exact(row, ACCOUNT)
        for key in ACCOUNT[:-2]:
            need(row[key] == initial[key] and type(row[key]) is type(initial[key]), 'conflict')
        for key in ACCOUNT[-2:]:
            integer(row[key], 0, 4096)
        rows.append(row)
    out['accounts'] = rows
    packed(out, 4096)
    return out


def current_binding(value, original):
    out = exact(value, CURRENT)
    need(type(out['version']) is int and out['version'] == 1)
    for key in ('hosted_vault_id','wallet_owner_id'):
        hex64(out[key], True)
    for key in ('retention_id','source_binding_id'):
        hex64(out[key])
    base = exact(out['vault_binding'], BINDING)
    need(type(base['version']) is int and base['version'] == 1)
    for key in ('authority_id','account_id','principal_id','provision_id'):
        hex64(base[key])
    for key in ('network','genesis','profile','root_public_key','gym_public_key','gym_id'):
        need(base[key] == original[key] and type(base[key]) is type(original[key]), 'conflict')
    out['vault_binding'] = base
    return out


def bindings_checked(values, originals):
    need(type(values) is list and len(values) == 2)
    need(type(originals) is list and len(originals) == 2)
    result = [current_binding(b, m) for b, m in zip(values, originals)]
    a, b = result
    for name in ('hosted_vault_id', 'source_binding_id'):
        need(a[name] == b[name], 'conflict')
    need(a['vault_binding']['authority_id'] == b['vault_binding']['authority_id'], 'conflict')
    for name in ('wallet_owner_id',):
        need(a[name] != b[name], 'conflict')
    for name in ('account_id', 'principal_id', 'root_public_key', 'gym_id'):
        need(a['vault_binding'][name] != b['vault_binding'][name], 'conflict')
    return result


def binding_hash(value):
    return sha(b'SLUG hosted current recovery binding\x00v1\x00' + canonical(value))


def monotonic(new, old):
    for a, b in zip(new['accounts'], old['accounts']):
        for key in ('next_external','next_internal'):
            need(a[key] >= b[key], 'conflict')


def checkpoint(value, expected_binding, original):
    out = exact(value, CHECKPOINT)
    need(type(out['version']) is int and out['version'] == 1)
    out['binding'] = current_binding(out['binding'], original)
    need(out['binding'] == expected_binding, 'conflict')
    integer(out['revision'], 1, 128)
    integer(out['expected_revision'], 0, 127)
    need(out['expected_revision'] + 1 == out['revision'], 'conflict')
    hex64(out['capture_id'], True)
    integer(out['captured_at_ms'], 1, TIME_MAX)
    integer(out['committed_at_ms'], out['captured_at_ms'], TIME_MAX)
    out['manifest'] = manifest(out['manifest'], original)
    monotonic(out['manifest'], original)
    hex64(out['manifest_sha256'])
    need(out['manifest_sha256'] == sha(canonical(out['manifest'])), 'conflict')
    packed(out, 8192)
    return out


class CurrentModel:
    """Public arithmetic model only; no session, IO or opaque source authority."""
    def __init__(self, bindings, originals):
        self.bindings = bindings_checked(bindings, originals)
        self.originals = own(originals)
        self.actions = {}
        self.current = [None,None]
        self.clock = 0

    def commit(self, index, request, now):
        integer(index,0,1)
        req = exact(request,REQUEST)
        req['binding'] = current_binding(req['binding'],self.originals[index])
        need(req['binding'] == self.bindings[index], 'conflict')
        hex64(req['capture_id'],True)
        integer(req['expected_revision'],0,127)
        integer(req['captured_at_ms'],1,TIME_MAX)
        req['manifest'] = manifest(req['manifest'],self.originals[index])
        integer(now,1,TIME_MAX)
        need(now >= self.clock, 'conflict')
        old = self.actions.get(req['capture_id'])
        if old is not None:
            need(all(old[k] == req[k] for k in REQUEST), 'conflict')
            return own(old), False
        need(len(self.actions)<128,'capacity')
        previous=self.current[index]
        need(req['expected_revision']==(previous['revision'] if previous else 0),'conflict')
        if previous:
            need(req['captured_at_ms']>=previous['captured_at_ms'],'conflict')
        monotonic(req['manifest'],previous['manifest'] if previous else self.originals[index])
        need(now>=req['captured_at_ms'],'conflict')
        row=dict(version=1,binding=req['binding'],revision=req['expected_revision']+1,
                 capture_id=req['capture_id'],expected_revision=req['expected_revision'],
                 captured_at_ms=req['captured_at_ms'],committed_at_ms=now,
                 manifest=req['manifest'],manifest_sha256=sha(canonical(req['manifest'])))
        row=checkpoint(row,self.bindings[index],self.originals[index])
        staged=own(self.actions);staged[row['capture_id']]=row
        pointers=own(self.current);pointers[index]=row
        meta=self.meta(pointers,len(staged),now)
        action_key=('action/'+row['capture_id']).encode('ascii')
        need(len(action_key)+len(canonical(row))+len(b'meta')+len(canonical(meta))<=12288,'capacity')
        need(sum(len(('action/'+k).encode('ascii'))+len(canonical(v)) for k,v in staged.items())+4+len(canonical(meta))<=2097152,'capacity')
        self.actions=staged;self.current=pointers;self.clock=now
        return own(row),True

    def marker(self):
        return dict(application='slug-hosted-current-recovery',version=1,bindings=own(self.bindings))

    def meta(self,current=None,count=None,clock=None):
        current=self.current if current is None else current
        rows=[dict(account_id=b['vault_binding']['account_id'],revision=r['revision'] if r else 0,
                   capture_id=r['capture_id'] if r else '') for b,r in zip(self.bindings,current)]
        value=dict(version=1,marker_sha256=sha(canonical(self.marker())),actions=len(self.actions) if count is None else count,
                   clock_high_water_ms=self.clock if clock is None else clock,current=rows)
        packed(value,4096)
        return value

    def entries(self):
        rows = [('meta', canonical(self.meta()))]
        rows += [('action/'+key, canonical(value)) for key, value in self.actions.items()]
        return [{'key': key, 'value_hex': value.hex()} for key, value in sorted(rows)]

    def snapshot(self):
        marker = self.marker()
        return dict(marker=marker, marker_file_utf8=packed(marker, 32768, True).decode(),
                    marker_sha256=sha(canonical(marker)), entries=self.entries(),
                    stored_key_value_bytes=sum(len(r['key'].encode('ascii'))+
                                               len(bytes.fromhex(r['value_hex']))
                                               for r in self.entries()))


def parse_checkpoint(raw, expected_binding, original):
    value, unframed = parse(raw, 8192)
    value = checkpoint(value, expected_binding, original)
    need(canonical(value) == unframed)
    return value


def audit(marker_file, entries, expected_bindings, originals):
    """Audit supplied public bytes against separate expected pins, not authority."""
    expected = CurrentModel(expected_bindings, originals)
    marker, raw = parse(marker_file, 32768, True)
    marker = exact(marker, MARKER)
    need(marker['application'] == 'slug-hosted-current-recovery')
    need(type(marker['version']) is int and marker['version'] == 1)
    marker['bindings'] = bindings_checked(marker['bindings'], originals)
    need(marker == expected.marker(), 'conflict')
    need(canonical(marker) == raw)
    need(type(entries) is list and len(entries) <= 129, 'capacity')
    values = {}
    total = 0
    rows = [[], []]
    accounts = [b['vault_binding']['account_id'] for b in expected.bindings]
    for entry in entries:
        entry = exact(entry, ('key', 'value_hex'))
        key, encoded = entry['key'], entry['value_hex']
        text(key, 71)
        need(key == 'meta' or key.startswith('action/') and len(key) == 71)
        if key != 'meta':
            hex64(key[7:], True)
        need(key not in values)
        # This is fixture serialization only. Hex spelling is not a LevelDB
        # semantic invariant; concrete tests supply the decoded bytes.
        need(type(encoded) is str and len(encoded) % 2 == 0)
        need(len(encoded) <= (4096 if key == 'meta' else 8192)*2, 'capacity')
        try:
            value_raw = bytes.fromhex(encoded)
        except ValueError:
            raise Rejected('invalid')
        total += len(key.encode('ascii')) + len(value_raw)
        need(total <= 2097152, 'capacity')
        values[key] = value_raw
        if key == 'meta':
            continue
        # Account selection is structural only; the complete binding is
        # compared with the separately supplied trusted test pin below.
        supplied, _ = parse(value_raw, 8192)
        need(type(supplied) is dict and type(supplied.get('binding')) is dict)
        base = supplied['binding'].get('vault_binding')
        need(type(base) is dict and base.get('account_id') in accounts, 'conflict')
        index = accounts.index(base['account_id'])
        row = parse_checkpoint(value_raw, expected.bindings[index], originals[index])
        need(row['capture_id'] == key[7:], 'conflict')
        rows[index].append(row)
    need('meta' in values)
    meta, raw = parse(values['meta'], 4096)
    meta = exact(meta, META)
    need(type(meta['version']) is int and meta['version'] == 1)
    hex64(meta['marker_sha256'])
    need(meta['marker_sha256'] == sha(canonical(marker)), 'conflict')
    integer(meta['actions'], 0, 128)
    integer(meta['clock_high_water_ms'], 0, TIME_MAX)
    need(type(meta['current']) is list and len(meta['current']) == 2)
    pointers = []
    highwater = 0
    count = 0
    for index, own_rows in enumerate(rows):
        own_rows.sort(key=lambda r: r['revision'])
        previous = None
        for revision, row in enumerate(own_rows, 1):
            need(row['revision'] == revision and row['expected_revision'] == revision-1, 'conflict')
            if previous:
                need(row['captured_at_ms'] >= previous['captured_at_ms'], 'conflict')
                need(row['committed_at_ms'] >= previous['committed_at_ms'], 'conflict')
            monotonic(row['manifest'], previous['manifest'] if previous else originals[index])
            previous = row
            highwater = max(highwater, row['committed_at_ms'])
            count += 1
            expected.actions[row['capture_id']] = own(row)
        expected.current[index] = own(previous)
        pointer = exact(meta['current'][index], POINTER)
        need(pointer['account_id'] == accounts[index], 'conflict')
        integer(pointer['revision'], 0, 128)
        if previous:
            hex64(pointer['capture_id'], True)
            need(pointer['revision'] == previous['revision'] and
                 pointer['capture_id'] == previous['capture_id'], 'conflict')
        else:
            need(pointer['revision'] == 0 and pointer['capture_id'] == '', 'conflict')
        pointers.append(pointer)
    meta['current'] = pointers
    need(meta['actions'] == count and meta['clock_high_water_ms'] == highwater, 'conflict')
    need(canonical(meta) == raw)
    expected.clock = highwater
    need(meta == expected.meta(), 'conflict')
    return expected


def export_model(fault, cleanup_failure=False):
    """Finite injected-state model. It does not execute or prove filesystem IO."""
    known = {'none', 'held', 'stale_view', 'cancel_before_fence', 'destination_exists',
             'missing_callback', 'late_callback', 'create', 'write', 'file_sync',
             'link_unknown', 'cancel_after_link', 'unlink', 'directory_sync',
             'postcheck', 'outer_error', 'double_callback', 'swallowed_write'}
    need(fault in known and type(cleanup_failure) is bool)
    trace = []
    unwrapped = False
    admitted = False
    final = 'absent'
    temporary = False
    terminal = 'unavailable'
    if fault in ('held', 'stale_view'):
        terminal = fault
    else:
        # Concrete runtime must separately prove this preflight is the real
        # original capability and purpose-only unwrap, not this enum model.
        trace += ['original_export_preflight', 'unwrap_recovery', 'encode_memory']
        unwrapped = True
        if fault == 'cancel_before_fence':
            terminal = 'cancelled'
        elif fault in ('missing_callback', 'late_callback'):
            terminal = 'unauthorized'
        else:
            admitted = True
            trace += ['final_original_fence', 'destination_check']
            if fault == 'destination_exists':
                final, terminal = 'preexisting_untouched', 'conflict'
            elif fault == 'create':
                trace += ['temporary_create_failed']
            else:
                temporary = True
                trace += ['temporary_create_0600', 'write']
                if fault in ('write', 'swallowed_write'):
                    trace += ['write_failed']
                else:
                    trace += ['file_sync']
                    if fault != 'file_sync':
                        trace += ['exclusive_link']
                        if fault == 'link_unknown':
                            final, terminal = 'unknown', 'export_uncertain'
                        else:
                            final, terminal = 'published', 'export_uncertain'
                            if fault != 'cancel_after_link':
                                trace += ['unlink_temporary']
                                if fault != 'unlink':
                                    temporary = False
                                    trace += ['directory_sync']
                                    if fault != 'directory_sync':
                                        trace += ['original_postcheck']
                                        if fault not in ('postcheck', 'outer_error', 'double_callback'):
                                            terminal = 'saved'
                                        elif fault == 'double_callback':
                                            trace += ['second_callback_refused']
    trace += ['join_close', 'clear_private_memory']
    if cleanup_failure:
        trace += ['cleanup_failed_owner_retained']
        terminal = ('export_uncertain' if final in ('published', 'unknown')
                    else 'cleanup_failed')
    else:
        if temporary:
            trace += ['remove_owned_temporary']
        temporary = False
    return dict(model_only=True, fault=fault, cleanup_failure=cleanup_failure,
                trace=trace, recovery_unwrapped=unwrapped, fence_entered=admitted,
                plaintext_file_before_fence=False, final_destination=final,
                temporary_retained=temporary, terminal=terminal,
                owner_retained=cleanup_failure, automatic_retry=False,
                automatic_final_unlink=False, process_restart_replays_export=False)
