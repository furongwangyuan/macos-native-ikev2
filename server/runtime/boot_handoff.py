"""Fixed post-close handoff: disable finite permission, retire exact old journal.
No new owner/session or service state is created. All original bytes remain archived.
"""
import base64,copy
import boot_record as r
import boot_native as native
import boot_source as source
import boot_reconcile as close
import native_support as s

PATH=native.ROOT/'handoff.json'
KEYS=('supervisor-config','native-config','native-journal')
AFTER={'supervisor-config':r.encode(dict(version=1,enabled=False)),
       'native-config':r.encode(dict(version=1,allow_data=False))}
TARGETS={'supervisor-config':s.CONF/'supervisor-config.json','native-config':s.CONF/'config.json',
         'native-journal':s.STATE/'native-session.json'}


def present(path):
    try:path.lstat();return True
    except FileNotFoundError:return False


def validate(value):
    if (type(value)is not dict or set(value)!={'version','profile','boot_record_sha256','boot','context_sha256','native_sha256','completed','intent','phase'}
            or type(value['version'])is not int or value['version']!=1 or value['profile']!='unified-bounded-boot-handoff-disabled-v1'
            or type(value['boot'])is not str or not value['boot'] or value['phase'] not in ('DISABLING','COMPLETE')
            or any(not r.exact_hash(value[k]) for k in ('boot_record_sha256','context_sha256','native_sha256'))
            or type(value['completed'])is not list or value['completed']!=list(KEYS[:len(value['completed'])])
            or value['intent'] not in (None,*KEYS)
            or value['intent'] is not None and value['intent']!=(KEYS[len(value['completed'])] if len(value['completed'])<len(KEYS) else None)
            or value['phase']=='COMPLETE' and (value['completed']!=list(KEYS) or value['intent'] is not None)):
        raise r.Refused('unknown_boot_handoff')
    return value


def readback(io,store,record):
    io.held();r.validate(record)
    if record['phase']!='RESTORED' or record['intent'] is not None:raise r.Refused('handoff_before_closed_completion')
    native_raw,context_raw=store.originals(record);old=r.bind(record,native_raw,context_raw)
    if io.boot()!=record['new_boot'] or io.implementation()!=record['implementation_sha256']:
        raise r.Refused('handoff_boot_or_code_changed')
    source.absent_service();io.closed_kernel()
    r.alf_scope(old,io.alf(),record['completed'])
    if io.alf()!=old['alf_before']:raise r.Refused('handoff_alf_not_restored')
    current=io.pf(old)
    if current['sha256']!=old['pf']['before_sha'] or current['root']!='baseline' or current['anchor']!={'filters':[],'nat':[]}:
        raise r.Refused('handoff_pf_not_restored')
    close.files_scope(io,old,record['completed'])
    return native_raw,context_raw


class Handoff:
    def __init__(self,io,store):self.io=io;self.store=store;self.previous=None
    def load(self):
        self.io.held()
        if not present(PATH):return None
        self.previous=s.read(PATH);return validate(s.json_value(self.previous))
    def save(self,value):
        self.io.held();validate(value);raw=r.encode(value)
        if self.previous is None:self.store.write_new(PATH,raw)
        else:
            if s.read(PATH)!=self.previous:raise r.Refused('handoff_cas_changed')
            s.atomic(PATH,raw)
        if s.read(PATH)!=raw:raise r.Refused('handoff_readback_failed')
        self.previous=raw
    def originals(self,record):
        raw=readback(self.io,self.store,record);files=source.unpack(raw[1])
        return {'native-journal':raw[0],'native-config':files['native-config'],'supervisor-config':files['supervisor-config']}
    def scope(self,value,record,before):
        self.io.held();validate(value)
        if (value['boot_record_sha256']!=r.sha(s.read(native.RECORD)) or value['boot']!=record['new_boot']
                or value['context_sha256']!=record['context_sha256'] or value['native_sha256']!=record['native_sha256']):
            raise r.Refused('handoff_source_binding')
        for key,path in TARGETS.items():
            observed=s.read(path) if present(path) else None
            target=AFTER.get(key)
            allowed=(target,) if key in value['completed'] else ((before[key],target) if value['intent']==key else (before[key],))
            if observed not in allowed:raise r.Refused('handoff_resource_changed_or_missing')
        source.absent_service()
    def run(self):
        record=self.store.load()
        if record is None:raise r.Refused('handoff_record_missing')
        before=self.originals(record);value=self.load()
        if value is None:
            # Before creating handoff authority, prove the actual original pair
            # and untouched config still match. No source filename is guessed.
            if self.io.originals()!=self.store.originals(record) or self.io.configuration()!=record['configuration_sha256']:
                raise r.Refused('handoff_originals_changed')
            value=dict(version=1,profile='unified-bounded-boot-handoff-disabled-v1',boot_record_sha256=r.sha(s.read(native.RECORD)),
                boot=record['new_boot'],context_sha256=record['context_sha256'],native_sha256=record['native_sha256'],
                completed=[],intent=None,phase='DISABLING')
            for key in ('supervisor-config','native-config'):
                self.store.write_new(native.ARCHIVES/(key+'-'+r.sha(before[key])+'.json'),before[key])
            self.save(value)
        self.scope(value,record,before)
        for key in KEYS:
            if key in value['completed']:continue
            readback(self.io,self.store,record);self.scope(value,record,before)
            value['intent']=key;self.save(value);self.scope(value,record,before)
            path=TARGETS[key]
            if key in AFTER:
                if s.read(path)!=AFTER[key]:s.atomic(path,AFTER[key])
                if s.read(path)!=AFTER[key]:raise r.Refused('handoff_disabled_config_readback')
            elif present(path):
                if s.read(path)!=before[key]:raise r.Refused('handoff_original_changed_before_retire')
                # A verified permanent archive already contains these exact bytes.
                archive=native.ARCHIVES/('native-'+r.sha(before[key])+'.json')
                if s.read(archive)!=before[key]:raise r.Refused('handoff_native_archive_changed')
                path.unlink();s.sync_dir(path.parent)
            if key=='native-journal' and present(path):raise r.Refused('handoff_native_still_present')
            value['completed'].append(key);value['intent']=None;self.save(value)
        readback(self.io,self.store,record);self.scope(value,record,before)
        value['phase']='COMPLETE';self.save(value)
        return dict(result='closed_reconciled_and_handed_off',data_started=False,production_enabled=False,
            original_journal_archived=True,new_owner_created=False)


def run_locked(io,store):return Handoff(io,store).run()


def completed_report_locked(io,store):
    """Read-only; the caller already owns the actual same native/legacy locks."""
    io.held();record=store.load();h=Handoff(io,store);value=h.load()
    if record is None or value is None or value['phase']!='COMPLETE':raise r.Refused('boot_handoff_not_complete')
    before=h.originals(record);h.scope(value,record,before)
    return dict(result='closed_reconciled_and_handed_off',data_started=False,production_enabled=False,
        original_journal_archived=True,new_owner_created=False,fresh_closed_readback=True)


def report_native():
    """Fixed read-only post-boot report, with fresh closed readback under lock."""
    from boot_store import Store
    native.Native.installed_scope();io=native.Native()
    with io.locked():return completed_report_locked(io,Store(io))

if __name__=='__main__':raise SystemExit('No standalone handoff; the fixed same-lock recovery entry owns this action.')
