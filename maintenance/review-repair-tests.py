"""Offline repair behavior regression checks. All service, file, and HTTP IO mocked."""
import datetime
import importlib.util
import json
from pathlib import Path
import plistlib
from unittest.mock import patch
import urllib.request

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('repair_review', HERE / 'maintenance.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
NOW = 1800000000.0
BOOT = 'test-boot'
BASE_STATE = {'phase':'RUNNING','reason':'running','boot':BOOT}
BASE_NATIVE = {'phase':'ACTIVE','boot':BOOT}
BASE_CONTROL = {'phase':'LOADED'}
BASE_VERIFIED = {'service_enabled':True,'data_permission':True}
ABSENT = {'loaded':False,'pid':None,'state':None}
STOPPED_JOB = {'loaded':True,'pid':None,'state':'waiting'}
RUNNING_JOB = {'loaded':True,'pid':777,'state':'running'}
RESULTS = []

def run_case(name, key='vpn', jobs=None, states=None, controls=None, natives=None,
             verified=None, disabled=None, monitor=None, attempts=None, plist_changed=False,
             expected_action='none', expected_mutation=None, expected_error=None,
             no_intent=False):
    label, args = m.JOBS[key]
    plist = Path('/Library/LaunchDaemons')/(label+'.plist')
    definition = {'Label':label,'ProgramArguments':args,'UserName':'root'}
    counters = {'job':0,'verified':0,'disabled':0,'plist':0,'http':0}
    values = {'service-state':states or [BASE_STATE], 'native-session':natives or [BASE_NATIVE],
              'service-control':controls or [BASE_CONTROL]}
    counts = {k:0 for k in values}
    commands, writes, audits = [], [], []
    job_values = jobs or [STOPPED_JOB,STOPPED_JOB,RUNNING_JOB]
    verified_values = verified or [BASE_VERIFIED]
    disabled_values = disabled or [False]
    monitor_values = monitor or []

    def next_value(sequence, counter):
        i = counters[counter]
        counters[counter] += 1
        return sequence[min(i,len(sequence)-1)]

    def fake_read(path, *unused, **unused_kwargs):
        assert path == plist, ('Unexpected file read',str(path))
        counters['plist'] += 1
        d = dict(definition)
        if plist_changed and counters['plist'] > 1:
            d['WorkingDirectory'] = '/changed'
        return plistlib.dumps(d)

    def fake_value(path):
        if path == m.STATE/'attempts.json':
            assert attempts is not None
            return dict(attempts)
        for log_id, sequence in values.items():
            if path == m.LOGS[log_id]:
                i = counts[log_id]
                counts[log_id] += 1
                return dict(sequence[min(i,len(sequence)-1)])
        raise AssertionError(('Unexpected JSON read',str(path)))

    def fake_command(argv, **kwargs):
        commands.append(list(argv))
        if argv == ['/bin/launchctl','print-disabled','system']:
            value = next_value(disabled_values,'disabled')
            if value == 'error':
                return {'exit_code':1,'stdout':'','stderr':'test-unavailable'}
            return {'exit_code':0,'stdout':'{\n "'+label+'" => '+('true' if value else 'false')+'\n}', 'stderr':''}
        if argv == ['/usr/sbin/sysctl','-n','kern.boottime']:
            return {'exit_code':0,'stdout':BOOT+'\n','stderr':''}
        if argv[:2] == ['/bin/launchctl','kickstart']:
            assert argv in (['/bin/launchctl','kickstart','system/'+label], ['/bin/launchctl','kickstart','-k','system/'+label])
            assert key == 'monitor' or '-k' not in argv
            return {'exit_code':0,'stdout':'','stderr':''}
        if argv == ['/bin/launchctl','bootstrap','system',str(plist)]:
            return {'exit_code':0,'stdout':'','stderr':''}
        raise AssertionError(('Unexpected command',argv))

    class Response:
        def __init__(self,value): self.value=value
        def __enter__(self): return self
        def __exit__(self,*unused): return None
        def read(self,limit):
            assert limit == 1048576
            observed = NOW - (120 if self.value == 'stale' else 2)
            timestamp = datetime.datetime.fromtimestamp(observed,datetime.timezone.utc).isoformat()
            return json.dumps({'observed_at':timestamp,'collector':{'state':'ok'}}).encode()

    class Opener:
        def open(self,url,timeout):
            assert url == 'http://127.0.0.1:8767/api/status' and timeout == 3
            assert monitor_values, 'Unexpected HTTP request'
            value = next_value(monitor_values,'http')
            if value == 'unavailable': raise TimeoutError('Mock endpoint unavailable')
            return Response(value)

    def cannot_execute(*unused,**unused_kwargs):
        raise AssertionError('Real subprocess execution forbidden by offline test')

    error = None
    result = None
    with patch.object(m,'read',fake_read), patch.object(m,'trusted',lambda *a,**kw:None), \
         patch.object(m,'value',fake_value), patch.object(m,'command',fake_command), \
         patch.object(m,'job',lambda job:dict(next_value(job_values,'job'))), \
         patch.object(m,'status_verified',lambda:dict(next_value(verified_values,'verified'))), \
         patch.object(m,'atomic',lambda path,data:writes.append((path,json.loads(data)))), \
         patch.object(m,'audit',lambda event:audits.append(dict(event))), \
         patch.object(m.Path,'exists',lambda path:path==m.STATE/'attempts.json' and attempts is not None), \
         patch.object(m.time,'time',lambda:NOW), patch.object(m.time,'sleep',lambda seconds:None), \
         patch.object(urllib.request,'build_opener',lambda *args:Opener()), \
         patch.object(m.subprocess,'run',cannot_execute):
        try:
            result = m.repair(key)
        except m.Refused as e:
            error = str(e)

    mutations = [cmd for cmd in commands if cmd[:2] in (['/bin/launchctl','kickstart'],['/bin/launchctl','bootstrap'])]
    assert error == expected_error, (name,error,expected_error)
    if expected_error is None:
        assert result['action'] == expected_action, (name,result)
    assert mutations == ([] if expected_mutation is None else [expected_mutation]), (name,mutations)
    if no_intent:
        assert not writes and not audits, (name,writes,audits)
    if expected_mutation:
        assert len(writes)==1 and writes[0][1]=={key:NOW}, (name,writes)
        assert audits[0]['event']=='repair_intent' and audits[-1]['event']=='repair_result'
        assert result['recovery_verified'] is False
    RESULTS.append({'name':name,'passed':True,'launchd_mutations':len(mutations),'http_observations':counters['http']})

vpn_kick = ['/bin/launchctl','kickstart','system/org.familyvpn.service']
vpn_boot = ['/bin/launchctl','bootstrap','system','/Library/LaunchDaemons/org.familyvpn.service.plist']
monitor_kick = ['/bin/launchctl','kickstart','system/org.familyvpn.monitor']
monitor_force = ['/bin/launchctl','kickstart','-k','system/org.familyvpn.monitor']
monitor_boot = ['/bin/launchctl','bootstrap','system','/Library/LaunchDaemons/org.familyvpn.monitor.plist']

run_case('vpn registered without pid',expected_action='kickstart',expected_mutation=vpn_kick)
run_case('vpn missing job',jobs=[ABSENT,ABSENT,RUNNING_JOB],expected_action='bootstrap',expected_mutation=vpn_boot)
run_case('vpn latest state selects bootstrap',jobs=[STOPPED_JOB,ABSENT,RUNNING_JOB],expected_action='bootstrap',expected_mutation=vpn_boot)
run_case('vpn manual stop before final check',states=[BASE_STATE,dict(BASE_STATE,phase='RECOVERING',reason='manual_stop')])
run_case('vpn stopped before final check',states=[BASE_STATE,dict(BASE_STATE,phase='STOPPED',reason='manual_stop')])
run_case('vpn config disabled before final check',verified=[BASE_VERIFIED,dict(BASE_VERIFIED,service_enabled=False)])
run_case('vpn data permission revoked before final check',verified=[BASE_VERIFIED,dict(BASE_VERIFIED,data_permission=False)])
run_case('vpn control changed before final check',controls=[BASE_CONTROL,{'phase':'STOPPING'}])
run_case('vpn native attention before final check',natives=[BASE_NATIVE,dict(BASE_NATIVE,phase='ATTENTION')])
run_case('vpn budget exhausted before final check',states=[BASE_STATE,dict(BASE_STATE,phase='ATTENTION',reason='retry_budget_exhausted')])
run_case('vpn launchd disabled before final check',disabled=[False,True],expected_error='disabled_during_repair')
run_case('vpn final launchd query unavailable',disabled=[False,'error'],expected_error='disabled_during_repair')
run_case('vpn already respawned',jobs=[STOPPED_JOB,RUNNING_JOB])
run_case('vpn cooldown',attempts={'vpn':NOW-10},no_intent=True)
run_case('vpn plist changed',plist_changed=True,expected_error='job_changed_during_repair')
run_case('healthy vpn preserved',jobs=[RUNNING_JOB],no_intent=True)
run_case('monitor registered without pid',key='monitor',expected_action='kickstart',expected_mutation=monitor_kick)
run_case('monitor missing job',key='monitor',jobs=[ABSENT,ABSENT,RUNNING_JOB],expected_action='bootstrap',expected_mutation=monitor_boot)
run_case('monitor stale confirmed three times',key='monitor',jobs=[RUNNING_JOB],monitor=['stale']*3,expected_action='kickstart',expected_mutation=monitor_force)
run_case('monitor fresh preserved',key='monitor',jobs=[RUNNING_JOB],monitor=['fresh'],no_intent=True)
run_case('monitor unavailable preserved',key='monitor',jobs=[RUNNING_JOB],monitor=['unavailable'],no_intent=True)
run_case('monitor recovered at second observation',key='monitor',jobs=[RUNNING_JOB],monitor=['stale','fresh'],no_intent=True)
run_case('monitor recovered at final observation',key='monitor',jobs=[RUNNING_JOB],monitor=['stale','stale','fresh'])
run_case('monitor pid replaced',key='monitor',jobs=[RUNNING_JOB,dict(RUNNING_JOB,pid=778)],monitor=['stale','stale'])
run_case('monitor starts before final check',key='monitor',jobs=[STOPPED_JOB,RUNNING_JOB])
run_case('monitor disabled before final check',key='monitor',disabled=[False,True],expected_error='disabled_during_repair')
run_case('monitor cooldown',key='monitor',attempts={'monitor':NOW-10},no_intent=True)
run_case('monitor stale pid exits before action',key='monitor',jobs=[RUNNING_JOB,STOPPED_JOB,RUNNING_JOB],monitor=['stale','stale'],expected_action='kickstart',expected_mutation=monitor_force)
print(json.dumps({'passed':len(RESULTS),'mode':'all IO mocked; zero real service operations','cases':RESULTS},indent=2))
