"""Read-only independent helper review. No sudo or service actions."""
import ast
import base64
import hashlib
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('reviewed_maintenance', HERE / 'maintenance.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
checks = 0

def check(condition, label):
    global checks
    assert condition, label
    checks += 1

def rejected(request):
    try:
        m.validate(request)
    except m.Refused:
        return True
    return False

for req in ({'action':'snapshot'}, {'action':'network'},
            {'action':'repair','job':'vpn'}, {'action':'repair','job':'monitor'},
            {'action':'read-log','id':'service-events','offset':0},
            {'action':'read-log','id':'error-history/'+'a'*64,'offset':2**63-1}):
    check(m.validate(req)==req['action'], 'valid request')

for req in (None, [], {'action':'exec','args':['/bin/sh']},
            {'action':'snapshot','path':'/etc/sudoers'},
            {'action':'network','args':'-F all'},
            {'action':'repair','job':'vpn; id'},
            {'action':'repair','job':'../vpn'},
            {'action':'read-log','id':'/etc/sudoers','offset':0},
            {'action':'read-log','id':'error-history/../x','offset':0},
            {'action':'read-log','id':'error-history/'+'a'*64+'\n','offset':0},
            {'action':'read-log','id':'service-events','offset':True},
            {'action':'read-log','id':'service-events','offset':-1},
            {'action':'read-log','id':'service-events','offset':2**63},
            {'action':'read-log','id':'service-events','offset':'0'}):
    check(rejected(req), 'invalid request refused')

boot = 'current-boot'
s = {'phase':'RUNNING','reason':'running','boot':boot}
n = {'phase':'ACTIVE','boot':boot}
c = {'phase':'LOADED'}
v = {'service_enabled':True,'data_permission':True}
live = {'pid':123,'loaded':True}
gone = {'pid':None,'loaded':True}
for native in ('WAITING', 'ACTIVE'):
    check(m.service_decision(s, dict(n,phase=native), c, v, live, boot)=='already_running', 'healthy native state is preserved')
check(m.service_decision(s,n,c,v,gone,boot)=='restore_supervisor','abnormal missing supervisor eligible')
for phase in ('STOPPED','DISABLED','ATTENTION','UNKNOWN'):
    check(m.service_decision(dict(s,phase=phase),n,c,v,gone,boot)!='restore_supervisor','stopped or latched service preserved')
for phase in ('PREFLIGHT','STARTING','RUNNING','RECOVERING','BACKOFF'):
    check(m.service_decision(dict(s,phase=phase,reason='manual_stop'),n,c,v,gone,boot)!='restore_supervisor','manual stop reason is preserved through transitions')
for reason in ('unknown_failure','configuration_changed','retry_budget_exhausted','latched_attention','unexpected'):
    check(m.service_decision(dict(s,reason=reason),n,c,v,gone,boot)!='restore_supervisor','unsafe reason preserved')
for control in ('STOPPED','DISABLED','STOPPING','UNKNOWN'):
    check(m.service_decision(s,n,dict(c,phase=control),v,gone,boot)!='restore_supervisor','manual control preserved')
for state,native in ((dict(s,boot='old'),n),(s,dict(n,boot='old')),(s,dict(n,phase='ATTENTION'))):
    check(m.service_decision(state,native,c,v,gone,boot)!='restore_supervisor','boot and native attention preserved')
for key in ('service_enabled','data_permission'):
    check(m.service_decision(s,n,c,dict(v,**{key:False}),gone,boot)!='restore_supervisor','disabled permission preserved')

tree = ast.parse((HERE/'maintenance.py').read_text())
for node in ast.walk(tree):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id=='subprocess':
        check(not any(k.arg=='shell' and not (isinstance(k.value,ast.Constant) and k.value.value is False) for k in node.keywords),'no shell execution')

installer = ast.parse((HERE/'build/installer-reviewed.py').read_text())
assignments = {n.targets[0].id:n.value for n in installer.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
payload = base64.b64decode(ast.literal_eval(assignments['HELPER_DATA'].args[0]))
check(payload==(HERE/'maintenance.py').read_bytes(),'installer includes reviewed helper bytes')
check(hashlib.sha256(payload).hexdigest()==ast.literal_eval(assignments['EXPECTED']),'installer payload hash')
rule = ast.literal_eval(assignments['rule_data']).decode()
check(rule.splitlines()[1]=='example ALL=(root) NOPASSWD: /usr/bin/python3 -I -B /Library/PrivilegedHelperTools/org.familyvpn.maintenance.py','exact sudoers command without wildcard')
print({'passed':checks,'mode':'read-only, no elevation, no service operations'})
