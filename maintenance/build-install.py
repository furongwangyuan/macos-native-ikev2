"""Prepare an embedded, reviewable administrator install request; no elevation here."""
from pathlib import Path
import base64
import hashlib
import json
import shlex
import argparse
import re

HERE = Path(__file__).resolve().parent
helper = (HERE / 'maintenance.py').read_bytes()
p = argparse.ArgumentParser()
p.add_argument('--user', default='example')
p.add_argument('--output', type=Path, default=HERE/'build')
args = p.parse_args()
if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}', args.user): p.error('invalid local short username')
HERE=args.output.resolve(); HERE.mkdir(parents=True,exist_ok=True)
code = r'''
import base64,hashlib,json,os,stat,subprocess,tempfile
from pathlib import Path
if os.geteuid()!=0:raise SystemExit('Administrator authentication required')
os.umask(0o077)
HELPER_DATA=base64.b64decode(__PAYLOAD__)
EXPECTED=__SHA__
assert hashlib.sha256(HELPER_DATA).hexdigest()==EXPECTED
compile(HELPER_DATA,'maintenance.py','exec')
helper=Path('/Library/PrivilegedHelperTools/org.familyvpn.maintenance.py')
state=Path('/private/var/db/family-vpn-maintenance')
rule=Path('/private/etc/sudoers.d/family-vpn-maintenance')
rule_data=b'# Family VPN maintenance; fixed root-owned program, no command-line arguments.\nexample ALL=(root) NOPASSWD: /usr/bin/python3 -I -B /Library/PrivilegedHelperTools/org.familyvpn.maintenance.py\n'
env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C','LC_ALL':'C','HOME':'/var/root'}
def trust(p,directory=False):
 for q in (p,*p.parents):
  s=q.lstat()
  if stat.S_ISLNK(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise RuntimeError('Unsafe root path')
  a=subprocess.run(['/bin/ls','-lde',str(q)],capture_output=True,env=env,timeout=3)
  if a.returncode or len(a.stdout.splitlines())!=1:raise RuntimeError('ACL refused')
 s=p.lstat()
 if not (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)):raise RuntimeError('Wrong type')
 if not directory and s.st_nlink!=1:raise RuntimeError('Hardlink refused')
def run(args):
 p=subprocess.run(args,env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=15)
 if p.returncode:raise RuntimeError('Validation failed: '+p.stderr.decode('utf-8','replace')[:500])
 return p
def put(p,data,mode):
 trust(p.parent,True)
 if p.exists() or p.is_symlink():
  trust(p)
  if p.read_bytes()!=data or stat.S_IMODE(p.stat().st_mode)!=mode:raise RuntimeError('Existing installation differs; retained')
  return False
 fd,tmp=tempfile.mkstemp(prefix='.'+p.name+'-',dir=str(p.parent))
 try:
  os.fchmod(fd,mode);os.fchown(fd,0,0)
  with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
  os.link(tmp,p)
 finally:os.unlink(tmp)
 return True
trust(helper.parent,True);trust(state.parent,True);trust(rule.parent,True)
trust(Path('/private/etc/sudoers'))
sudoers=Path('/private/etc/sudoers').read_text()
if not any(line.strip().split() in (['@includedir','/private/etc/sudoers.d'],['@includedir','/etc/sudoers.d'],['#includedir','/private/etc/sudoers.d'],['#includedir','/etc/sudoers.d']) for line in sudoers.splitlines()):
 raise RuntimeError('Existing sudoers does not include its standard drop-in directory; no global file changed')
run(['/usr/sbin/visudo','-c'])
created_helper=False;created_rule=False;created_state=False
try:
 if not state.exists():state.mkdir(mode=0o700);created_state=True
 trust(state,True)
 if stat.S_IMODE(state.stat().st_mode)!=0o700:raise RuntimeError('State mode refused')
 created_helper=put(helper,HELPER_DATA,0o600)
 # The dot-prefixed temporary file is deliberately ignored by sudo's include directory.
 fd,candidate=tempfile.mkstemp(prefix='.family-vpn-check-',dir=str(rule.parent))
 try:
  os.fchmod(fd,0o440)
  with os.fdopen(fd,'wb') as f:f.write(rule_data);f.flush();os.fsync(f.fileno())
  run(['/usr/sbin/visudo','-c','-f',candidate])
 finally:os.unlink(candidate)
 created_rule=put(rule,rule_data,0o440)
 run(['/usr/sbin/visudo','-c'])
 if helper.read_bytes()!=HELPER_DATA or rule.read_bytes()!=rule_data:raise RuntimeError('Installation readback failed')
 receipt={'version':1,'helper':str(helper),'sha256':EXPECTED,'sudoers':str(rule),'user':'example','scope':['snapshot','read-log','network','repair vpn','repair monitor']}
 put(state/'installed.json',(json.dumps(receipt,sort_keys=True)+'\n').encode(),0o600)
 print(json.dumps({'installed':True,**receipt}))
except BaseException:
 if created_rule:rule.unlink()
 if created_helper:helper.unlink()
 if created_state:
  try:state.rmdir()
  except OSError:pass
 raise
'''
code = code.replace('example ALL=', args.user+' ALL=').replace("'user':'example'","'user':"+repr(args.user))
code = code.replace('__PAYLOAD__', repr(base64.b64encode(helper).decode())).replace('__SHA__', repr(hashlib.sha256(helper).hexdigest()))
(HERE / 'installer-reviewed.py').write_text(code)
bootstrap = "import base64;exec(compile(base64.b64decode(" + repr(base64.b64encode(code.encode()).decode()) + "),'<family-vpn-authorized-installer>','exec'))"
cmd = '/usr/bin/python3 -I -B -c ' + shlex.quote(bootstrap)
applescript = 'with timeout of 600 seconds\n  do shell script ' + json.dumps(cmd) + ' with administrator privileges\nend timeout\n'
(HERE / 'authorize-install.applescript').write_text(applescript)
(HERE / 'install-manifest.json').write_text(json.dumps({'helper_sha256':hashlib.sha256(helper).hexdigest(),'installer_sha256':hashlib.sha256(code.encode()).hexdigest()},indent=2)+'\n')
print(json.dumps({'prepared':True,'helper_sha256':hashlib.sha256(helper).hexdigest(),'installer_bytes':len(code)}))
