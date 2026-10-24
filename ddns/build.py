#!/usr/bin/env python3
"""Configure a self-contained DDNS build and regenerate every source binding."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser()
p.add_argument('--domain',default='example.com')
p.add_argument('--subdomain',default='vpn')
p.add_argument('--interface',default='en0')
p.add_argument('--output',type=Path,default=HERE/'build')
args=p.parse_args()
if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?',args.domain) or '..' in args.domain or '.' not in args.domain:
    p.error('domain must be an ASCII DNS domain (punycode for international names)')
if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',args.subdomain): p.error('invalid subdomain label')
if not re.fullmatch(r'en[0-9]+',args.interface): p.error('use a macOS Ethernet interface such as en0')
out=args.output.resolve();out.mkdir(parents=True,exist_ok=True)
for name in ('helper','scheduler'):
    target=out/name
    if target.exists(): shutil.rmtree(target)
    shutil.copytree(HERE/name,target,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
helper=out/'helper/update.py';source=helper.read_text()
source=re.sub(r'^DOMAIN, HOST, FQDN = .*$',f'DOMAIN, HOST, FQDN = {args.domain!r}, {args.subdomain!r}, {(args.subdomain+"."+args.domain+".")!r}',source,flags=re.M)
source=source.replace("'en0'",repr(args.interface)).replace('"en0"',repr(args.interface))
helper.write_text(source.replace('vpn.example.com',args.subdomain+'.'+args.domain))
launcher_builder=out/'helper/build-package.py'
launcher_builder.write_text(launcher_builder.read_text().replace('vpn.example.com',args.subdomain+'.'+args.domain))
installer_template=out/'helper/install-root-template.py'
installer_template.write_text(installer_template.read_text().replace('vpn.example.com',args.subdomain+'.'+args.domain))
subprocess.run([sys.executable,'-I','-B',str(out/'helper/build-package.py')],check=True)
sha=hashlib.sha256(helper.read_bytes()).hexdigest()
scheduler=out/'scheduler/scheduler.py';source=scheduler.read_text()
source=re.sub(r'^HELPER_SHA = .*$',f'HELPER_SHA = {sha!r}',source,flags=re.M);scheduler.write_text(source)
subprocess.run([sys.executable,'-I','-B',str(out/'scheduler/build-package.py')],check=True)
manifest={str(f.relative_to(out)):hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(out.rglob('*')) if f.is_file() and f.name!='manifest.json' and '__pycache__' not in f.parts}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n')
print(json.dumps({'built':True,'files':len(manifest),'credentials_read':False,'installed':False,'example_only':args.domain=='example.com'}))
