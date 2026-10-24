#!/usr/bin/env python3
"""Configure ordinary-user uploader source; credentials are never an input."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser()
p.add_argument('--site-url',required=True,help='Confirmed owner-private Sites HTTPS origin')
p.add_argument('--keychain-account',required=True,help='Non-secret private Site project ID')
p.add_argument('--output',type=Path,default=HERE/'build')
args=p.parse_args();url=urlsplit(args.site_url)
if url.scheme!='https' or not url.hostname or not url.hostname.endswith('.chatgpt.site') or url.username or url.password or url.port or url.path not in ('','/') or url.query or url.fragment:
    p.error('supply a private chatgpt.site HTTPS origin without path, password or query')
if not re.fullmatch(r'appgprj_[A-Za-z0-9_]{1,128}',args.keychain_account):p.error('invalid private Site project ID')
out=args.output.resolve();out.mkdir(parents=True,exist_ok=True)
for name in ('uploader.mjs','model.mjs','daily_model_v2.mjs','install.mjs'):
    source=(HERE/name).read_text()
    if name=='uploader.mjs':
        source=source.replace('export const CONFIGURED=false;','export const CONFIGURED=true;')
        source=source.replace('https://vpn-monitor.example.invalid/api/telemetry',args.site_url.rstrip('/')+'/api/telemetry')
        source=source.replace('appgprj_REPLACE_WITH_YOUR_PRIVATE_SITE',args.keychain_account)
    (out/name).write_text(source)
files={name:hashlib.sha256((out/name).read_bytes()).hexdigest() for name in ('uploader.mjs','model.mjs','daily_model_v2.mjs')}
(out/'source-pins.json').write_text(json.dumps({'version':1,'files':files},indent=2)+'\n')
print(json.dumps({'built':True,'credentials_read':False,'installed':False}))
