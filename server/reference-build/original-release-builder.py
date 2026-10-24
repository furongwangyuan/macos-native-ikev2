# Historical build implementation; not a configured deployment entry.
"""Ordinary fixed release assembly; never installs or starts a service."""
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys

HERE=Path(__file__).resolve().parent
PROJECT=HERE.parent
TARGET=PROJECT/'bundle'
COMMON_SHA='d85566bf5abc7b9ce9abe30d9d1c5abbee28291cc66cf0441cc68c26304b35de'
CONTROL_DATA=('install_io.py','installation.py','handoff.py','batch.py','diagnostics.py',
              'admission.py','finite_service.py','trial_install.py')
CONTROL=('activation_install.py','production_service.py','production_service_job.py','pki_registry_setup.py',
         'device_control.py','device_delivery.py','device_password.py')
HARNESS=('closed_checkpoint.py','coordinator_entry.py','coordinator_logic.py','fault_protocol.py',
         'fixed_entries.py','integration_readonly.py','native_adapter.py','observer_entry.py',
         'owner_entry.py','process_observe.py','receipt_store.py','role_logic.py')
BINDINGS={('control','installation.py'):'COMMON_SHA',
          ('control','finite_service.py'):'COMMON_MANIFEST_SHA256',
          ('harness','native_adapter.py'):'CLOSURE_SHA'}
LAUNCHERS=(('install-trial','安装或启用家庭VPN'),('service-disable','停止家庭VPN并恢复网络'),('service-status','查看家庭VPN状态'))
ARITY={action:0 for action,_ in LAUNCHERS}
ARITY.update({'device-add':2,'device-export':1,'device-password':1,'device-revoke':2})

def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def read(path):
    if path.is_symlink() or not path.is_file():raise ValueError('nonregular fixed source: '+str(path))
    return path.read_bytes()
def pinned(path,wanted):
    raw=read(path)
    if sha(raw)!=wanted:raise ValueError('source digest differs: '+str(path))
    return raw
def replace_once(text,marker,value):
    if text.count(marker)!=1:raise ValueError('build marker not unique: '+marker)
    return text.replace(marker,value)
def tree(root):
    if root.is_symlink():raise ValueError('build root symlink')
    out={}
    for p in sorted(root.rglob('*')):
        if p.is_symlink():raise ValueError('build symlink')
        if p.is_file():out[p.relative_to(root).as_posix()]=sha(p.read_bytes())
        elif not p.is_dir():raise ValueError('build special file')
    return out


def public_codes():
    codes=set()
    for folder in (PROJECT/'runtime',PROJECT/'control',PROJECT/'control-data',HERE):
        for path in folder.rglob('*.py'):
            if path.name.startswith(('check-','independent-')):continue
            for node in ast.walk(ast.parse(read(path),filename=str(path))):
                if isinstance(node,ast.Raise) and isinstance(node.exc,ast.Call) and node.exc.args:
                    arg=node.exc.args[0]
                    if isinstance(arg,ast.Constant) and type(arg.value)is str:
                        import re
                        if re.fullmatch('[a-z][a-z0-9_]{1,95}',arg.value):codes.add(arg.value)
    return frozenset(codes)

def previous_v9():
    parent=PROJECT.parent/'family-vpn-production-v9/bundle/installer-root.py'
    raw=pinned(parent,'7e0e408a5f80163d992ad80afa2824b4758be47ed7a802b29cc3cf2071eef276')
    for node in ast.parse(raw).body:
        if isinstance(node,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='PAYLOAD' for x in node.targets):
            return ast.literal_eval(node.value)
    raise ValueError('fixed v9 payload missing')

def payload():
    if COMMON_SHA is None:raise ValueError('successor runtime not frozen')
    subprocess.run(['/usr/bin/python3','-I','-B',str(PROJECT/'freeze_runtime.py'),'--check'],check=True)
    common=pinned(PROJECT/'runtime/candidate-pins.json',COMMON_SHA)
    manifest=json.loads(common)
    if (manifest['journal_version']!=8 or manifest['profile']!='production-native-fleet-v1'
            or manifest['native_installed'] is not False):raise ValueError('runtime source status')
    data={'common':{n:pinned(PROJECT/'runtime'/n,v) for n,v in manifest['runtime'].items()},
          'control':{n:read(PROJECT/'control-data'/n) for n in CONTROL_DATA},
          'harness':{n:read(PROJECT/'harness'/n) for n in HARNESS}}
    data['common']['candidate-pins.json']=common
    for name in CONTROL:
        if name in data['control']:raise ValueError('duplicate control module')
        data['control'][name]=read(PROJECT/'control'/name)
    for (group,name),key in BINDINGS.items():
        marker=key+'=None # FINAL_BUILD_BINDING'
        text=replace_once(data[group][name].decode(),marker,key+'='+repr(COMMON_SHA)+' # FINAL_BUILD_BINDING')
        data[group][name]=text.encode()
    parent_raw=read(PROJECT.parent/'family-vpn-production-v8/bundle/payload/harness/integration-pins.json')
    parent=json.loads(parent_raw)
    unchanged={n:sha(raw) for n,raw in data['harness'].items() if parent.get(n)==sha(raw)}
    for name,wanted in unchanged.items():pinned(PROJECT.parent/'family-vpn-production-v8/bundle/payload/harness'/name,wanted)
    data['harness']['parent-closure.json']=encoded(dict(version=1,checkpoint_version=5,
        common_journal_version=8,common_profile=manifest['profile'],common_manifest_sha256=COMMON_SHA,
        integrated_parent_manifest_sha256=sha(parent_raw),unchanged_protocol_files=unchanged))
    data['harness']['integration-pins.json']=encoded({n:sha(raw) for n,raw in data['harness'].items()})
    primitives=read(PROJECT/'control-data/install_io.py').decode()
    diagnostics=read(PROJECT/'control-data/diagnostics.py').decode()
    entry=read(PROJECT/'control-data/entry-template.py').decode()
    entry=replace_once(entry,'# IO_PRIMITIVES',primitives)
    entry=replace_once(entry,'# DIAGNOSTIC_PRIMITIVES',diagnostics)
    arguments=read(HERE/'arguments-template.py').decode()
    entry=replace_once(entry,'# ARGUMENT_PRIMITIVES',arguments)
    entry=replace_once(entry,'PUBLIC_CODES=frozenset() # PUBLIC_ERROR_CODES','PUBLIC_CODES=frozenset('+repr(sorted(public_codes()))+')')
    contract={g:{n:sha(raw) for n,raw in files.items()} for g,files in data.items()}
    entry=replace_once(entry,'CONTRACT = {} # ENTRY_CONTRACT','CONTRACT = '+repr(contract))
    data['control']['root_entry.py']=entry.encode()
    expected={g:{n:sha(raw) for n,raw in files.items()} for g,files in data.items()}
    root=read(HERE/'root-template.py').decode()
    root=replace_once(root,'# IO_PRIMITIVES',primitives)
    root=replace_once(root,'# ASSET_PRIMITIVES',read(HERE/'assets-template.py').decode())
    root=replace_once(root,'# DIAGNOSTIC_PRIMITIVES',diagnostics)
    root=replace_once(root,'# ARGUMENT_PRIMITIVES',arguments)
    root=replace_once(root,'PAYLOAD={} # RELEASE_PAYLOAD','PAYLOAD='+repr(expected))
    root=replace_once(root,'OLD_PAYLOAD={} # PREVIOUS_V9_PAYLOAD','OLD_PAYLOAD='+repr(previous_v9()))
    prior=json.loads(pinned(HERE/'previous-control-resources.json','e6dba6349509e179e0205ce4583a91b2bdaaff330ef54f2bd5d8555675317dce'))
    root=replace_once(root,'PRIOR_CONTROL={} # PREVIOUS_CONTROL_PAYLOAD','PRIOR_CONTROL='+repr(prior))
    root=replace_once(root,'PUBLIC_CODES=frozenset() # PUBLIC_ERROR_CODES','PUBLIC_CODES=frozenset('+repr(sorted(public_codes()))+')')
    ast.parse(root,filename='installer-root.py')
    for group,files in data.items():
        for name,raw in files.items():
            if name.endswith('.py'):ast.parse(raw,filename=group+'/'+name)
    return data,root.encode()

def launcher(action,root_sha,bootstrap):
    prefix=('''#!/bin/bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C LC_ALL=C
unset BASH_ENV ENV CDPATH PYTHONPATH PYTHONHOME
if [[ "$#" -ne 0 ]]; then echo '固定入口不接受参数。' >&2; exit 2; fi
HERE="$(cd -- "$(dirname -- "$0")" && pwd -P)"
ACTUAL="$(/usr/bin/shasum -a 256 "$HERE/installer-root.py" | /usr/bin/awk '{print $1}')"
if [[ "$ACTUAL" != "%s" ]]; then echo '安装程序已变化，请停止并复核。' >&2; exit 2; fi
echo %s
echo '只打开一次；文件核验暂时没有新行时，请保留窗口等待。'
echo '只输入 Mac 管理员密码；此入口不需要域名、手机或证书密码。'
echo '本程序不会重启 Mac。出现错误请保留报告，不要连续重复运行。'
ARGS=()
ROOT_BOOTSTRAP=%s
# FIXED_LOADER_END
'''%(root_sha,shlex.quote({'install-trial':'安装或启用服务；就绪后再用手机连接一次。','service-disable':'停止家庭 VPN 服务，并恢复原网络设置。','service-status':'只查看家庭 VPN 当前状态，不启动或停止服务。'}.get(action,'执行所选设备管理操作。')),shlex.quote(bootstrap)))
    if ARITY[action]:
        prefix+='read -r -p "设备编号（2至32位小写字母/数字/连字符，如 family02）：" DEVICE\nARGS=("$DEVICE")\n'
    if action=='device-add':
        prefix+='read -r -p "设备显示名称：" DISPLAY_NAME\nARGS+=("$DISPLAY_NAME")\necho "新增设备会暂停所有 VPN 连接，完成后仅恢复原本开启的服务。"\n'
    elif action=='device-revoke':
        prefix+='echo "将永久撤销此设备身份；再次使用需要新编号和新配置。"\nread -r -p "再次输入同一设备编号确认撤销：" CONFIRM_DEVICE\n[[ "$CONFIRM_DEVICE" == "$DEVICE" ]] || exit 2\nARGS+=("cessationOfOperation")\n'
    elif action=='device-export':
        client_sha=sha(read(HERE/'device-client.py'))
        prefix+='CLIENT_SHA="$(/usr/bin/shasum -a 256 "$HERE/device-client.py" | /usr/bin/awk \'{print $1}\')"\n'
        prefix+='[[ "$CLIENT_SHA" == '+shlex.quote(client_sha)+' ]] || exit 2\n'
    # macOS ships Bash 3.2: expanding an empty array under set -u fails.
    command='/usr/bin/sudo -- /usr/bin/python3 -I -B -c "$ROOT_BOOTSTRAP" "$HERE/installer-root.py" '+action
    if ARITY[action]:command+=' "${ARGS[@]}"'
    if action=='device-export':
        suffix=command+' | /usr/bin/python3 -I -B "$HERE/device-client.py" "$DEVICE"\n'
    elif action=='device-password':
        suffix='echo "安装密码仅在本机终端显示，请直接输入手机，不要复制到聊天。"\n'+command+'\n'
    else:
        suffix='REPORT="$(/usr/bin/mktemp "$HERE/public-report.XXXXXX")"\n'+command+' | /usr/bin/tee "$REPORT"\n'
    return (prefix+suffix).encode()

def main():
    if os.geteuid()==0 or sys.argv[1:]:raise SystemExit('ordinary fixed build only')
    data,root=payload()
    if TARGET.exists():
        previous=json.loads(read(PROJECT/'bundle-pins.json'))
        if tree(TARGET)!=previous:raise ValueError('changed existing bundle preserved')
        shutil.rmtree(TARGET)
    for group,files in data.items():
        for name,raw in files.items():
            path=TARGET/'payload'/group/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(raw);path.chmod(0o755 if name=='crypto/public-crl-verify' else 0o600)
    (TARGET/'installer-root.py').write_bytes(root);(TARGET/'installer-root.py').chmod(0o600)
    bootstrap=replace_once(read(HERE/'bootstrap-template.py').decode(),'__ROOT_SHA__',repr(sha(root)))
    bootstrap=replace_once(bootstrap,'__ROOT_ACTIONS__',repr(ARITY))
    ast.parse(bootstrap,filename='fixed-root-bootstrap.py')
    (TARGET/'fixed-root-bootstrap.py').write_text(bootstrap)
    for action,label in LAUNCHERS:
        path=TARGET/(label+'.command');path.write_bytes(launcher(action,sha(root),bootstrap));path.chmod(0o700)
        subprocess.run(['/bin/bash','-n',str(path)],check=True)
    for name in ('README.txt',):(TARGET/name).write_bytes(read(HERE/name))
    pins=tree(TARGET);(PROJECT/'bundle-pins.json').write_bytes(encoded(pins))
    report=dict(event='simple_service_candidate_built_not_installed',common_sha256=COMMON_SHA,
        installer_sha256=sha(root),bundle_files=len(pins),payload_files=sum(map(len,data.values())),
        native_installed=False,phone_same_version_tested=False,production_24h_tested=False)
    (PROJECT/'build-result.json').write_bytes(encoded(report));print(json.dumps(report,sort_keys=True))

if __name__=='__main__':
    raise SystemExit('Historical build source only. See reference-build/README.md; use tools/build_reference.py for the self-contained source package.')
