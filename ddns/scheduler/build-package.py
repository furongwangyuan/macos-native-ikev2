"""Work-only pinning. Does not install, run launchctl, read secrets or network."""
from pathlib import Path
import hashlib
import json
import plistlib
import subprocess

here=Path(__file__).resolve().parent
resources={name:hashlib.sha256((here/name).read_bytes()).hexdigest()
    for name in ('scheduler.py','org.familyvpn.ddns.plist')}
compile((here/'scheduler.py').read_bytes(),'scheduler.py','exec')
plistlib.loads((here/'org.familyvpn.ddns.plist').read_bytes())
control=(here/'control-template.py').read_text().replace('__EXPECTED__',repr(resources)).replace('__HELPER_SHA__',hashlib.sha256((here.parent/'helper/update.py').read_bytes()).hexdigest())
compile(control,'control-root.py','exec')
(here/'control-root.py').write_text(control)
control_sha=hashlib.sha256(control.encode()).hexdigest()
manifest={**resources,'control-root.py':control_sha}
for name,action,description in [('安装DDNS自动更新.command','install','安装固定域名的自动更新调度'),
    ('安装并核验DDNS自动更新.command','install-and-watch','安装后最多等待8分钟，只读核验首次自动运行；关闭本窗口不会卸载调度'),
    ('检查DDNS自动更新.command','check','只读检查自动更新状态，不读取口令或发送更新请求'),
    ('卸载DDNS自动更新.command','remove','卸载自动更新调度，保留口令和当前DNS记录')]:
    launcher='''#!/bin/bash
set -uo pipefail
umask 077
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
REPORT="$HERE/ddns-__ACTION__-$(date +%Y%m%d-%H%M%S).txt"
echo '__DESCRIPTION__。只会要求Mac管理员密码，不会要求域名口令。'
if ! /usr/bin/sudo -v </dev/tty; then
    echo '管理员认证未完成，已停止。'
    exit 1
fi
BOOTSTRAP="$(/bin/cat <<'PYPIN'
from pathlib import Path
import hashlib, os, stat, sys
p=Path(sys.argv[2])/'control-root.py'
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(fd,'rb') as f:
    st=os.fstat(f.fileno())
    if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size>100000:
        sys.exit('Untrusted control resource; no code executed')
    data=f.read(100001)
if len(data)>100000 or hashlib.sha256(data).hexdigest()!='__CONTROL_SHA__':
    sys.exit('Reviewed control hash differs; no code executed')
sys.argv=[str(p),sys.argv[1],sys.argv[2]]
exec(compile(data,str(p),'exec'),{'__name__':'__main__','__file__':str(p)})
PYPIN
)"
/usr/bin/sudo -n -u root -- /usr/bin/python3 -I -c "$BOOTSTRAP" __ACTION__ "$HERE" </dev/null 2>&1 | /usr/bin/tee -i "$REPORT"
result=${PIPESTATUS[0]}
echo "返回状态 ${result}。报告只含固定检查结果；不要在此输入域名口令。"
exit "$result"
'''.replace('__ACTION__',action).replace('__DESCRIPTION__',description).replace('__CONTROL_SHA__',control_sha)
    path=here/name;path.write_text(launcher);path.chmod(0o755)
    subprocess.run(['/bin/bash','-n',str(path)],check=True)
    manifest[name]=hashlib.sha256(path.read_bytes()).hexdigest()
(here/'package-digests.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n')
print('Pinned work-only DDNS scheduler/install/watch/remove/check package. No installation or network.')
