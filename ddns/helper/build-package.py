"""Pin a work-only candidate; does not publish, install, read secrets or send requests."""
from pathlib import Path
import hashlib
import json
import subprocess

here = Path(__file__).resolve().parent
helper = (here / 'update.py').read_bytes()
compile(helper, 'update.py', 'exec')
helper_sha = hashlib.sha256(helper).hexdigest()
installer = (here / 'install-root-template.py').read_text().replace('__HELPER_SHA__', helper_sha)
compile(installer, 'install-root.py', 'exec')
(here / 'install-root.py').write_text(installer)
installer_sha = hashlib.sha256(installer.encode()).hexdigest()
bridge = (here / 'credential-bridge-template.py').read_text().replace('__INSTALLER_SHA__', installer_sha)
compile(bridge, 'credential-bridge.py', 'exec')
(here / 'credential-bridge.py').write_text(bridge)
bridge_sha = hashlib.sha256(bridge.encode()).hexdigest()
launcher = '''#!/bin/bash
set -uo pipefail
umask 077
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
REPORT="$HERE/ddns-setup-$(date +%Y%m%d-%H%M%S).txt"
echo '首先只输入Mac管理员密码；随后程序会检查凭据传递条件。'
echo '只有看到 New Dynadot DDNS password (hidden) 时才输入新域名口令。'
echo '仅检查并更新 vpn.example.com 的 A 记录；不启用定时任务，不启动 VPN。'
if ! /usr/bin/sudo -v </dev/tty; then
    echo '管理员认证未完成，程序已停止。不要继续输入任何口令。'
    exit 1
fi
BOOTSTRAP="$(/bin/cat <<'PYBRIDGE'
from pathlib import Path
import hashlib, os, stat, sys
path = Path(sys.argv[1]) / 'credential-bridge.py'
fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(fd, 'rb') as handle:
    info = os.fstat(handle.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_size > 100000:
        sys.exit('Credential bridge is not a bounded regular file; no code executed')
    data = handle.read(100001)
if len(data) > 100000 or hashlib.sha256(data).hexdigest() != '__BRIDGE_SHA__':
    sys.exit('Credential bridge changed after review; no code executed')
sys.argv = [str(path)]
exec(compile(data, str(path), 'exec'), {'__name__': '__main__', '__file__': str(path)})
PYBRIDGE
)"
/usr/bin/python3 -I -c "$BOOTSTRAP" "$HERE" </dev/tty 2>&1 | /usr/bin/tee -i "$REPORT"
result=${PIPESTATUS[0]}
echo "返回状态 ${result}；报告只含核验结果。定时更新仍未启用。"
exit "$result"
'''.replace('__BRIDGE_SHA__', bridge_sha)
entry = here / 'import-DDNS-password.command'
entry.write_text(launcher)
entry.chmod(0o755)
(here / 'package-digests.json').write_text(json.dumps({'update.py': helper_sha,
    'install-root.py': installer_sha, 'credential-bridge.py': bridge_sha,
    entry.name: hashlib.sha256(launcher.encode()).hexdigest()}, indent=2) + '\n')
subprocess.run(['/bin/bash', '-n', str(entry)], check=True)
print('Work-only DDNS candidate pinned; no root installation or network request.')
