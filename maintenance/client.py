"""Unprivileged client for the single fixed sudo capability."""
import json
import subprocess
import sys

args = sys.argv[1:]
if args in (['snapshot'], ['network']):
    request = {'action': args[0]}
elif len(args) == 2 and args[0] == 'repair' and args[1] in ('vpn', 'monitor'):
    request = {'action': 'repair', 'job': args[1]}
elif len(args) == 3 and args[0] == 'read-log':
    request = {'action': 'read-log', 'id': args[1], 'offset': int(args[2])}
else:
    raise SystemExit('Usage: client.py snapshot | network | repair vpn|monitor | read-log LOG_ID BYTE_OFFSET')
result = subprocess.run(['/usr/bin/sudo', '-n', '/usr/bin/python3', '-I', '-B',
                         '/Library/PrivilegedHelperTools/org.familyvpn.maintenance.py'],
                        input=json.dumps(request) + '\n', text=True, capture_output=True, timeout=120)
sys.stdout.write(result.stdout)
sys.stderr.write(result.stderr)
raise SystemExit(result.returncode)
