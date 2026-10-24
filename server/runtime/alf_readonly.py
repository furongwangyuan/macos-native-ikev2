"""Extracted reviewed functions; import performs no native operation."""
import re
import native_support as support
ALF='/usr/libexec/ApplicationFirewall/socketfilterfw'
def command(args):return support.run(args,timeout=3).stdout.strip()


def parse_apps(text):
    lines = text.splitlines()
    m = re.fullmatch(r'Total number of apps = (0|[1-9][0-9]*)\s*', lines[0] if lines else '')
    if not m or len(lines) != 1 + 2 * int(m[1]):
        raise RuntimeError('Unknown ALF app-list layout')
    apps = {}
    for i in range(int(m[1])):
        m = re.fullmatch(str(i + 1) + r' : (/[^\r\n]+?)\s*', lines[1 + 2 * i])
        if not m or m[1] != m[1].strip() or m[1] in apps:
            raise RuntimeError('Unknown or duplicate ALF app path')
        state = lines[2 + 2 * i].strip()
        if state not in ['(Allow incoming connections)', '(Block incoming connections)']:
            raise RuntimeError('Unknown ALF app state')
        apps[m[1]] = state == '(Allow incoming connections)'
    return apps

def parse_flags(text):
    lines = text.splitlines()
    names = ['built-in', 'downloaded']
    if len(lines) != 2:
        raise RuntimeError('Unknown ALF automatic-signing layout')
    values = []
    for line, name in zip(lines, names):
        m = re.fullmatch('Automatically allow ' + name + r' signed software (ENABLED|DISABLED)\.', line)
        if not m:
            raise RuntimeError('Unknown ALF automatic-signing state')
        values.append(m[1] == 'ENABLED')
    return dict(zip(['builtin', 'downloaded'], values))

def flags():
    return parse_flags(command([ALF, '--getallowsigned']))


def parse_global(text):
    known = {'Firewall is disabled. (State = 0)': 0, 'Firewall is enabled. (State = 1)': 1,
             'Firewall is blocking all non-essential incoming connections. (State = 2)': 2}
    if text not in known:
        raise RuntimeError('Unknown ALF global state')
    return known[text]


def parse_blockall(block):
    blocks = {'Firewall is blocking all non-essential incoming connections.': True,
              'Firewall has block all state set to disabled.': False}
    if block not in blocks:
        raise RuntimeError('Unknown ALF block-all state')
    return blocks[block]

def firewall():
    return parse_global(command([ALF, '--getglobalstate'])), parse_blockall(command([ALF, '--getblockall']))


def snapshot():
    # One fresh invocation performs the same five read-only getters, in this
    # exact observed order. No state or permission result survives this call.
    # A failed getter, extra output or partial section must not become a sample.
    result = support.run([ALF, '--getglobalstate', '--getblockall',
                          '--getstealthmode', '--listapps', '--getallowsigned'], timeout=3)
    if result.stderr:
        raise RuntimeError('Unknown ALF combined diagnostic')
    lines = result.stdout.strip().splitlines()
    if len(lines) < 6:
        raise RuntimeError('Unknown ALF combined layout')
    global_state, blockall = parse_global(lines[0].strip()), parse_blockall(lines[1].strip())
    stealth = lines[2].strip()
    if stealth not in ['Firewall stealth mode is on', 'Firewall stealth mode is off']:
        raise RuntimeError('Unknown ALF stealth state')
    return dict(global_state=global_state, blockall=blockall, stealth=stealth,
                apps=parse_apps('\n'.join(lines[3:-2]).strip()),
                **parse_flags('\n'.join(lines[-2:]).strip()))
