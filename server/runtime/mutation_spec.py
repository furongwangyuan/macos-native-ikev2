"""Finite native mutator grammar. No environment-selected paths or commands."""
from pathlib import Path
import re
import ipaddress
from alf_transaction import app_path

BASE=Path('/usr/local/family-vpn/production-guardian')
STATE=Path('/private/var/db/family-vpn/production-guardian')
RUN=Path('/private/var/run/family-vpn/production-guardian')
PFC='/private/etc/pf.conf'
ANCHOR='org.familyvpn.production-guardian'
SWAN='/usr/local/family-vpn/strongswan-6.1.0/sbin/swanctl'
URI='unix:///var/run/family-vpn/charon.vici'
ALF='/usr/libexec/ApplicationFirewall/socketfilterfw'
SYS={'net.inet.ip.forwarding':{0,1},'net.inet6.ip6.forwarding':{0,1},
     'net.inet.ip.redirect':{0,1},'net.inet6.ip6.redirect':{0,1},'net.inet.ipsec.esp_port':{0,4500}}


class InvalidMutation(ValueError):pass


def classification(argv):
    args=[str(x) for x in argv]
    if not args or any('\0' in x or '\n' in x for x in args):raise InvalidMutation('invalid_command')
    program=args[0];tail=args[1:]
    if program=='/sbin/pfctl':
        if tail in [['-sr'],['-sn'],['-ss'],['-s','info'],['-s','References'],['-s','dummynet']]:return 'read'
        if len(tail)==3 and tail[:1]==['-a'] and tail[1] in [ANCHOR,'com.apple'] and tail[2] in ['-sr','-sn']:return 'read'
        if len(tail)==2 and tail[0]=='-nf' and tail[1] in [str(RUN/'pf-main.conf'),str(RUN/'pf-restore.conf')]:return 'read'
        if (len(tail)==6 and tail[:4]==['-n','-v','-a',ANCHOR] and tail[4]=='-f' and
                tail[5] in [str(RUN/'guard.pf'),str(RUN/'active.pf')]):return 'read'
        if len(tail)==6 and tail[:2]==['-a',ANCHOR] and tail[2]=='-t' and tail[3] in ('familyvpn_active4','familyvpn_active6') and tail[4:]==['-T','show']:return 'read'
        if tail==['-E']:return 'mutate'
        if len(tail)==2 and tail[0]=='-X' and re.fullmatch(r'[1-9][0-9]{0,19}',tail[1]):return 'mutate'
        if tail==['-f',PFC]:return 'mutate'
        if (len(tail)==4 and tail[:3]==['-a',ANCHOR,'-f'] and
                tail[3] in [str(RUN/'guard.pf'),str(RUN/'active.pf'),str(RUN/'empty.pf')]):return 'mutate'
        for pool,anynet in [('10.77.26.0/24','0.0.0.0/0'),('fd6d:fe83:ab27:2600::/64','::/0')]:
            if tail in [['-k',pool],['-k',anynet,'-k',pool]]:return 'mutate'
        # Exact individual addresses only; runtime Dispatcher additionally checks
        # durable registered VIP ownership before permitting these commands.
        if tail[:1]==['-k'] and len(tail) in (2,4):
            try:
                host=ipaddress.ip_address(tail[-1])
                pool=ipaddress.ip_network('10.77.26.0/24' if host.version==4 else 'fd6d:fe83:ab27:2600::/64')
                if str(host)==tail[-1] and host in pool and (len(tail)==2 or tail[:3]==['-k','0.0.0.0/0' if host.version==4 else '::/0','-k']):return 'mutate'
            except ValueError:pass
        raise InvalidMutation('unlisted_pfctl_command')
    if program=='/usr/sbin/sysctl':
        if len(tail)==2 and tail[0]=='-n' and tail[1] in [*SYS,'kern.boottime']:return 'read'
        if tail==['net.inet.ip.forwarding','net.inet6.ip6.forwarding',
                  'net.inet.ip.redirect','net.inet6.ip6.redirect']:return 'read'
        if len(tail)==2 and tail[0]=='-w':
            key,sep,value=tail[1].partition('=')
            if sep and key in SYS and value.isdecimal() and int(value) in SYS[key]:return 'mutate'
        raise InvalidMutation('unlisted_sysctl_command')
    if program=='/usr/sbin/setkey':
        if tail in [['-DP'],['-D']]:return 'read'
        fixed=[str(STATE/name) for name in ['floor-add-0.conf','floor-add-1.conf','floor-gc-add.conf',
                                          'keeper-held-keeper.conf','keeper-timer-trigger.conf']]
        if len(tail)==3 and tail[:2]==['-n','-f'] and tail[2] in fixed:return 'read'
        if len(tail)==2 and tail[0]=='-f' and tail[1] in fixed:return 'mutate'
        raise InvalidMutation('unlisted_setkey_command')
    if program==SWAN:
        if tail==['--load-all','--noprompt','--uri',URI,'--file',
                   '/usr/local/etc/family-vpn/swanctl/swanctl.guardian-test.conf']:return 'mutate'
        if tail in [['--list-sas','--uri',URI],['--list-certs','--type','x509_crl','--pem','--uri',URI]]:return 'read'
        raise InvalidMutation('unlisted_vici_command')
    if program==ALF and len(tail)==1 and tail[0] in [
            '--getallowsigned','--getglobalstate','--getblockall','--getstealthmode','--listapps']:return 'read'
    if program==ALF and tail==['--getglobalstate','--getblockall','--getstealthmode',
                              '--listapps','--getallowsigned']:return 'read'
    if program==ALF and len(tail)==2:
        if tail[0] in ['--setblockall','--setallowsigned','--setallowsignedapp'] and tail[1] in ['on','off']:
            return 'mutate'
        if tail[0] in ['--blockapp','--unblockapp'] and app_path(tail[1]):return 'mutate'
    if program=='/bin/ls' and len(tail)==2 and tail[0]=='-lde':return 'read'
    if program=='/usr/bin/pgrep' and tail==['-x','charon']:return 'read'
    if program=='/usr/sbin/netstat' and len(tail)==3 and tail[:2]==['-rn','-f'] and tail[2] in ['inet','inet6']:return 'read'
    if program=='/sbin/ifconfig' and tail==['en0']:return 'read'
    if program=='/sbin/route' and len(tail)==4 and tail[:2]==['-n','get'] and tail[2] in ['-inet','-inet6']:return 'read'
    if program=='/usr/sbin/lsof':
        if tail==['-nP','-iTCP:47729','-F','pftn']:return 'read'
        if (len(tail)==7 and tail[:3]==['-nP','-a','-p'] and tail[3].isdecimal() and tail[4:]==['-F','p','/private/var/run/family-vpn/charon.vici']):return 'read'
        if tail in [['-nP','/private/var/run/family-vpn/charon.vici'],['-nP','-iUDP:500','-iUDP:4500']]:return 'read'
        if (len(tail)==7 and tail[:3]==['-nP','-a','-p'] and tail[3].isdecimal() and
                tail[4:]==['-iUDP','-F','pftn']):return 'read'
    if program=='/usr/bin/curl':
        prefix=['--disable','--fail','--silent','--show-error','--noproxy','*','--connect-timeout','4',
                '--max-time','7','--interface','en0']
        urls=['https://www.cloudflare.com/cdn-cgi/trace','https://1.1.1.1/cdn-cgi/trace',
              'https://[2606:4700:4700::1111]/cdn-cgi/trace']
        if len(tail)==14 and tail[:12]==prefix and tail[12] in ['-4','-6'] and tail[13] in urls:return 'read'
    raise InvalidMutation('unlisted_native_command')


def require_mutation(argv):
    if (not isinstance(argv,list) or not 1<=len(argv)<=10 or any(type(x)is not str or len(x)>512 for x in argv)
            or classification(argv)!='mutate'):
        raise InvalidMutation('fixed_mutator_required')
    return tuple(argv)


def require_for_mode(argv,allow_data):
    args=list(require_mutation(argv))
    if type(allow_data)is not bool:raise InvalidMutation('strict_session_mode_required')
    if not allow_data:
        program=args[0];tail=args[1:]
        if program==ALF:raise InvalidMutation('closed_alf_write_unavailable')
        if program=='/sbin/pfctl' and ('-k' in tail or str(RUN/'active.pf') in tail):
            raise InvalidMutation('closed_pf_data_write_unavailable')
        if program=='/usr/sbin/sysctl' and tail[:1]==['-w']:
            key,_,value=tail[1].partition('=')
            if key in ('net.inet.ip.redirect','net.inet6.ip6.redirect'):
                raise InvalidMutation('closed_redirect_write_unavailable')
            if key in ('net.inet.ip.forwarding','net.inet6.ip6.forwarding') and value!='0':
                raise InvalidMutation('closed_forwarding_write_unavailable')
    return tuple(args)
