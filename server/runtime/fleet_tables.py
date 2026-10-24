"""Fixed private active table reads; rule text alone cannot prove a VIP set."""
import ipaddress
import native_support as s

TABLES={'active4':'familyvpn_active4','active6':'familyvpn_active6'}
ANCHOR='org.familyvpn.production-guardian'

def expected(devices):
    return {key:sorted(getattr(d.generation,'vip'+key[-1]) for d in devices) for key in TABLES}

def validate(value):
    if type(value)is not dict or set(value)!=set(TABLES):raise s.Refused('fleet_table_shape')
    for key,items in value.items():
        if type(items)is not list or len(items)>16:raise s.Refused('fleet_table_bound')
        parsed=[]
        for x in items:
            try:ip=ipaddress.ip_address(x)
            except (ValueError,TypeError):raise s.Refused('fleet_table_address') from None
            if str(ip)!=x or ip.version!=int(key[-1]):raise s.Refused('fleet_table_address')
            parsed.append(str(ip))
        if items!=sorted(set(parsed)):raise s.Refused('fleet_table_order')
    return value

def read():
    result={}
    for key,name in TABLES.items():
        value=s.run(['/sbin/pfctl','-a',ANCHOR,'-t',name,'-T','show'])
        if value.stderr.strip() not in ('','No ALTQ support in kernel\nALTQ related functions disabled'):
            raise s.Refused('fleet_table_read_warning')
        parsed=[]
        for line in value.stdout.splitlines():
            text=line.strip()
            if not text:continue
            try:n=ipaddress.ip_network(text,strict=True)
            except ValueError:raise s.Refused('fleet_table_output_unknown') from None
            if n.num_addresses!=1 or n.version!=int(key[-1]):raise s.Refused('fleet_table_not_host')
            parsed.append(str(n.network_address))
        if len(parsed)!=len(set(parsed)):raise s.Refused('fleet_table_duplicate')
        result[key]=sorted(parsed)
    return validate(result)
