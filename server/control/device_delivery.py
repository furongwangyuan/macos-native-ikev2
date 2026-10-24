"""Private profile -> fixed root stdout transport, never a user-path writer.
The verified successor manager holds its real closed/original-lock scope and
passes the actual profile_export return. This helper does not stop/start a
service, create a credential, reveal a password, or authorize an export alone.
"""
import base64,hashlib,json,plistlib,re,xml.etree.ElementTree as ET
MAX_PROFILE=2*1024*1024
MAX_JSON=4*((MAX_PROFILE+2)//3)+16384
RESULT_KEYS={'event','device','registry_revision','profile_sha256','private_relative_path','encrypted_identity_included','password_exported','iphone_installation_verified','data_started'}
class Refused(RuntimeError):pass
def device(value):
    if type(value)is not str or not re.fullmatch('[a-z][a-z0-9-]{0,30}[a-z0-9]',value):raise Refused('profile_device_id')
    return value
def digest(raw):return hashlib.sha256(raw).hexdigest()
def exported(value,expected=None):
    if type(value)is not dict or set(value)!=RESULT_KEYS:raise Refused('profile_export_result_fields')
    ident=device(value['device']);revision=value['registry_revision']
    if (expected is not None and ident!=expected or value['event']!='membership_private_profile_exported'
        or type(revision)is not int or not 1<=revision<=2147483647 or type(value['profile_sha256'])is not str
        or not re.fullmatch('[a-f0-9]{64}',value['profile_sha256'])or type(value['private_relative_path'])is not str
        or not re.fullmatch('clients/'+ident+'/exports/enrollment-[a-f0-9]{32}-r'+str(revision)+r'\.mobileconfig',value['private_relative_path'])
        or value['encrypted_identity_included']is not True or value['password_exported']is not False
        or value['iphone_installation_verified']is not False or value['data_started']is not False):raise Refused('profile_export_result_contract')
    return ident

def profile(raw,ident):
    # Accept exactly the fixed builder's canonical UTF-8 XML format. Before any
    # parser, reject entity definitions, NUL/alternative encodings, oversized
    # input; then bound the XML tree and forbid duplicate dictionary keys.
    if (type(raw)is not bytes or not 128<=len(raw)<=MAX_PROFILE or not raw.startswith(b'<?xml version="1.0" encoding="UTF-8"?>\n')
        or b'\x00'in raw or b'<!ENTITY'in raw):raise Refused('profile_xml_format')
    declaration=b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    if raw.count(b'<!DOCTYPE')!=1 or declaration not in raw:raise Refused('profile_xml_doctype')
    try:tree=ET.fromstring(raw)
    except (ValueError,ET.ParseError):raise Refused('profile_xml_parse')from None
    todo=[(tree,0)];count=0
    while todo:
        node,depth=todo.pop();count+=1
        if count>512 or depth>16 or node.tag not in {'plist','dict','array','key','string','integer','true','false','data'}:raise Refused('profile_xml_tree')
        if node.attrib!=({'version':'1.0'}if node is tree else {}):raise Refused('profile_xml_attributes')
        children=list(node)
        if node.tag=='integer'and (type(node.text)is not str or not re.fullmatch('-?[0-9]{1,20}',node.text)):raise Refused('profile_integer_bound')
        if node.tag in ('key','string')and len(node.text or '')>4096:raise Refused('profile_string_bound')
        if node.tag=='dict':
            if len(children)%2:raise Refused('profile_dictionary_shape')
            keys=[]
            for i in range(0,len(children),2):
                key=children[i]
                if key.tag!='key'or type(key.text)is not str or len(key.text)>128 or 'password'in key.text.lower()or key.text.lower()in ('sharedsecret','secret'):raise Refused('profile_secret_or_unknown_key')
                keys.append(key.text)
            if len(keys)!=len(set(keys)):raise Refused('profile_duplicate_key')
        todo.extend((child,depth+1)for child in children)
    if tree.tag!='plist'or len(tree)!=1:raise Refused('profile_plist_root')
    try:value=plistlib.loads(raw)
    except (ValueError,TypeError,OverflowError,plistlib.InvalidFileException):raise Refused('profile_plist_parse')from None
    if plistlib.dumps(value,fmt=plistlib.FMT_XML,sort_keys=False)!=raw:raise Refused('profile_not_canonical')
    if type(value)is not dict or value.get('PayloadType')!='Configuration'or type(value.get('PayloadVersion'))is not int or value['PayloadVersion']!=1:raise Refused('profile_configuration')
    entries=value.get('PayloadContent')
    if type(entries)is not list or len(entries)!=3 or any(type(x)is not dict for x in entries):raise Refused('profile_payloads')
    kinds=[x.get('PayloadType')for x in entries]
    if any(type(k)is not str for k in kinds)or set(kinds)!={'com.apple.security.root','com.apple.security.pkcs12','com.apple.vpn.managed'}:raise Refused('profile_payload_types')
    if any(type(x.get('PayloadUUID'))is not str or not re.fullmatch('[A-F0-9]{8}-(?:[A-F0-9]{4}-){3}[A-F0-9]{12}',x['PayloadUUID'])for x in entries):raise Refused('profile_payload_uuid')
    ca,identity,vpn=(next(x for x in entries if x['PayloadType']==kind)for kind in ('com.apple.security.root','com.apple.security.pkcs12','com.apple.vpn.managed'))
    if any(type(x.get('PayloadContent'))is not bytes or len(x['PayloadContent'])<16 or x['PayloadContent'][0]!=0x30 for x in (ca,identity)):raise Refused('profile_binary_identity')
    ike=vpn.get('IKEv2')
    if (vpn.get('VPNType')!='IKEv2'or type(ike)is not dict or ike.get('RemoteAddress')!='vpn.example.com'
        or ike.get('RemoteIdentifier')!='vpn.family.home.arpa'or ike.get('LocalIdentifier')!=ident+'.family.home.arpa'
        or ike.get('AuthenticationMethod')!='Certificate'or ike.get('PayloadCertificateUUID')!=identity.get('PayloadUUID')
        or type(ike.get('IncludeAllNetworks'))is not int or ike['IncludeAllNetworks']!=1
        or any(type(ike.get(k))is not int or ike[k]!=0 for k in ('ExcludeLocalNetworks','ExcludeAPNs','ExcludeCellularServices','ExcludeDeviceCommunication','OnDemandEnabled'))):raise Refused('profile_vpn_binding')
    dns=vpn.get('DNS')
    if type(dns)is not dict or dns.get('SupplementalMatchDomains')!=['']or dns.get('ServerAddresses')!=['202.188.18.188','1.9.1.9']:raise Refused('profile_dns_binding')
    return raw

def encode_profile(io,result):
    ident=exported(result)
    raw=io.read(io.root/result['private_relative_path'],MAX_PROFILE)
    if digest(raw)!=result['profile_sha256']:raise Refused('profile_live_hash_changed')
    profile(raw,ident)
    return dict(device=ident,profile_sha256=digest(raw),profile_base64=base64.b64encode(raw).decode('ascii'))

if __name__=='__main__':raise SystemExit('Only the fixed verified manager may encode a checked private profile.')
