#!/usr/bin/env python3
"""Ordinary-user half of the fixed profile pipe; never calls sudo or a shell.
stdin must contain one successful bounded manager JSON object. stdout contains
only local file path/hash metadata, never the profile or password. The profile
contains a previously verified encrypted PKCS#12; this client checks its bound
bytes/format, not independent cryptographic password strength or iOS behavior.
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

import ctypes,errno,os,secrets,stat,sys
from pathlib import Path

def pairs(rows):
    out={}
    for key,value in rows:
        if key in out:raise Refused('profile_duplicate_json')
        out[key]=value
    return out

def transport(raw,ident):
    device(ident)
    if type(raw)is not bytes or not 1<=len(raw)<=MAX_JSON:raise Refused('profile_transport_size')
    try:value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(Refused('profile_nonfinite_json')))
    except (ValueError,UnicodeError,RecursionError):raise Refused('profile_transport_json')from None
    if (type(value)is not dict or set(value)!={'version','stage','action','result','delivery','service'}
        or type(value['version'])is not int or value['version']!=1 or value['stage']!='production_control'or value['action']!='device-export'):
        raise Refused('profile_transport_contract')
    exported(value['result'],ident)
    service=value['service'];delivery=value['delivery']
    if (type(service)is not dict or set(service)!={'restart_requested','left_disabled','health_verified'}
        or type(service['restart_requested'])is not bool or type(service['left_disabled'])is not bool or service['health_verified']is not False):raise Refused('profile_service_contract')
    if (type(delivery)is not dict or set(delivery)!={'device','profile_sha256','profile_base64'}or delivery['device']!=ident
        or delivery['profile_sha256']!=value['result']['profile_sha256']or type(delivery['profile_base64'])is not str
        or len(delivery['profile_base64'])>4*((MAX_PROFILE+2)//3)):raise Refused('profile_delivery_contract')
    try:content=base64.b64decode(delivery['profile_base64'],validate=True)
    except (ValueError,UnicodeError):raise Refused('profile_transport_base64')from None
    if base64.b64encode(content).decode('ascii')!=delivery['profile_base64']or digest(content)!=delivery['profile_sha256']:raise Refused('profile_transport_hash')
    return profile(content,ident)

def acl_absent(fd):
    # Same Darwin FD API/strict absent contract as the reviewed private reader.
    lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
    lib.acl_get_fd_np.argtypes=[ctypes.c_int,ctypes.c_int];lib.acl_get_fd_np.restype=ctypes.c_void_p
    lib.acl_free.argtypes=[ctypes.c_void_p];lib.acl_free.restype=ctypes.c_int
    ctypes.set_errno(0);acl=lib.acl_get_fd_np(fd,0x100);error=ctypes.get_errno()
    if acl:
        try:raise Refused('profile_export_acl_present')
        finally:
            if lib.acl_free(acl)!=0:raise Refused('profile_export_acl_free')
    if error!=errno.ENOENT:raise Refused('profile_export_acl_unknown')

def stamp(st):return(st.st_dev,st.st_ino,st.st_uid,st.st_gid,st.st_mode,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
def directory(fd,mode=None):
    st=os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode)or st.st_uid!=os.getuid()or st.st_mode&0o7022 or mode is not None and stat.S_IMODE(st.st_mode)!=mode:raise Refused('profile_export_directory')
    acl_absent(fd);return st

def open_parent(path):
    path=Path(path).absolute()
    if '..'in path.parts:raise Refused('profile_export_parent')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=new
        directory(fd)
        return fd
    except BaseException:os.close(fd);raise

def existing(fd,name):
    try:file=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
    except FileNotFoundError:return None
    try:
        before=os.fstat(file)
        if not stat.S_ISREG(before.st_mode)or before.st_uid!=os.getuid()or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or not 1<=before.st_size<=MAX_PROFILE:raise Refused('profile_export_existing_metadata')
        acl_absent(file);out=bytearray()
        while len(out)<=MAX_PROFILE:
            chunk=os.read(file,min(65536,MAX_PROFILE+1-len(out)))
            if not chunk:break
            out.extend(chunk)
        if len(out)!=before.st_size or stamp(os.fstat(file))!=stamp(before)or stamp(os.stat(name,dir_fd=fd,follow_symlinks=False))!=stamp(before):raise Refused('profile_export_existing_changed')
        return bytes(out)
    finally:os.close(file)

def save(content,ident,*,parent):
    # parent is injected only in ordinary tests; main always uses its own fixed
    # script directory, beside the launcher. No output path CLI exists.
    device(ident);profile(content,ident)
    if os.geteuid()==0 or os.geteuid()!=os.getuid():raise Refused('profile_export_requires_ordinary_user')
    parent=Path(parent).absolute();name=ident+'.mobileconfig';dirname='家人设备配置'
    base=open_parent(parent);base_identity=os.fstat(base);folder=None;tmp=None;file=None
    try:
        created=False
        try:os.mkdir(dirname,0o700,dir_fd=base);created=True
        except FileExistsError:pass
        folder=os.open(dirname,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=base)
        if created:os.fchmod(folder,0o700);os.fsync(folder);os.fsync(base)
        initial=directory(folder,0o700)
        def linked():
            fresh=open_parent(parent)
            try:
                observed=os.fstat(fresh)
                if (observed.st_dev,observed.st_ino)!=(base_identity.st_dev,base_identity.st_ino):raise Refused('profile_export_parent_replaced')
            finally:os.close(fresh)
            current=os.stat(dirname,dir_fd=base,follow_symlinks=False)
            if (current.st_dev,current.st_ino)!=(initial.st_dev,initial.st_ino):raise Refused('profile_export_directory_replaced')
            directory(folder,0o700);directory(base)
        linked();old=existing(folder,name)
        if old is not None:
            if old!=content:raise Refused('profile_export_existing_differs')
            linked();return dict(path=str(parent/dirname/name),sha256=digest(content),reused_existing=True)
        tmp='.profile-'+secrets.token_hex(16)
        file=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=folder)
        os.fchmod(file,0o600);acl_absent(file);offset=0
        while offset<len(content):
            written=os.write(file,content[offset:])
            if written<=0:raise Refused('profile_export_short_write')
            offset+=written
        os.fsync(file);os.close(file);file=None;linked()
        try:os.link(tmp,name,src_dir_fd=folder,dst_dir_fd=folder,follow_symlinks=False)
        except FileExistsError:
            if existing(folder,name)!=content:raise Refused('profile_export_raced_existing_differs')
        os.unlink(tmp,dir_fd=folder);tmp=None;os.fsync(folder);linked()
        if existing(folder,name)!=content:raise Refused('profile_export_final_readback')
        return dict(path=str(parent/dirname/name),sha256=digest(content),reused_existing=False)
    finally:
        try:
            if file is not None:os.close(file)
        finally:
            try:
                if tmp is not None:
                    try:os.unlink(tmp,dir_fd=folder)
                    except FileNotFoundError:pass
            finally:
                if folder is not None:os.close(folder)
                os.close(base)

def main():
    if len(sys.argv)!=2:raise Refused('profile_fixed_device_argument')
    ident=device(sys.argv[1]);raw=sys.stdin.buffer.read(MAX_JSON+1);content=transport(raw,ident)
    result=save(content,ident,parent=Path(__file__).absolute().parent)
    print(json.dumps(result,ensure_ascii=False,sort_keys=True))

if __name__=='__main__':
    try:main()
    except (OSError,ValueError,Refused):
        print('设备配置未导出：输入、文件或安全校验未通过；原文件已保留。',file=sys.stderr);raise SystemExit(2)
