"""Embedded after fixed installer I/O; immutable scoped runtime publication."""

def asset_name(name):
    if (type(name)is not str or not re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?',name)
            or any(x in ('.','..') for x in name.split('/'))
            or '/' in name and name.split('/')[0] not in ('crypto','vici')):
        raise Failure('fixed_asset_name')
    return name

def asset_mode(name):
    return 0o755 if name=='crypto/public-crl-verify' else 0o600

def asset_read(folder,name,installed=False):
    asset_name(name);path=folder/name
    info=trusted(path,mode=asset_mode(name)) if installed else path.lstat()
    raw=read(path,limit=16*1024*1024 if name=='crypto/public-crl-verify' else LIMIT)
    if stamp(path.lstat())!=stamp(info):raise Failure('asset_metadata_changed')
    return raw

def asset_inventory(folder,expected,*,installed=False,partial=False):
    expected=set(expected)
    for name in expected:asset_name(name)
    parents={name.split('/')[0] for name in expected if '/' in name}
    if installed:trusted(folder,directory=True,mode=0o700)
    elif folder.is_symlink() or not folder.is_dir():raise Failure('source_directory_type')
    actual=set()
    for path in folder.iterdir():
        if path.name in parents:
            if installed:trusted(path,directory=True,mode=0o700)
            elif path.is_symlink() or not path.is_dir():raise Failure('source_nested_directory')
            for child in path.iterdir():actual.add(path.name+'/'+child.name)
        else:actual.add(path.name)
    if not (actual<=expected if partial else actual==expected):raise Failure('asset_inventory_changed')
    for name in actual:asset_read(folder,name,installed)
    return actual

def asset_write_new(folder,name,raw):
    """Binary-specific create-only path retains mode at first publication."""
    asset_name(name)
    for part in Path(name).parts[:-1]:
        folder=folder/part;directory(folder)
    path=folder/Path(name).name
    if name!='crypto/public-crl-verify':return write_new(path,raw)
    if len(raw)>16*1024*1024:raise Failure('asset_limit')
    trusted(folder,directory=True,mode=0o700)
    def same():
        info=trusted(path,mode=0o755)
        if read(path,limit=16*1024*1024)!=raw or stamp(path.lstat())!=stamp(info):raise Failure('binary_asset_changed')
    if exists(path):same();return
    temporary=folder/('.asset-'+secrets.token_hex(12));fd=None
    try:
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        offset=0
        while offset<len(raw):
            count=os.write(fd,raw[offset:])
            if count<=0:raise Failure('asset_short_write')
            offset+=count
        os.fchmod(fd,0o755);os.fsync(fd);os.close(fd);fd=None
        try:os.link(temporary,path,follow_symlinks=False)
        except FileExistsError:same()
        temporary.unlink();sync_dir(folder);same()
    finally:
        if fd is not None:os.close(fd)
        if exists(temporary):temporary.unlink()

def asset_publish(folder,resources):
    expected={name:digest(raw) for name,raw in resources.items()}
    intent=MANAGER/('publish-'+folder.name+'.json')
    record=encode(dict(version=1,path=str(folder),inventory=expected))
    if exists(folder):
        trusted(folder,directory=True,mode=0o700)
        if not exists(intent) or read(intent,installed=True)!=record:
            actual=asset_inventory(folder,expected,installed=True)
        else:actual=asset_inventory(folder,expected,installed=True,partial=True)
        for name in actual:
            if digest(asset_read(folder,name,True))!=expected[name]:raise Failure('installed_asset_changed')
    else:
        write_new(intent,record);directory(folder)
    for name,raw in resources.items():asset_write_new(folder,name,raw)
    asset_inventory(folder,expected,installed=True)
    for name in expected:
        if digest(asset_read(folder,name,True))!=expected[name]:raise Failure('installed_asset_readback')

@contextlib.contextmanager
def install_native_locks():
    """Original exact lock inodes; no replacement of any historical lock."""
    with contextlib.ExitStack() as stack:
        checks=[stack.enter_context(lock(NATIVE/'lock'))];records=[]
        for root in LEGACY:
            path=root/'lock';record=root/'session.json'
            if not exists(path):
                if exists(record):raise Failure('legacy_record_without_lock')
                continue
            checks.append(stack.enter_context(lock(path)))
            if exists(record):
                raw=read(record,installed=True);value=decode(raw)
                if (type(value)is not dict or type(value.get('version'))is not int
                        or value['version']!=1 or value.get('active')is not False):
                    raise Failure('legacy_owner_active_or_unknown')
                records.append((record,raw))
        def held():
            for check in checks:
                if check() is not None:raise Failure('install_native_lease')
            for path,raw in records:
                if read(path,installed=True)!=raw:raise Failure('legacy_record_changed')
        held();yield held
