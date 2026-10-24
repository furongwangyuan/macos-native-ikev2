"""Exactly one durable bounded owner kind, never a caller-selected fallback."""
import native_support as s
import boot_finite_source as finite
import boot_server_source as server
import production_source as production

class Refused(RuntimeError):pass

def kind(native):
    if type(native)is not dict:raise Refused('bounded_native_source_type')
    found=[name for name in ('finite','server') if name+'_window' in native or name+'_ready' in native]
    if 'production_run' in native:found.append('production')
    if len(found)!=1:raise Refused('bounded_source_requires_exactly_one_kind')
    return found[0]

def module(native):return {'finite':finite,'server':server,'production':production}[kind(native)]

def snapshot(native):return production.snapshot(native) if kind(native)=='production' else module(native).snapshot()

def validate(native,raw,*,permission_closed=False):return module(native).validate(native,raw,permission_closed=permission_closed)

def unpack(raw):
    value=s.json_value(raw)
    if type(value)is not dict:raise Refused('bounded_context_type')
    if value.get('kind')==finite.KIND:return finite.unpack(raw)
    if value.get('kind')==server.KIND:return server.unpack(raw)
    if value.get('kind')==production.KIND:return production.unpack(raw)
    raise Refused('bounded_context_kind_unknown')

def verify_current_resources(native,raw):return module(native).verify_current_resources(raw)

def absent_service():return finite.absent_service()
