"""Explicit operator enablement bound to installed source and OS.

This is configuration authority, never a test PASS. The installer records a
real closed observation before enabling; every Owner still runs real preflight.
"""
import json
import re
import native_support as s

class Refused(RuntimeError):pass

def encode(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def exact_hash(value):return type(value)is str and re.fullmatch('[0-9a-f]{64}',value)is not None

def validate(record,code,kernel,machine):
    keys={'version','stage','explicit_enable','code_sha256','kernel_release','machine',
          'common_sha256','enabled_boot','closed_observation','fault_tests_performed','phone_test_performed'}
    if (type(record)is not dict or set(record)!=keys or type(record['version'])is not int
            or record['version']!=2 or record['stage']!='explicit-enable' or record['explicit_enable']is not True
            or record['code_sha256']!=code or record['kernel_release']!=kernel or record['machine']!=machine
            or not exact_hash(code) or not exact_hash(record['common_sha256'])
            or type(record['enabled_boot'])is not str or not record['enabled_boot']
            or record['fault_tests_performed']is not False or record['phone_test_performed']is not False):
        raise Refused('explicit_enable_record_unknown_or_stale')
    closed=record['closed_observation']
    if (type(closed)is not dict or set(closed)!={'kind','sha256'} or
            closed['kind'] not in ('fresh-no-owner','same-boot-native','retired-production-boot')
            or not exact_hash(closed['sha256'])):
        raise Refused('explicit_enable_closed_observation_unknown')
    return dict(stage='explicit-enable',explicit_enable=True,tests_claimed=False,
                all_project_requirements_verified=False)

def authorize(code,kernel,machine):
    path=s.CONF/'service-activation.json'
    raw=s.read(path,limit=16384);record=s.json_value(raw)
    result=validate(record,code,kernel,machine)
    if s.digest(s.read(s.BASE/'candidate-pins.json'))!=record['common_sha256']:
        raise Refused('explicit_enable_implementation_changed')
    if s.read(path,limit=16384)!=raw:raise Refused('explicit_enable_record_changed')
    return result
