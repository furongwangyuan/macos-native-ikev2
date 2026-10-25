"""Synthetic address/identity fixtures. No endpoint is contacted by these tests.

The local IPv6 literals must pass the real global-address validator; they are
invented test values, not deployment addresses or a published VPN endpoint.
"""
import copy
import vici_fixture as vici
import test_native_fleet

LOCAL6 = '2001:4860:1234:5678::8'
PEER6 = '2001:4860:abcd::101'
OUTER = ('192.0.2.8', LOCAL6)
REG = vici.REG


def registry_many(count=2):
    result = copy.deepcopy(REG)
    result['devices'] = [dict(device_id=f'device{i+1:02}', display_name=f'Phone {i+1}',
        ike_identity=f'device{i+1:02}.family.home.arpa', state='enabled',
        vip4=f'10.77.26.{10+i}', vip6=f'fd6d:fe83:ab27:2600::{16+i:x}')
        for i in range(count)]
    return result


def event(device=None, ikeid=1, childid=1):
    index = 0 if device is None else next(i for i,d in enumerate(REG['devices'])
                                        if d['device_id']==device['device_id'])
    return vici.event(index, ikeid, childid)


inner = vici.inner
decoded = vici.decode


def child(value):
    return next(iter(inner(value)['child-sas'].values()))


def native_fixture():
    return test_native_fleet.fixture(OUTER, PEER6)
