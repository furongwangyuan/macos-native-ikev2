"""Bounded evidence parser for the frozen C probe's private stdout pipe.

No listener, executable selection, privilege, process signalling or network
authorization. Complete records are not proof of VPN authentication or egress.
"""
import json
import math

LINE_LIMIT=768
RECORD_LIMIT=130
STREAM_LIMIT=LINE_LIMIT*RECORD_LIMIT
BYTE_BUDGET=80000000
U64=(1<<64)-1

class InvalidRecords(ValueError):pass

def integer(value,lower,upper):
    if type(value)is not int or not lower<=value<=upper:raise InvalidRecords('integer')
    return value

def number(value):
    if type(value)not in (int,float) or not 0<=value<=(1<<53)-1 or not math.isfinite(value):raise InvalidRecords('number')
    return value

def exact(value,keys):
    if type(value)is not dict or set(value)!=set(keys.split()):raise InvalidRecords('schema')

def decode(raw):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise InvalidRecords('duplicate_key')
            result[key]=value
        return result
    def bad(_):raise InvalidRecords('nonfinite')
    try:return json.loads(raw.decode('ascii'),object_pairs_hook=pairs,parse_constant=bad)
    except (UnicodeError,json.JSONDecodeError):raise InvalidRecords('json') from None

class Records:
    def __init__(self,expected_ready,page_length):
        exact(expected_ready,'event bind port peer seconds budget page_sha256')
        if expected_ready['event']!='ready' or expected_ready['port']!=47729 or type(expected_ready['port'])is not int:raise InvalidRecords('expected_ready')
        if expected_ready['budget']!=BYTE_BUDGET or type(expected_ready['budget'])is not int:raise InvalidRecords('expected_budget')
        integer(expected_ready['seconds'],1,900)
        if type(expected_ready['bind'])is not str or type(expected_ready['peer'])is not str:raise InvalidRecords('expected_address')
        if expected_ready['bind']=='127.0.0.1':
            if expected_ready['peer']!='127.0.0.1':raise InvalidRecords('expected_address')
        elif expected_ready['bind']=='192.0.2.8':
            if expected_ready['peer'] not in {'10.77.26.'+str(i) for i in range(10,101)}:raise InvalidRecords('expected_address')
        else:raise InvalidRecords('expected_address')
        pin=expected_ready['page_sha256']
        if type(pin)is not str or len(pin)!=64 or any(c not in '0123456789abcdef' for c in pin):raise InvalidRecords('expected_page')
        self.expected=dict(expected_ready);self.page_length=integer(page_length,1,65535)
        self.buffer=bytearray();self.bytes_read=0;self.ready=None;self.requests=[];self.stopped=None;self.eof=False;self.failed=False

    def feed(self,chunk):
        if self.failed or self.eof:raise InvalidRecords('stream_already_closed')
        try:
            if type(chunk)is not bytes or not chunk:raise InvalidRecords('chunk')
            self.bytes_read+=len(chunk)
            if self.bytes_read>STREAM_LIMIT:raise InvalidRecords('stream_limit')
            self.buffer.extend(chunk)
            while b'\n' in self.buffer:
                end=self.buffer.index(10)
                if end+1>=LINE_LIMIT:raise InvalidRecords('line_limit')
                raw=bytes(self.buffer[:end]);del self.buffer[:end+1]
                self._record(decode(raw))
            if len(self.buffer)>=LINE_LIMIT:raise InvalidRecords('line_limit')
        except Exception:
            self.failed=True;raise

    def _record(self,value):
        if self.stopped is not None:raise InvalidRecords('after_stopped')
        if self.ready is None:
            # Typed numeric fields are checked separately: bool must not alias 1.
            exact(value,'event bind port peer seconds budget page_sha256')
            for key in ('port','seconds','budget'):integer(value[key],0,BYTE_BUDGET)
            if value!=self.expected:raise InvalidRecords('ready_mismatch')
            self.ready=value;return
        if type(value)is not dict:raise InvalidRecords('record_type')
        if value.get('event')=='stopped':
            exact(value,'event connections reserved_budget body_in body_out dropped_logs')
            integer(value['connections'],0,128);integer(value['reserved_budget'],0,BYTE_BUDGET)
            for name in ('body_in','body_out'):integer(value[name],0,BYTE_BUDGET)
            integer(value['dropped_logs'],0,RECORD_LIMIT)
            if value['body_in']+value['body_out']>value['reserved_budget']:raise InvalidRecords('body_exceeds_reservation')
            if self.requests and value['connections']<self.requests[-1]['id']:raise InvalidRecords('connection_count')
            self.stopped=value;return
        exact(value,'event id utc_ms route requested body_in body_out elapsed_ms status result')
        if value['event']!='request' or len(self.requests)>=128:raise InvalidRecords('request_count')
        integer(value['id'],1,128)
        if self.requests and value['id']<=self.requests[-1]['id']:raise InvalidRecords('request_order')
        integer(value['utc_ms'],1,(1<<53)-1);integer(value['requested'],0,U64)
        for name in ('body_in','body_out'):integer(value[name],0,BYTE_BUDGET)
        number(value['elapsed_ms'])
        if type(value['status'])is not int or value['status'] not in (200,400,413):raise InvalidRecords('status')
        if value['result'] not in ('rejected','incomplete_header','incomplete_body','aborted','complete'):raise InvalidRecords('result')
        route=value['route'];size=value['requested']
        if route not in ('invalid','page','download','upload'):raise InvalidRecords('route')
        if route=='page' and size!=self.page_length:raise InvalidRecords('page_length')
        if route=='download' and size not in (0,1024,1000000,8000000,25000000):raise InvalidRecords('download_size')
        if route=='upload' and size not in (1024,125000,500000,5000000):raise InvalidRecords('upload_size')
        if value['result']=='complete':
            if value['status']!=200 or route=='invalid':raise InvalidRecords('complete_status')
            if route in ('page','download') and (value['body_in']!=0 or value['body_out']!=size):raise InvalidRecords('complete_download_count')
            if route=='upload' and (value['body_in']!=size or not 1<=value['body_out']<256):raise InvalidRecords('complete_upload_count')
        self.requests.append(value)

    def finish(self,*,exit_code,stderr_empty):
        """Call only after this private pipe reached EOF and exact child was reaped.

        The caller owns those observations. This parser cannot prove process
        identity, closure of another pipe or current native policy by itself.
        """
        if self.eof:raise InvalidRecords('duplicate_eof')
        self.eof=True
        reasons=[]
        if self.failed:reasons.append('invalid_stream')
        if self.buffer:reasons.append('partial_line')
        if self.ready is None:reasons.append('missing_ready')
        if self.stopped is None:reasons.append('missing_stopped')
        if type(exit_code)is not int or exit_code!=0:reasons.append('child_exit_not_zero')
        if stderr_empty is not True:reasons.append('stderr_not_empty')
        if self.stopped is not None:
            final=self.stopped
            if final['dropped_logs']!=0:reasons.append('dropped_records')
            contiguous=[r['id'] for r in self.requests]==list(range(1,final['connections']+1))
            if not contiguous:reasons.append('unobserved_connection')
            for name in ('body_in','body_out'):
                if sum(r[name] for r in self.requests)!=final[name]:reasons.append('total_'+name+'_mismatch')
            # Failed/rejected requests can reserve differently, so this exact
            # frozen-C equation applies only to fully observed complete ones.
            if contiguous and all(r['result']=='complete' for r in self.requests):
                expected=16384*final['connections']+sum(r['requested'] for r in self.requests)
                if final['reserved_budget']!=expected:reasons.append('reserved_budget_mismatch')
        if any(r['result']!='complete' for r in self.requests):reasons.append('incomplete_request')
        if any(r['elapsed_ms']>=15000 for r in self.requests):reasons.append('request_time_limit')
        return dict(version=1,scope='private_probe_stdout_records_only',complete=not reasons,
                    reasons=reasons,records=([self.ready] if self.ready is not None else [])+self.requests+([self.stopped] if self.stopped is not None else []),
                    bytes_read=self.bytes_read,record_count=len(self.requests)+(self.ready is not None)+(self.stopped is not None),
                    authenticated_vpn_verified=False,throughput_computed=False)
