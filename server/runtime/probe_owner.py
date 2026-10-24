"""Synthetic child adapter belonging to one actual native Owner.

No CLI, second writer, sockets, or independent authorization supplied here.
"""
import copy
import json
import native_support as s
import controller as ctl
import probe_policy as policy
import probe_contract as contract
import probe_process as process
import probe_paths

FIELDS=('probe_child','probe_generation','probe_result','probe_retired')
RESULT_LIMIT=24576
REQUEST_COLUMNS=('id','utc_ms','route','requested','body_in','body_out','elapsed_ms','status','result')


def history(session):
    mode=policy.mode(session.get('probe_mode'),session.get('allow_data'))
    if mode=='off':
        if any(k in session for k in FIELDS):raise s.Refused('off_session_has_probe_ownership')
        return
    row=session.get('probe_child')
    gen=session.get('probe_generation')
    if gen is not None:policy.generation(gen)
    if row is not None:
        contract.record(row)
        if gen is None or row['peer']!=gen['vip4'] or row['boot']!=session.get('boot'):
            raise s.Refused('probe_record_generation_or_boot_changed')
    if 'probe_retired' in session and type(session['probe_retired'])is not bool:raise s.Refused('probe_retirement_shape')
    if 'probe_result' in session:
        result=session['probe_result']
        if type(result)is not dict or len(json.dumps(result,allow_nan=False).encode())>RESULT_LIMIT:
            raise s.Refused('probe_result_shape')
    if session.get('phase')=='RESTORED' and row is not None and row['phase'] not in ('exited','retired-no-go'):
        raise s.Refused('restored_probe_not_retired')



def result_projection(value):
    """Losslessly compact known request rows; no summary manufactures throughput.

    Fixed columns avoid repeating keys up to128 times in the native journal.
    Reconstruct each row with event=request to verify records_sha256. Ready and
    stopped records stay verbatim; original order is ready, requests, stopped.
    """
    result=copy.deepcopy(value)
    if type(result)is not dict:raise s.Refused('probe_result_not_object')
    if 'protocol' in result:
        protocol=result['protocol']
        if type(protocol)is not dict or type(protocol.get('records'))is not list:
            raise s.Refused('probe_protocol_records_missing')
        records=protocol.pop('records')
        if len(records)>130:raise s.Refused('probe_protocol_record_count')
        ready=[];stopped=[];rows=[]
        for row in records:
            event=row.get('event') if type(row)is dict else None
            if event=='ready':ready.append(row)
            elif event=='stopped':stopped.append(row)
            elif event=='request' and set(row)==set(REQUEST_COLUMNS)|{'event'}:
                rows.append([row[k] for k in REQUEST_COLUMNS])
            else:raise s.Refused('probe_projection_unknown_record')
        rebuilt=ready+[dict(event='request',**dict(zip(REQUEST_COLUMNS,row))) for row in rows]+stopped
        if rebuilt!=records or len(ready)>1 or len(stopped)>1:
            raise s.Refused('probe_projection_order_changed')
        canonical=json.dumps(records,sort_keys=True,allow_nan=False,separators=(',',':')).encode()
        protocol.update(record_format='compact-v1',request_columns=list(REQUEST_COLUMNS),request_rows=rows,
                        ready=ready[0] if ready else None,stopped=stopped[0] if stopped else None,
                        records_sha256=s.digest(canonical))
    if len(json.dumps(result,allow_nan=False).encode())>RESULT_LIMIT:raise s.Refused('probe_result_limit')
    return result


def port_absent():
    result=s.run(['/usr/sbin/lsof','-nP','-iTCP:47729','-F','pftn'],check=False,timeout=5)
    if result.returncode!=1 or result.stdout.strip() or result.stderr.strip():raise s.Refused('probe_tcp_endpoint_not_absent')
    return True


class Journal:
    def __init__(self,owner):self.owner=owner
    def save(self,row):
        self.owner.session['probe_child']=copy.deepcopy(row);self.owner.save()
    def load(self):
        # Read the store's actual durable readback; the process component compares
        # its serialized row and cannot substitute a still-unsaved Python object.
        value=self.owner.store.load()
        if value is None:raise s.Refused('probe_parent_journal_missing')
        return copy.deepcopy(value.get('probe_child'))


class Adapter:
    def __init__(self,owner):self.owner=owner;self.child=None
    def enabled(self):return self.owner.session['probe_mode']==policy.MODE
    def want_start(self):
        return self.enabled() and self.owner.session.get('probe_child') is None and not self.owner.session.get('probe_retired',False)
    def start(self,current,proof):
        if not self.want_start():raise ctl.Fault('probe_single_attempt_required')
        policy.verified_reply_scope(current,proof)
        owner=self.owner
        seconds=policy.seconds(owner.session,owner.probe_clock())
        port_absent()
        owner.session['probe_generation']=current.info();owner.save()
        self.child=process.ProbeChild(Journal(owner))
        self.child.start(current.vip4,seconds)
    def check(self):
        if self.child is None or self.owner.session.get('probe_retired',False):return
        # This also performs bounded private pipe reads and exact child checks.
        result=self.child.poll()
        if result is not None:raise ctl.Fault('probe_ended_before_owner_window')
    def stop(self):
        owner=self.owner
        result=None
        if self.child is not None:
            # The actual unreaped child remains ours even if the session was
            # corrupted. stop_owned attempts termination despite save failure.
            result=self.child.stop_owned()
        else:
            if not self.enabled() or owner.session.get('probe_child') is None:return
            result=process.recover_exact(Journal(owner))
        # Forwarding=0 and a claimed exit receipt alone cannot close local TCP.
        port_absent()
        owner.session['probe_retired']=True
        if result is not None:owner.session['probe_result']=result_projection(result)
        owner.save()
