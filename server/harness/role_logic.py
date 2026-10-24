"""Shared fixed role state machines. No process creation, import-time native work,
CLI-selectable adapter, or child command supplied in the pipe protocol.
"""
import os
import select
import signal
import time
from fault_protocol import Refused, checkpoint, digest, exact, identity, observer_decision
from process_observe import observe


def read_line(fd,seconds,limit=16):
    data=b'';end=time.monotonic()+seconds
    while not data.endswith(b'\n'):
        left=end-time.monotonic()
        if left<=0 or not select.select([fd],[],[],left)[0]:raise Refused('role_control_timeout')
        more=os.read(fd,1)
        if not more:raise Refused('role_control_eof')
        data+=more
        if len(data)>limit:raise Refused('role_control_limit')
    return data


def bound_roles(receipts):
    intent=receipts.read('intent.json')
    run=intent.get('run')
    if type(run)is not str or len(run)!=32 or any(x not in '0123456789abcdef' for x in run):
        raise Refused('intent_run')
    roles={k:identity(receipts.read(k+'.json')) for k in ('owner','observer','coordinator')}
    if len({x['pid'] for x in roles.values()})!=3:raise Refused('role_identity_collision')
    return intent,roles


def watch_receipt(intent,roles):
    return dict(run=intent['run'],intent_sha256=digest(intent),owner=roles['owner'],
                observer=roles['observer'],coordinator=roles['coordinator'])


def checked_watch(receipts,intent,roles):
    value=receipts.read('watch.json');expected=watch_receipt(intent,roles)
    if type(value)is not dict or set(value)!=set(expected):raise Refused('watch_schema')
    for role in ('owner','observer','coordinator'):identity(value[role])
    if value!=expected:raise Refused('watch_not_bound')
    exact(observe(roles['observer']['pid']),roles['observer'],stopped=False)


def owner_role(receipts,native,control=0,output=1):
    os.write(output,b'READY\n') # Interpreter has initialized before birth receipt.
    if read_line(control,10)!=b'GO\n':raise Refused('owner_fixed_go')
    intent,roles=bound_roles(receipts)
    exact(observe(os.getpid()),roles['owner'],stopped=False)
    checked_watch(receipts,intent,roles)
    with native.locks():
        try:
            seal=checkpoint(native.prepare())
            if seal['run']!=intent['run'] or seal['boot']!=intent['boot']:raise Refused('owner_seal_binding')
            receipts.write('checkpoint.json',seal)
            os.write(output,b'PARKED\n')
            # STOP plus fresh native seal, rather than this earlier notice or a
            # deadline margin, is the only admission to injected SIGKILL.
            try:command=read_line(control,45)
            except Refused as error:
                if str(error) not in ('role_control_eof','role_control_timeout'):raise
            else:
                if command!=b'ABORT\n':raise Refused('owner_unknown_control')
        finally:native.cleanup_owner()
    return 0


def no_kill_receipt(receipts,seal,roles):
    if seal is None or not receipts.exists('abort.json'):return False
    value=receipts.read('abort.json')
    expected=dict(run=seal['run'],owner=roles['owner'],observer=roles['observer'],
                  seal_sha256=digest(seal),no_kill=True)
    if type(value)is not dict or set(value)!=set(expected) or value.get('no_kill')is not True:
        raise Refused('abort_receipt_schema')
    identity(value['owner']);identity(value['observer'])
    if value!=expected:raise Refused('abort_binding')
    return True


def observer_role(receipts,native,control=0,output=1,wait_seconds=120):
    os.write(output,b'READY\n')
    if read_line(control,10)!=b'WATCH\n':raise Refused('observer_fixed_watch')
    intent,roles=bound_roles(receipts)
    exact(observe(os.getpid()),roles['observer'],stopped=False)
    exact(observe(roles['owner']['pid']),roles['owner'],stopped=False)
    exact(observe(roles['coordinator']['pid']),roles['coordinator'],stopped=False)
    receipts.write('watch.json',watch_receipt(intent,roles));os.write(output,b'WATCHING\n')
    eof=False;seal=None;buffer=b'';end=time.monotonic()+wait_seconds
    while time.monotonic()<end:
        if not eof and select.select([control],[],[],.02)[0]:
            raw=os.read(control,1)
            if not raw:eof=True
            else:
                buffer+=raw
                if len(buffer)>4:raise Refused('observer_control_limit')
                if buffer.endswith(b'\n'):
                    if buffer!=b'ARM\n' or seal is not None:raise Refused('observer_fixed_arm')
                    seal=checkpoint(receipts.read('checkpoint.json'))
                    if seal['run']!=intent['run'] or seal['boot']!=intent['boot']:raise Refused('observer_seal_binding')
                    # This ARM is not native proof by itself. Coordinator will
                    # independently collect again only after owner SSTOP.
                    receipts.write('armed.json',dict(run=intent['run'],observer=roles['observer'],seal_sha256=digest(seal)))
                    os.write(output,b'ARMED\n');buffer=b''
        own=observe(roles['owner']['pid']);coord=observe(roles['coordinator']['pid'])
        action=observer_decision(own,coord,owner_expected=roles['owner'],coordinator_expected=roles['coordinator'],
            coordinator_eof=eof,explicit_no_kill=no_kill_receipt(receipts,seal,roles))
        if action=='CONTINUE_EXACT_OWNER':
            exact(observe(roles['owner']['pid']),roles['owner'],stopped=True)
            os.kill(roles['owner']['pid'],signal.SIGCONT)
        elif action=='RECOVER':
            with native.locks():
                # Another task must not replace this run between absence and
                # lock acquisition. Native.recover re-reads exact run/boot/v4.
                if observe(roles['owner']['pid']) is not None:raise Refused('owner_reappeared')
                restored=native.recover()
                if restored is True and seal is not None:restored=native.restored_readback()
                receipts.write('recovery.json',dict(run=intent['run'],observer=roles['observer'],
                    seal_sha256=digest(seal) if seal is not None else None,restored=restored is True))
            return 0 if restored is True else 2
        time.sleep(.01)
    # This only bounds observation before recovery starts. Cleanup deliberately
    # has no hard timeout; coordinator may report incomplete, never kill writer.
    receipts.write('observer-attention.json',dict(run=intent['run'],event='observer_wait_incomplete'))
    return 2
