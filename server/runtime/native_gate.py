"""Sole-writer, write-ahead PF/sysctl gate; no actions on import."""
import base64
import re
import stat
import native_support as s
import alf_readonly as alf

ANCHOR='org.familyvpn.production-guardian'
PF='/sbin/pfctl'
APPLE_SOURCE='/private/etc/pf.anchors/com.apple'
GUARD='''block drop quick inet from 10.77.26.0/24 to any
block drop quick inet to 10.77.26.0/24
block drop quick inet6 from fd6d:fe83:ab27:2600::/64 to any
block drop quick inet6 to fd6d:fe83:ab27:2600::/64
block drop quick tagged FAMILYVPN_EGRESS4
block drop quick tagged FAMILYVPN_EGRESS6
'''


def rule_lines(text):return [x.strip() for x in text.splitlines() if x.strip()]


def stable_rules_source(text):
    # Syntax-only and actual PF loads may assign different anonymous table
    # names. Keep this anchor's generated rules explicit so exact comparison
    # stays reliable; preserve the persisted guard bytes for old-owner cleanup.
    directive='set ruleset-optimization none\n'
    if text.startswith(directive):return text
    return directive+text


def reference_tokens(text):
    """Actual pfctl -s References table; elapsed TIMESTAMP is not ownership."""
    if type(text)is not str or len(text)>65536 or '\0' in text:
        raise s.Refused('pf_reference_table_unknown')
    lines=rule_lines(text)
    if (len(lines)<2 or lines[0]!='TOKENS:' or
            lines[1].split()!=['PID','Process','Name','TOKEN','TIMESTAMP']):
        raise s.Refused('pf_reference_table_unknown')
    tokens=set()
    for line in lines[2:]:
        row=re.fullmatch(r'([0-9]{1,10})[ \t]+([!-~](?:[ -~]{0,62}[!-~])?)[ \t]+([1-9][0-9]{0,19})[ \t]+([0-9]{1,10}) days? ([0-9]{2}):([0-9]{2}):([0-9]{2})',line)
        if (row is None or int(row[1])>2147483647 or int(row[3])>18446744073709551615
                or int(row[5])>23 or int(row[6])>59 or int(row[7])>59 or row[3] in tokens):
            raise s.Refused('pf_reference_table_unknown')
        tokens.add(row[3])
    return frozenset(tokens)


def classify(text):
    filters=[];nat=[]
    for x in rule_lines(text):
        if x.startswith(('pass ','block ')):filters.append(x)
        elif x.startswith(('nat ','no nat ')):nat.append(x)
        elif x == 'wan = "en0"':continue
        elif x.startswith(('table ','set ','#')):continue
        else:raise s.Refused('compiled_rule_layout_unknown')
    return dict(filters=filters,nat=nat)


def default_root(filters,nat):
    # This is an explicit candidate grammar, not a claim that its spellings
    # have been observed on this host. First native check must read the live
    # root. Unknown, reordered, duplicated or cross-category items refuse
    # BEFORE changing the main file. The original exact lines remain journaled.
    forms=[(rule_lines(filters),[r'scrub-anchor "com\.apple/\*"(?: all)? fragment reassemble',
                                r'anchor "com\.apple/\*"(?: all)?']),
           (rule_lines(nat),[r'nat-anchor "com\.apple/\*"(?: all)?',
                            r'rdr-anchor "com\.apple/\*"(?: all)?'])]
    for lines,patterns in forms:
        if len(lines)!=len(patterns) or not all(re.fullmatch(p,x) for x,p in zip(lines,patterns)):
            raise s.Refused('unreviewed_runtime_root_layout')


def default_auxiliary(value):
    forms=[(value['dummynet'],[r'dummynet-anchor "com\.apple/\*"(?: all)?']),
           (value['apple_filters'],[r'anchor "200\.AirDrop/\*"(?: all)?',
                                    r'anchor "250\.ApplicationFirewall/\*"(?: all)?']),
           (value['apple_nat'],[])]
    for lines,patterns in forms:
        if len(lines)!=len(patterns) or not all(re.fullmatch(p,x) for x,p in zip(lines,patterns)):
            raise s.Refused('unreviewed_auxiliary_root_layout')


def apple_source():
    raw=s.read(APPLE_SOURCE,mode=None,limit=20000)
    if [x for x in rule_lines(raw.decode('utf-8')) if not x.startswith('#')]!=[
            'anchor "200.AirDrop/*"','anchor "250.ApplicationFirewall/*"']:
        raise s.Refused('apple_anchor_source_requires_review')
    return s.digest(raw)


def prepared_main(raw):
    text=raw.decode('utf-8')
    if ANCHOR in text:raise s.Refused('unowned_guardian_reference')
    # Same preserved Apple baseline as previous tests; custom main rules need
    # separate reconciliation, never a dump-to-file reconstruction.
    expected=['scrub-anchor "com.apple/*"','nat-anchor "com.apple/*"',
              'rdr-anchor "com.apple/*"','dummynet-anchor "com.apple/*"',
              'anchor "com.apple/*"','load anchor "com.apple" from "/etc/pf.anchors/com.apple"']
    if [x for x in rule_lines(text) if not x.startswith('#')]!=expected:
        raise s.Refused('pf_main_layout_requires_review')
    # Replacements below require the exact original lines too; whitespace
    # variants cannot silently omit the new reference.
    if any(text.splitlines().count(line)!=1 for line in expected):raise s.Refused('pf_main_anchor_count')
    text=text.replace('nat-anchor "com.apple/*"','nat-anchor "'+ANCHOR+'"\nnat-anchor "com.apple/*"')
    text=text.replace('\nanchor "com.apple/*"','\nanchor "'+ANCHOR+'" quick\nanchor "com.apple/*"')
    return (text+'\nload anchor "'+ANCHOR+'" from "'+str(s.CONF/'guard.pf')+'"\n').encode()


class Gate:
    MANAGED=s.SYS
    def __init__(self,session,store):
        s.require_local_modules(('native_gate','native_support','alf_readonly'))
        self.session,self.store=session,store
        self.data_mode=session.get('allow_data')
        self.state=session.setdefault('network',{'installed':False,'mode':'new'})
    def save(self):self.store.save(self.session)
    def sys_values(self):return s.values()
    def mode(self):
        s.session_history(self.session)
        if type(self.data_mode)is not bool or self.session['allow_data'] is not self.data_mode:
            raise s.Refused('gate_session_mode_changed')
        return self.data_mode
    def set_knob(self,key,value):
        data=self.mode()
        if not data:
            if key in ('net.inet.ip.redirect','net.inet6.ip6.redirect'):
                raise s.Refused('closed_mode_redirect_write_unavailable')
            if key in ('net.inet.ip.forwarding','net.inet6.ip6.forwarding') and (type(value)is not int or value!=0):
                raise s.Refused('closed_mode_cannot_open_forwarding')
        if key not in [*s.SYS,s.ESP]:raise s.Refused('unknown_sysctl')
        baseline=self.session['baseline'][key]
        own=4500 if key==s.ESP else (0 if not data and key in ('net.inet.ip.forwarding','net.inet6.ip6.forwarding') else s.SYS[key])
        current=int(s.run(['/usr/sbin/sysctl','-n',key]).stdout)
        if current not in (baseline,own):raise s.Refused('sysctl_external_change')
        rec=self.session.setdefault('knobs',{}).setdefault(key,dict(before=baseline,after=own,phase='untouched'))
        if (rec['before'],rec['after'])!=(baseline,own):raise s.Refused('sysctl_journal_changed')
        rec['phase']='restore-intent' if value==baseline else 'apply-intent';self.save()
        s.run(['/usr/sbin/sysctl','-w',key+'='+str(value)])
        if int(s.run(['/usr/sbin/sysctl','-n',key]).stdout)!=value:raise s.Refused('sysctl_readback')
        rec['phase']='restored' if value==baseline else 'applied';self.save()
    def restore_sysctls(self):
        self.mode()
        errors=[]
        for key in s.SYS:
            try:
                if key in self.session.get('knobs',{}):self.set_knob(key,self.session['baseline'][key])
                elif int(s.run(['/usr/sbin/sysctl','-n',key]).stdout)!=self.session['baseline'][key]:
                    raise s.Refused('unowned_sysctl_change')
            except Exception:errors.append(key)
        if errors:raise s.Refused('forwarding_restore_incomplete')
    def roots(self):return s.run([PF,'-sr']).stdout,s.run([PF,'-sn']).stdout
    def auxiliary_roots(self):
        return dict(dummynet=rule_lines(s.run([PF,'-s','dummynet']).stdout),
            apple_filters=rule_lines(s.run([PF,'-a','com.apple','-sr']).stdout),
            apple_nat=rule_lines(s.run([PF,'-a','com.apple','-sn']).stdout))
    def auxiliary_intact(self):
        pf=self.session['pf']
        if apple_source()!=pf.get('apple_source_sha') or self.auxiliary_roots()!=pf.get('auxiliary_before'):
            raise s.Refused('auxiliary_root_changed_preserve_external')
    def root_intact(self):
        pf=self.session.get('pf',{})
        if not pf or s.digest(s.read(s.PFC,mode=pf['mode']))!=pf['after_sha']:raise s.Refused('main_pf_changed')
        self.own_root(*self.roots())
        self.auxiliary_intact()
    def own_root(self,filters,nat):
        baseline=self.session.get('pf',{}).get('root_before')
        if not baseline:raise s.Refused('root_baseline_missing')
        default_root('\n'.join(baseline['filters']),'\n'.join(baseline['nat']))
        lines=rule_lines(filters);nats=rule_lines(nat)
        # The sole preceding scrub anchor is normalization, not a pass/filter.
        # Our quick anchor must precede the original Apple FILTER anchor.
        if (len(lines)!=3 or lines[0]!=baseline['filters'][0] or
                not re.fullmatch(r'anchor "'+re.escape(ANCHOR)+r'" (?:quick(?: all)?|all quick)',lines[1])):
            raise s.Refused('guard_anchor_not_first_quick')
        if [lines[0],*lines[2:]]!=baseline['filters'] or len(nats)!=3 or nats[1:]!=baseline['nat']:
            raise s.Refused('root_baseline_changed')
        if not re.fullmatch(r'nat-anchor "'+re.escape(ANCHOR)+r'"(?: all)?',nats[0]):
            raise s.Refused('nat_anchor_not_first')
    def compile_rules(self,text,name):
        path=s.RUN/name;s.atomic(path,stable_rules_source(text))
        result=s.run([PF,'-n','-v','-a',ANCHOR,'-f',path])
        expected=classify(result.stdout)
        if not expected['filters']:raise s.Refused('empty_compiled_filter')
        return path,expected
    def rules_equal(self,expected):
        actual=dict(filters=rule_lines(s.run([PF,'-a',ANCHOR,'-sr']).stdout),
                    nat=rule_lines(s.run([PF,'-a',ANCHOR,'-sn']).stdout))
        return actual==expected
    def refs(self):return s.run([PF,'-s','References']).stdout
    def token_present(self):
        token=self.session.get('pf_reference',{}).get('token')
        return token in reference_tokens(self.refs())
    def enabled(self):
        lines=[line.strip() for line in s.run([PF,'-s','info']).stdout.splitlines()
               if line.strip().startswith('Status:')]
        if len(lines)!=1:raise s.Refused('pf_enabled_state_unknown')
        match=re.fullmatch(r'Status:\s+(Enabled|Disabled)(?:\s+for\s+[0-9]+\s+days?\s+[0-9]{2}:[0-9]{2}:[0-9]{2})?(?:\s+Debug:\s+[A-Za-z]+)?',lines[0])
        if not match:raise s.Refused('pf_enabled_state_unknown')
        return match[1]=='Enabled'
    def closed_scope(self):
        if self.mode():raise s.Refused('closed_scope_requires_closed_mode')
        s.closed_history(self.session)
        # Unified profile v7 is refused by every older recovery loader.
        # Closed sessions never acquire data or pool-state deletion ownership.
        if (type(self.session.get('version'))is not int or self.session['version']!=7
                or self.session.get('profile')!='unified-native-service-v1'
                or self.session.get('allow_data')is not False):
            raise s.Refused('closed_no_state_delete_profile_required')
        before=self.session.get('alf_before')
        if (type(before)is not dict or type(before.get('global_state'))is not int or before['global_state']!=2
                or before.get('blockall')is not True or before.get('apps',{}).get(str(s.CHARON))is not False
                or alf.snapshot()!=before):raise s.Refused('closed_alf_baseline_changed')
        if not s.sad_empty():raise s.Refused('closed_mode_sad_not_empty')
        current=s.values()
        for key in ['net.inet.ip.forwarding','net.inet6.ip6.forwarding']:
            if type(self.session.get('baseline',{}).get(key))is not int or self.session['baseline'][key]!=0:
                raise s.Refused('closed_baseline_must_be_zero')
            if type(current.get(key))is not int or current[key]!=0:
                raise s.Refused('closed_forwarding_changed')
            rec=self.session.get('knobs',{}).get(key)
            if rec is not None and (type(rec)is not dict or rec.get('before')!=0 or rec.get('after')!=0
                    or type(rec.get('before'))is not int or type(rec.get('after'))is not int):
                raise s.Refused('closed_forwarding_history_changed')
    def kill_states(self):
        if not self.mode():raise s.Refused('closed_mode_state_deletion_unavailable')
        for pool,anynet in [('10.77.26.0/24','0.0.0.0/0'),('fd6d:fe83:ab27:2600::/64','::/0')]:
            s.run([PF,'-k',pool]);s.run([PF,'-k',anynet,'-k',pool])
        raw=s.run([PF,'-ss']).stdout
        if '10.77.26.' in raw or 'fd6d:fe83:ab27:2600:' in raw:raise s.Refused('pool_states_remain')
    def prepare(self):
        if not self.mode():self.closed_scope()
        raw=s.read(s.PFC,mode=None,limit=20000);mode=stat.S_IMODE(s.PFC.lstat().st_mode)
        filters,nat=self.roots();default_root(filters,nat)
        auxiliary=self.auxiliary_roots();default_auxiliary(auxiliary);apple_sha=apple_source()
        if not rule_lines(filters) or not rule_lines(nat):raise s.Refused('empty_root_baseline_requires_review')
        pf_enabled=self.enabled();refs_before=self.refs()
        # Apple's -e holds an implicit reference that is not listed as a Token.
        # Keep the same owned -E/-X lifecycle; releasing our token preserves
        # that reference. Exact baseline enabled/refs readback remains below.
        if s.run([PF,'-a',ANCHOR,'-sr']).stdout.strip() or s.run([PF,'-a',ANCHOR,'-sn']).stdout.strip():
            raise s.Refused('unowned_anchor_rules')
        candidate=prepared_main(raw)
        s.atomic(s.CONF/'guard.pf',GUARD)
        guard_path,guard_expected=self.compile_rules(GUARD,'guard.pf')
        s.atomic(s.RUN/'pf-main.conf',candidate);s.run([PF,'-nf',s.RUN/'pf-main.conf'])
        self.session['pf']=dict(before=base64.b64encode(raw).decode(),before_sha=s.digest(raw),
            after_sha=s.digest(candidate),mode=mode,phase='apply-intent',guard=guard_expected,
            root_before=dict(filters=rule_lines(filters),nat=rule_lines(nat)),
            auxiliary_before=auxiliary,apple_source_sha=apple_sha,
            enabled_before=pf_enabled,references_before=refs_before)
        self.save() # includes original bytes/hash and intended target BEFORE replace/reload
        s.atomic(s.PFC,candidate,mode);s.run([PF,'-f',s.PFC])
        self.state.update(installed=True,mode='guarded');self.session['pf']['phase']='applied';self.save()
        self.root_intact()
        rec=dict(phase='enable-intent',before_references_sha=s.digest(self.refs().encode()),token=None)
        self.session['pf_reference']=rec;self.save()
        result=s.run([PF,'-E']);tokens=re.findall(r'\bToken\s*:\s*([0-9]+)\b',result.stdout+result.stderr,re.I)
        if len(tokens)!=1:raise s.Refused('enable_token_unknown_preserve_guard')
        rec.update(token=tokens[0],phase='owned');self.save()
        if not self.enabled() or not self.token_present():raise s.Refused('enable_reference_readback')
        self.guard('prepared')
    def guard(self,_reason):
        data=self.mode()
        if not data:self.closed_scope()
        self.root_intact()
        known=[self.session['pf']['guard']]
        if self.session.get('gate_intent',{}).get('expected'):
            known.append(self.session['gate_intent']['expected'])
        if self.session.get('gate_intent',{}).get('previous'):
            known.append(self.session['gate_intent']['previous'])
        # A changed owned anchor is no longer safely ours to overwrite. The
        # outer protect() still closes recorded forwarding and retains all
        # resources for review; it never erases an external rule change.
        if not any(self.rules_equal(rules) for rules in known):raise s.Refused('anchor_changed_preserve_external')
        if data and not self.rules_equal(self.session['pf']['guard']):
            import fleet_tables
            intent=self.session.get('gate_intent',{})
            if fleet_tables.read() not in [intent.get('fleet_tables_before'),intent.get('fleet_tables_after')]:
                raise s.Refused('fleet_active_tables_external_change')
        path,expected=self.compile_rules(GUARD,'guard.pf')
        # Re-closing is allowed without a new durable record: it cannot open.
        s.run([PF,'-a',ANCHOR,'-f',path])
        if data:self.kill_states()
        else:self.closed_scope() # Retain all existing PF states in closed mode.
        self.state['mode']='guarded'
        if not self.enabled() or not self.rules_equal(expected):raise s.Refused('guard_readback_failed')
        self.session['fleet_active']=[]
        self.save()
    def closed(self):
        if not self.mode():self.closed_scope()
        self.root_intact()
        if not (self.enabled() and self.token_present() and self.rules_equal(self.session['pf']['guard'])):
            return False
        current=s.values()
        return all(current[k]==0 for k in ['net.inet.ip.forwarding','net.inet6.ip6.forwarding'])
    def protect(self):
        failures=[]
        try:self.guard('protect')
        except Exception:failures.append('guard')
        # Always attempt both families, even if PF/journal storage is broken.
        # Direct closure uses only pre-recorded baseline0 and owned apply intent.
        for key in ['net.inet.ip.forwarding','net.inet6.ip6.forwarding']:
            try:
                s.close_owned_forwarding(key,self.store.durable)
            except Exception:failures.append('forwarding')
        try:
            if not self.closed():failures.append('readback')
        except Exception:failures.append('readback')
        return not failures
    def activate(self,text):
        if not self.mode():raise s.Refused('closed_mode_activation_unavailable')
        self.guard('activate-validation');self.restore_sysctls()
        path,expected=self.compile_rules(text,'active.pf')
        self.session['gate_intent']=dict(phase='apply-intent',sha256=s.digest(s.read(path)),expected=expected)
        self.save()
        for key,value in s.SYS.items():self.set_knob(key,value)
        if s.values()!=s.SYS:raise s.Refused('forwarding_readback')
        s.run([PF,'-a',ANCHOR,'-f',path])
        if not self.rules_equal(expected):raise s.Refused('active_rules_readback')
        self.state['mode']='active';self.session['gate_intent']['phase']='applied';self.save()
    def verify_active(self):
        if not self.mode():raise s.Refused('closed_mode_has_no_active_data_path')
        self.root_intact()
        expected=self.session.get('gate_intent',{}).get('expected')
        import fleet_tables,fleet_session
        active=fleet_session.decode_active(self.session['fleet_active'],self.session['fleet']['registry'],fleet_session.endpoints(self.session['fleet']))
        return (self.enabled() and self.token_present() and s.values()==s.SYS and expected and self.rules_equal(expected)
                and fleet_tables.read()==fleet_tables.expected(active))
    def restore_pf(self):
        self.mode() # Validates closed history before any restore write.
        pf=self.session.get('pf')
        if pf is None:return
        ref=self.session.get('pf_reference')
        # A crash between -E and recording its token is deliberately not
        # guessed from a numeric difference. Preserve the installed closed
        # anchor until the ambiguous ownership has been reviewed.
        if ref and ref.get('token') is None:raise s.Refused('ambiguous_pf_reference_requires_review')
        if not s.sad_empty():
            raise s.Refused('pf_release_without_closed_empty_baseline')
        current_knobs=s.values()
        if any(current_knobs[k] for k in ['net.inet.ip.forwarding','net.inet6.ip6.forwarding']):
            raise s.Refused('pf_release_without_closed_empty_baseline')
        raw=s.read(s.PFC,mode=pf['mode']);current=s.digest(raw)
        original=base64.b64decode(pf['before'],validate=True)
        if s.digest(original)!=pf['before_sha'] or current not in [pf['before_sha'],pf['after_sha']]:
            raise s.Refused('pf_changed_preserve_external')
        roots=self.roots()
        self.auxiliary_intact()
        try:
            self.own_root(*roots);live_owned=True
        except s.Refused:
            # A previous restore can replace the file before its reload. Only
            # exact original root shape is an alternative, never arbitrary rules.
            expected=pf.get('root_before')
            if dict(filters=rule_lines(roots[0]),nat=rule_lines(roots[1]))!=expected:
                raise s.Refused('live_root_changed_preserve_external')
            live_owned=False
        actual=dict(filters=rule_lines(s.run([PF,'-a',ANCHOR,'-sr']).stdout),
                    nat=rule_lines(s.run([PF,'-a',ANCHOR,'-sn']).stdout))
        permitted=[pf['guard'],dict(filters=[],nat=[])]
        if self.session.get('gate_intent',{}).get('expected'):permitted.append(self.session['gate_intent']['expected'])
        if self.session.get('gate_intent',{}).get('previous'):permitted.append(self.session['gate_intent']['previous'])
        if actual not in permitted:raise s.Refused('owned_anchor_changed_preserve_external')
        pf['phase']='restore-intent';self.save()
        if current==pf['after_sha']:
            s.atomic(s.RUN/'pf-restore.conf',original);s.run([PF,'-nf',s.RUN/'pf-restore.conf'])
            s.atomic(s.PFC,original,pf['mode'])
        if live_owned:s.run([PF,'-f',s.PFC])
        roots=self.roots()
        if dict(filters=rule_lines(roots[0]),nat=rule_lines(roots[1]))!=pf['root_before']:
            raise s.Refused('root_baseline_restore_unverified')
        self.auxiliary_intact()
        s.atomic(s.RUN/'empty.pf','# Empty owned guardian anchor\n')
        s.run([PF,'-a',ANCHOR,'-f',s.RUN/'empty.pf'])
        if s.run([PF,'-a',ANCHOR,'-sr']).stdout.strip() or s.run([PF,'-a',ANCHOR,'-sn']).stdout.strip():
            raise s.Refused('anchor_not_empty')
        pf['phase']='restored';self.state.update(installed=False,mode='restored');self.save()
        if ref:
            present=self.token_present()
            if not present and ref['phase'] not in ['release-intent','released']:raise s.Refused('own_pf_reference_disappeared')
            ref['phase']='release-intent';self.save()
            if present:s.run([PF,'-X',ref['token']])
            if self.token_present():raise s.Refused('own_reference_release_unverified')
            ref['phase']='released';self.save()
        # Preserve later references. If the reference set stayed identical,
        # require the original enabled/disabled state too; never call -d.
        current_refs=self.refs()
        same_refs=reference_tokens(current_refs)==reference_tokens(pf['references_before'])
        if same_refs and self.enabled()!=pf['enabled_before']:
            raise s.Refused('pf_enabled_baseline_not_restored')
        self.session['pf_external_reference_change_preserved']=not same_refs
        self.save()
