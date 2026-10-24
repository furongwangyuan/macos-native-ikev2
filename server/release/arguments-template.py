"""Fixed action grammar, validated before imports or privileged effects."""
import unicodedata

DEVICE_ARITY={'device-add':2,'device-revoke':2,'device-recover':0,
              'device-list':0,'device-report':0,'device-export':1,'device-password':1}

def validate_request(action,values,allowed):
    if (type(action)is not str or action not in allowed or type(values)is not list
            or len(values)!=allowed[action]):
        raise ValueError('fixed_action_arity')
    if any(type(x)is not str or not x or len(x)>80
           or any(unicodedata.category(c)[0]=='C' or c in '\u2028\u2029' for c in x)
           for x in values):
        raise ValueError('fixed_argument_text')
    if action in ('device-add','device-revoke','device-export','device-password'):
        if re.fullmatch('[a-z][a-z0-9-]{0,30}[a-z0-9]',values[0])is None:
            raise ValueError('fixed_device_id')
        if action=='device-add' and values[1]!=values[1].strip():
            raise ValueError('fixed_device_display_name')
        if action=='device-revoke' and values[1] not in (
                'unspecified','keyCompromise','affiliationChanged','superseded','cessationOfOperation'):
            raise ValueError('fixed_revocation_reason')
    return action,tuple(values)
