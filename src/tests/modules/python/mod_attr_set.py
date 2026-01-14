import freeradius

def recv(p):
    p.reply["Reply-Message"] = "Value set by Python"
    p.control['NAS-IP-Address'] = '1.2.3.4'
    p.control['NAS-Port'] = '1'
    p.control['Class'] = 'hello'
    return freeradius.RLM_MODULE_OK

def authenticate(p):
    p.control['Password']['Cleartext'].value = p.request['User-Password'].value
    p.control['NAS-IP-Address'].value = '10.0.0.10'
    p.control['NAS-Port'].value = 123
    p.control['Class'].value = b'goodbye'
    return freeradius.RLM_MODULE_OK

def send(p):
    p.reply["Vendor-Specific"]["Cisco"]["AVPair"] = 'cisco=crazy'
    p.reply["Vendor-Specific"]["Cisco"]["AVPair"][1] = 'insane=syntax'
    return freeradius.RLM_MODULE_UPDATED

def recv_accounting_request(p):
    try:
        p.reply["Reply-Message"][5] = "This should not set"
    except:
        p.request['Filter-Id'] = 'Index exception caught'
    return freeradius.RLM_MODULE_OK

def accounting(p):
    try:
        p.request['NAS-IP-Address'] = 'hello'
    except:
        p.request['Filter-Id'].value = 'Conversion exception caught'

    try:
        p.request['NAS-IP-Address'].value = 1
    except:
        p.request['Filter-Id'][1].value = 'Type exception caught'

    return freeradius.RLM_MODULE_OK
