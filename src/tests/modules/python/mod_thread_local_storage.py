import freeradius
import threading

local = threading.local()

def authorize(p):
    global local
    freeradius.log(freeradius.L_DBG, 'Python - threading.local.tls()=' + str(hasattr(local, 'tls')))
    if hasattr(local, 'tls'):
        return freeradius.RLM_MODULE_OK
    else:
        local.tls = True
        return freeradius.RLM_MODULE_NOOP
