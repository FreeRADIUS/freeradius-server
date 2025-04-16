import threading

import freeradius

local = threading.local()


def authorize(p):
    global local
    freeradius.log(
        "Python - threading.local.tls()=" + str(hasattr(local, "tls")), freeradius.L_DBG
    )
    if hasattr(local, "tls"):
        return freeradius.RLM_MODULE_OK
    else:
        local.tls = True
        return freeradius.RLM_MODULE_NOOP
