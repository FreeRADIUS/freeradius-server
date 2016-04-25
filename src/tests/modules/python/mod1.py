import threading

local = threading.local()

def authorize(p):
    global local
    if hasattr(local, 'tls'):
        return 2
    else:
        local.tls = True
        return 7