import radiusd

def authorize(request, reply, *args):
    control, state = args
    
    # On the first call, control should be empty
    if not control:
        # Simply reply ok
        return (radiusd.RLM_MODULE_UPDATED, 
            ( ('Tmp-String-1', "MyReply"), ),
            ( ('Tmp-String-2', "MyControl"), ))


    # On the second call, we should have data in reply and control
    reply_ok = False
    for vp in reply:
        if vp[0] == 'Tmp-String-1':
            if vp[1] == 'MyReply':
                reply_ok = True

    control_ok = False
    for vp in control:
        if vp[0] == 'Tmp-String-2':
            if vp[1] == 'MyControl':
                control_ok = True

    if reply_ok and control_ok:
        return radiusd.RLM_MODULE_OK
    
    return radiusd.RLM_MODULE_NOOP