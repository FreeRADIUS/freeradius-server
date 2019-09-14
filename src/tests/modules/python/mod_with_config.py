import radiusd

def authorize(p):
    if radiusd.config.get('a_param'):
        return radiusd.RLM_MODULE_OK

    return radiusd.RLM_MODULE_NOOP