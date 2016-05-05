import radiusd
import shared

def authorize(p):
    if not hasattr(shared, 'shared_attribute'):
        setattr(shared, 'shared_attribute', True)
        return radiusd.RLM_MODULE_NOOP

    return radiusd.RLM_MODULE_OK

