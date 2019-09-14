import radiusd
import shared

def authorize(p):
  radiusd.log(radiusd.L_DBG, 'Python - shared_attribute=' + str(hasattr(shared, 'shared_attribute')))
  if not hasattr(shared, 'shared_attribute'):
    setattr(shared, 'shared_attribute', True)
    return radiusd.RLM_MODULE_NOOP
  else:
     return radiusd.RLM_MODULE_OK
