import freeradius


def authorize(p):
    if freeradius.config.get("a_param"):
        return freeradius.RLM_MODULE_OK

    return freeradius.RLM_MODULE_NOOP
