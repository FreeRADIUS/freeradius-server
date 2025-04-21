import freeradius
import shared


def recv(p):
    freeradius.log(
        "Python - shared_attribute=" + str(hasattr(shared, "shared_attribute")),
        freeradius.L_DBG
    )
    if not hasattr(shared, "shared_attribute"):
        setattr(shared, "shared_attribute", True)
        return freeradius.RLM_MODULE_NOOP
    else:
        return freeradius.RLM_MODULE_OK
