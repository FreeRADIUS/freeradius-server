import freeradius
import shared


def authorize(p):
    freeradius.log(
        freeradius.L_DBG,
        "Python - shared_attribute=" + str(hasattr(shared, "shared_attribute")),
    )
    if not hasattr(shared, "shared_attribute"):
        setattr(shared, "shared_attribute", True)
        return freeradius.RLM_MODULE_NOOP
    else:
        return freeradius.RLM_MODULE_OK
