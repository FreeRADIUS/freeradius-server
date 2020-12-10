import freeradius

#
# Print out the p["request"], p["control"], p["reply"] and p["session-state"]
#
def radius_dump_list(p):
  for _l in p:
    list_keys = p[_l]
    print("  list: '{}'".format(_l))
    if not list_keys is None:
      for k, v in list_keys:
        print("     attr='{}', value='{}'".format(k, v))

def authorize(p):
  freeradius.log(freeradius.L_INFO, '*** log call in authorize ***')
  print("# Dump lists")
  radius_dump_list(p)
  print("# Print freeradius.config")
  print(freeradius.config)

  freeradius.log(freeradius.L_INFO, "*** Updating request=('NAS-Identifier', 'Tapioca')")
  update_dict = {
    "request": (
      ("NAS-Identifier", "Tapioca"),
    ),
    "control": (
      ("NAS-Identifier", "Pudim"),
    ),
    "session-state": (
      ("NAS-Identifier", "Goiabada"),
    ),
    "reply": (
      ("NAS-Identifier", "Farofa"),
      ("Reply-Message", "Handled by rlm_python"),
    ),
  }
  return freeradius.RLM_MODULE_OK, update_dict
