#! /usr/bin/env python3
#
# Python module example file
# Miguel A.L. Paraz <mparaz@mparaz.com>
#
# $Id$

import freeradius

#
# Print out the p["request"], p["control"], p["reply"] and p["session-state"]
#
def radius_dump_list(p):
  print("# Dump lists")
  for _l in p:
    list_keys = p[_l]
    print("  list: '{}'".format(_l))
    if not list_keys is None:
      for k, v in list_keys:
        print("     attr='{}', value='{}'".format(k, v))

def instantiate(p):
  print("*** instantiate ***")
  radius_dump_list(p)
  # return 0 for success or -1 for failure

def authorize(p):
  print("*** authorize ***")
  print("")
  freeradius.log(freeradius.L_INFO, '*** log call in authorize ***')
  print("")
  radius_dump_list(p)
  print("")
  print(freeradius.config)
  print("")
  return freeradius.RLM_MODULE_OK

def preacct(p):
  print("*** preacct ***")
  freeradius.log(freeradius.L_INFO, '*** log call in authorize ***')
  radius_dump_list(p)
  print("# Print freeradius.config")
  print(freeradius.config)
  print("")
  #
  # Dictionary representing changes we want to make to the different VPS
  #
#  update_dict = {
#    "request": (
#      ("NAS-Identifier", "python-script"),
#    ),
#    "reply": (
#     ("Reply-Message", "Handled by rlm_python"),
#    ),
#  }
#  return freeradius.RLM_MODULE_OK, update_dict
  return freeradius.RLM_MODULE_OK

def preacct(p):
  print("*** preacct ***")
  radius_dump_list(p)
  return freeradius.RLM_MODULE_OK

def accounting(p):
  print("*** accounting ***")
  freeradius.log(freeradius.L_INFO, '*** log call in accounting (0) ***')
  print("")
  radius_dump_list(p)
  return freeradius.RLM_MODULE_OK

def pre_proxy(p):
  print("*** pre_proxy ***")
  radius_dump_list(p)
  return freeradius.RLM_MODULE_OK

def post_proxy(p):
  print("*** post_proxy ***")
  radius_dump_list(p)
  return freeradius.RLM_MODULE_OK

def post_auth(p):
  print("*** post_auth ***")
  radius_dump_list(p)
  return freeradius.RLM_MODULE_OK

def recv_coa(p):
  print("*** recv_coa ***")
  radius_dump_list(p)
  return freeradius.RLM_MODULE_OK

def send_coa(p):
  print("*** send_coa ***")
  radius_dump_list(p)
  return freeradius.RLM_MODULE_OK

def detach():
  print("*** goodbye from example.py ***")
  return freeradius.RLM_MODULE_OK
