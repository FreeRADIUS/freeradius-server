#! /usr/bin/env python3
#
# Python module example file
# Miguel A.L. Paraz <mparaz@mparaz.com>
#
# $Id$

import freeradius


def instantiate(p):
    print("*** instantiate ***")
    print(p)
    # return 0 for success or -1 for failure


def authorize(p):
    print("*** authorize ***")
    print("")
    freeradius.log(freeradius.L_INFO, "*** log call in authorize ***")
    print("")
    print(p)
    print("")
    print(freeradius.config)
    print("")
    return freeradius.RLM_MODULE_OK


def preacct(p):
    print("*** preacct ***")
    print(p)
    return freeradius.RLM_MODULE_OK


def accounting(p):
    print("*** accounting ***")
    freeradius.log(freeradius.L_INFO, "*** log call in accounting (0) ***")
    print("")
    print(p)
    return freeradius.RLM_MODULE_OK


def pre_proxy(p):
    print("*** pre_proxy ***")
    print(p)
    return freeradius.RLM_MODULE_OK


def post_proxy(p):
    print("*** post_proxy ***")
    print(p)
    return freeradius.RLM_MODULE_OK


def post_auth(p):
    print("*** post_auth ***")
    print(p)
    return freeradius.RLM_MODULE_OK


def recv_coa(p):
    print("*** recv_coa ***")
    print(p)
    return freeradius.RLM_MODULE_OK


def send_coa(p):
    print("*** send_coa ***")
    print(p)
    return freeradius.RLM_MODULE_OK


def detach(p):
    print("*** goodbye from example.py ***")
    return freeradius.RLM_MODULE_OK
