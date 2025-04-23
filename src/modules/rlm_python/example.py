#! /usr/bin/env python3
#
# Python module example file
# Miguel A.L. Paraz <mparaz@mparaz.com>
#
# $Id$

import freeradius


def instantiate(p):
    print("*** instantiate ***")
    # return 0 for success or -1 for failure


def recv_access_request(p):
    print("*** recv Access-Request ***")
    freeradius.log("*** log call in authorize ***", freeradius.L_INFO)
    print(p.request["User-Name"])
    print(freeradius.config)
    return freeradius.RLM_MODULE_OK

def authenticate(p):
    print("*** authenticate ***")
    print(p.request["User-Name"])
    return freeradius.RLM_MODULE_OK

def send(p):
    print("*** send ***")
    print(p.reply["Packet-Type"])
    return freeradius.RLM_MODULE_OK

def recv_accounting_request(p):
    print("*** recv Accounting-Request ***")
    print(p.request["Acct-Session-Id"])
    return freeradius.RLM_MODULE_OK

def accounting(p):
    print("*** accounting ***")
    freeradius.log("*** log call in accounting (0) ***", freeradius.L_INFO)
    print(p.request["User-Name"])
    return freeradius.RLM_MODULE_OK

def detach(p):
    print("*** goodbye from example.py ***")
    return freeradius.RLM_MODULE_OK
