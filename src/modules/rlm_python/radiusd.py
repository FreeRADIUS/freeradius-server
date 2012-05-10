#! /usr/bin/env python
#
# Definitions for RADIUS programs
#
# Copyright 2002 Miguel A.L. Paraz <mparaz@mparaz.com>
#
# This should only be used when testing modules.
# Inside freeradius, the 'radiusd' Python module is created by the C module
# and the definitions are automatically created.
#
# $Id$

# from modules.h

RLM_MODULE_REJECT = 0
RLM_MODULE_FAIL = 1
RLM_MODULE_OK = 2
RLM_MODULE_HANDLED = 3
RLM_MODULE_INVALID = 4
RLM_MODULE_USERLOCK = 5
RLM_MODULE_NOTFOUND = 6
RLM_MODULE_NOOP = 7	
RLM_MODULE_UPDATED = 8
RLM_MODULE_NUMCODES = 9


# from radiusd.h
L_DBG = 1
L_AUTH = 2
L_INFO = 3
L_ERR = 4
L_PROXY	= 5
L_CONS = 128

# from token.h
T_OP_ADD = 8
T_OP_EQ = 11
T_OP_CMP_EQ = 21


# log function
def radlog(level, msg):
    import sys
    sys.stdout.write(msg + '\n')

    level = level
  


  
