#
# Python module test
# Miguel A.L. Paraz <mparaz@mparaz.com>

import radiusd

def instantiate(p):
  print "*** instantiate ***"
  print p

def authorize(p):
  print "*** authorize ***"
  print
  radiusd.radlog(radiusd.L_INFO, '*** radlog call in authorize ***')
  print
  print p 
  return radiusd.RLM_MODULE_OK

def preacct(p):
  print "*** preacct ***"
  print p 
  return radiusd.RLM_MODULE_OK

def accounting(p):
  print "*** accounting ***"
  radiusd.radlog(radiusd.L_INFO, '*** radlog call in accounting (0) ***')
  print
  print p 
  return radiusd.RLM_MODULE_OK


def detach():
  print "*** goodbye from radiusd_test.py ***"
  return radiusd.RLM_MODULE_OK

