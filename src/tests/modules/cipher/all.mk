#
#  Test the "cipher" module
#
cipher.test:
TEST.modules.$(lastword $(subst /, ,$(dir $(lastword $(MAKEFILE_LIST))))).parallel := 1
