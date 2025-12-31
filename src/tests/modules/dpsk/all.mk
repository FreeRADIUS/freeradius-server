#
#  Test the "dpsk" module
#
TEST.modules.$(lastword $(subst /, ,$(dir $(lastword $(MAKEFILE_LIST))))).parallel := 1
