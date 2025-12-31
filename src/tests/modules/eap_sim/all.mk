#
#  Test the eap_sim module
#
test.modules.$(lastword $(subst /, ,$(dir $(lastword $(makefile_list))))).parallel := 1
