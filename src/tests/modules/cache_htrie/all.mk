#
#  Test the "cache_htrie" module
#
cache_htrie.test:
TEST.modules.$(lastword $(subst /, ,$(dir $(lastword $(MAKEFILE_LIST))))).parallel := 1
