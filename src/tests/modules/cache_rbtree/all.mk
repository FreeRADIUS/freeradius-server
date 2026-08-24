#
#  Test the "cache_rbtree" module
#
cache_rbtree.test:
TEST.modules.$(lastword $(subst /, ,$(dir $(lastword $(MAKEFILE_LIST))))).parallel := 1
