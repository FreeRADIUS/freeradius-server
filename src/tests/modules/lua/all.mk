#
#  Test the "lua" module
#
TEST.modules.$(lastword $(subst /, ,$(dir $(lastword $(MAKEFILE_LIST))))).parallel := 1

LUA_PATH := $(top_builddir)/src/tests/modules/lua/
export LUA_PATH

#  MODULE.test is the main target for this module.
lua.test:
