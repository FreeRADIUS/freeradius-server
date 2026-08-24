#
#  Test the "lua" module
#
$(eval $(call TEST_PARALLEL))

LUA_PATH := $(top_builddir)/src/tests/modules/lua/
export LUA_PATH

#  MODULE.test is the main target for this module.
lua.test:
