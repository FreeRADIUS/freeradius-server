#
#  Test the "python" module
#
TEST.modules.$(lastword $(subst /, ,$(dir $(lastword $(MAKEFILE_LIST))))).parallel := 1

PYTHONPATH := $(top_builddir)/src/tests/modules/python/
export PYTHONPATH

#  MODULE.test is the main target for this module.
python.test:
