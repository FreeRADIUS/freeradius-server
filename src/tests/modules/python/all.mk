#
#  Test the "python" module
#
$(eval $(call TEST_PARALLEL))

PYTHONPATH := $(top_builddir)/src/tests/modules/python/
export PYTHONPATH

#  MODULE.test is the main target for this module.
python.test:
