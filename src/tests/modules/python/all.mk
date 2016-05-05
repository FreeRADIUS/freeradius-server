#
#  Test the "files" module
#

PYTHONPATH := $(top_builddir)/src/tests/modules/python/
export PYTHONPATH

#  MODULE.test is the main target for this module.
python.test: