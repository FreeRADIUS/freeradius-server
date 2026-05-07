#
#  Per-test result recorder.  Invoked from individual test recipes as:
#
#      $(call test_record,<category>,<name>,<status>,<logfile>)
#
#  Activated by touching $(BUILD_DIR)/tests/results.tsv
#

BUILD_DIR   ?= $(top_builddir)/build
RESULTS_TSV ?= $(BUILD_DIR)/tests/results.tsv

test_record = [ -e $(RESULTS_TSV) ] && printf '%s\t%s\t%s\t%s\n' '$(1)' '$(2)' '$(3)' '$(4)' >> $(RESULTS_TSV) || true
