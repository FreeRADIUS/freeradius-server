#
#  Unit tests for individual pieces of functionality.
#

#
#  The files are put here in order.  Later tests need
#  functionality from earlier tests.
#
FILES  := rfc.txt errors.txt extended.txt lucent.txt wimax.txt \
	escape.txt condition.txt xlat.txt vendor.txt

#
#  Create the output directory
#
.PHONY: $(BUILD_DIR)/tests/unit
$(BUILD_DIR)/tests/unit:
	@mkdir -p $@

#
#  Files in the output dir depend on the unit tests
#
$(BUILD_DIR)/tests/unit/%: $(DIR)/% $(TESTBINDIR)/radattr | $(BUILD_DIR)/tests/unit
	@echo UNIT-TEST $(notdir $@)
	@if ! $(TESTBIN)/radattr -xxx -D $(top_srcdir)/share $<; then \
		echo "$(TESTBIN)/radattr -D $(top_srcdir)/share $<"; \
		exit 1; \
	fi
	@touch $@

#
#  Get all of the unit test output files
#
TESTS.UNIT_FILES := $(addprefix $(BUILD_DIR)/tests/unit/,$(FILES))

#
#  Depend on the output files, and create the directory first.
#
tests.unit: $(TESTS.UNIT_FILES)
