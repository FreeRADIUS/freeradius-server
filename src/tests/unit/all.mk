#
#  Unit tests for individual pieces of functionality.
#

#
#  The files are put here in order.  Later tests need
#  functionality from earlier tests.
#
FILES  := rfc.txt errors.txt extended.txt lucent.txt wimax.txt \
	condition.txt xlat.txt

#
#  Create the output directory
#
.PHONY: $(BUILD_DIR)/tests/unit
$(BUILD_DIR)/tests/unit:
	@mkdir -p $@

#
#  Files in the output dir depend on the unit tests
#
$(BUILD_DIR)/tests/unit/%: $(DIR)/% ./$(BUILD_DIR)/bin/local/radattr | $(BUILD_DIR)/tests/unit
	@echo UNIT-TEST $(notdir $@)
	@$(JLIBTOOL) --quiet --mode=execute ./$(BUILD_DIR)/bin/local/radattr -d $(top_srcdir)/share $<
	@touch $@

#
#  Get all of the unit test output files
#
TESTS.UNIT_FILES := $(addprefix $(BUILD_DIR)/tests/unit/,$(FILES))

#
#  Depend on the output files, and create the directory first.
#
tests.unit: $(TESTS.UNIT_FILES)
