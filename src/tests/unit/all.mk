#
#  Unit tests for individual pieces of functionality.
#

#
#  The files are put here in order.  Later tests need
#  functionality from earlier tests.
#
FILES  := rfc.txt errors.txt extended.txt lucent.txt wimax.txt \
	escape.txt condition.txt xlat.txt vendor.txt dhcp.txt

#
#  Create the output directory
#
.PHONY: $(BUILD_DIR)/tests/unit
$(BUILD_DIR)/tests/unit:
	@mkdir -p $@

.PHONY: $(BUILD_DIR)/share
$(BUILD_DIR)/share:
	@mkdir -p $@

#
#  We need $INCLUDE in the output file, so we pass 2 parameters to 'echo'
#  No idea how portable that is...
#
$(BUILD_DIR)/share/dictionary: $(top_srcdir)/share/dictionary $(top_srcdir)/share/dictionary.dhcp | $(BUILD_DIR)/share
	@rm -f $@
	@for x in $^; do \
		echo '$$INCLUDE ' "$$x" >> $@; \
	done

#
#  Files in the output dir depend on the unit tests
#
$(BUILD_DIR)/tests/unit/%: $(DIR)/% $(BUILD_DIR)/bin/radattr $(TESTBINDIR)/radattr $(BUILD_DIR)/share/dictionary | $(BUILD_DIR)/tests/unit
	@echo UNIT-TEST $(notdir $@)
	@if ! $(TESTBIN)/radattr -D $(BUILD_DIR)/share $<; then \
		echo "$(TESTBIN)/radattr -D $(BUILD_DIR)/share $<"; \
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
