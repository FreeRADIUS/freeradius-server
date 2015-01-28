#
#  Unit tests for dynamic xlat expansions
#

#
#  The test files are files without extensions.
#  The list is unordered.  The order is added in the next step by looking
#  at precursors.
#
XLAT_FILES := $(subst $(DIR)/,,$(wildcard $(DIR)/*.txt))

#
#  Create the output directory
#
.PHONY: $(BUILD_DIR)/tests/xlat
$(BUILD_DIR)/tests/xlat:
	@mkdir -p $@

#
#  Files in the output dir depend on the unit tests
#
#	src/tests/xlat/FOO		input file
#	build/tests/xlat/FOO		updated if the test succeeds
#	build/tests/xlat/FOO.log	debug output for the test
#
#  Auto-depend on modules via $(shell grep INCLUDE $(DIR)/radiusd.conf | grep mods-enabled | sed 's/.*}/raddb/'))
#
#  If the test fails, then look for ERROR in the input.  No error
#  means it's unexpected, so we die.
#
#  Otherwise, check the log file for a parse error which matches the
#  ERROR line in the input.
#
$(BUILD_DIR)/tests/xlat/%: $(DIR)/% $(TESTBINDIR)/unittest | $(BUILD_DIR)/tests/xlat build.raddb
	@echo XLAT-TEST $(notdir $@)
	@if ! $(TESTBIN)/unittest -D share -d src/tests/xlat/ -i $< -xx -O xlat_only > $@.log 2>&1; then \
		cat $@.log; \
		echo "./$(TESTBIN)/unittest -D share -d src/tests/xlat/ -i $< -xx -O xlat_only"; \
		exit 1; \
	fi
	@touch $@

#
#  Get all of the unit test output files
#
TESTS.XLAT_FILES := $(addprefix $(BUILD_DIR)/tests/xlat/,$(XLAT_FILES))

#
#  Depend on the output files, and create the directory first.
#
tests.xlat: $(TESTS.XLAT_FILES)

$(TESTS.XLAT_FILES): $(TESTS.UNIT_FILES)

.PHONY: clean.tests.xlat
clean.tests.xlat:
	@rm -rf $(BUILD_DIR)/tests/xlat/
