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
	${Q}mkdir -p $@

#
#  Files in the output dir depend on the unit tests
#
#	src/tests/keywords/FOO		unlang for the test
#	src/tests/keywords/FOO.attrs	input RADIUS and output filter
#	build/tests/keywords/FOO	updated if the test succeeds
#	build/tests/keywords/FOO.log	debug output for the test
#
#  Auto-depend on modules via $(shell grep INCLUDE $(DIR)/radiusd.conf | grep mods-enabled | sed 's/.*}/raddb/'))
#
#  If the test fails, then look for ERROR in the input.  No error
#  means it's unexpected, so we die.
#
#  Otherwise, check the log file for a parse error which matches the
#  ERROR line in the input.
#
$(BUILD_DIR)/tests/xlat/%: $(DIR)/% $(TESTBINDIR)/unit_test_module | $(BUILD_DIR)/tests/xlat build.raddb
	${Q}echo XLAT-TEST $(notdir $@)
	${Q}if ! $(TESTBIN)/unit_test_module -D share -d src/tests/xlat/ -i $< -xx -O xlat_only > $@.log 2>&1; then \
		cat $@.log; \
		echo "./$(TESTBIN)/unit_test_module -D share -d src/tests/xlat/ -i $< -xx -O xlat_only"; \
		exit 1; \
	fi
	${Q}touch $@

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
	${Q}rm -rf $(BUILD_DIR)/tests/xlat/
