#
#  Unit tests for dynamic xlat expansions
#


#
#  Test name
#
TEST := test.xlat

#
#  The test files are files without extensions.
#  The list is unordered.  The order is added in the next step by looking
#  at precursors.
#
FILES := $(subst $(DIR)/,,$(wildcard $(DIR)/*.txt))

$(eval $(call TEST_BOOTSTRAP))

#
#  And the actual script to run each test.
#
$(OUTPUT)/%: $(DIR)/% $(TESTBINDIR)/unit_test_module | build.raddb
	@echo "XLAT-TEST $(notdir $@)"
	${Q}if ! $(TESTBIN)/unit_test_module -D share/dictionary -d src/tests/xlat/ -r "$@" -i "$<" -xx -O xlat_only > "$@.log" 2>&1 || ! test -f "$@"; then \
		cat $@.log; \
		echo "./$(TESTBIN)/unit_test_module -D share/dictionary -d src/tests/xlat/ -r \"$@\" -i \"$<\" -xx -O xlat_only"; \
		rm -f $(BUILD_DIR)/tests/test.xlat; \
		exit 1; \
	fi
