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

OUTPUT := $(subst $(top_srcdir)/src,$(BUILD_DIR),$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

#
#  Create the output directory
#
.PHONY: $(OUTPUT)
$(OUTPUT):
	${Q}mkdir -p $@

#
#  All of the output files depend on the input files
#
FILES.$(TEST) := $(addprefix $(OUTPUT),$(notdir $(FILES)))

#
#  The output files also depend on the directory
#  and on the previous test.
#
$(FILES.$(TEST)): $(BUILD_DIR)/tests/test.unit | $(OUTPUT)

#
#  We have a real file that's created if all of the tests pass.
#
$(BUILD_DIR)/tests/$(TEST): $(FILES.$(TEST))
	${Q}touch $@

#
#  For simplicity, we create a phony target so that the poor developer
#  doesn't need to remember path names
#
$(TEST): $(BUILD_DIR)/tests/$(TEST)

#
#  Clean the ouput directory and files.
#
#  Note that we have to specify the actual filenames here, because
#  of stupidities with GNU Make.
#
.PHONY: clean.$(TEST)
clean.$(TEST):
	${Q}rm -rf $(BUILD_DIR)/tests/xlat $(BUILD_DIR)/tests/test.xlat

clean.test: clean.$(TEST)

#
#  And the actual script to run each test.
#
$(BUILD_DIR)/tests/xlat/%: $(DIR)/% $(TESTBINDIR)/unit_test_module | build.raddb
	${Q}echo XLAT-TEST $(notdir $@)
	${Q}if ! $(TESTBIN)/unit_test_module -D share/dictionary -d src/tests/xlat/ -r "$@" -i "$<" -xx -O xlat_only > "$@.log" 2>&1 || ! test -f "$@"; then \
		cat $@.log; \
		echo "./$(TESTBIN)/unit_test_module -D share/dictionary -d src/tests/xlat/ -r \"$@\" -i \"$<\" -xx -O xlat_only"; \
		rm -f $(BUILD_DIR)/tests/test.xlat; \
		exit 1; \
	fi
