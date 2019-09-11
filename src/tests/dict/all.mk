#
#  Test name
#
TEST := test.dict

#
#  Input files.
#
FILES := $(wildcard $(DIR)/*.dict)

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
#
$(FILES.$(TEST)): | $(OUTPUT)

#
#  We have a real file that's created if all of the tests pass.
#
$(BUILD_DIR)/tests/$(TEST): $(FILES.$(TEST))
	${Q}touch $@

#
#  For simplicity, we create a phony target so that the poor developer
#  doesn't need to remember path names
#
.PHONY: $(TEST)
$(TEST): $(BUILD_DIR)/tests/$(TEST)

#
#  Clean the ouput directory and files.
#
#  Note that we have to specify the actual filenames here, because
#  of stupidities with GNU Make.
#
.PHONY: clean.$(TEST)
clean.$(TEST):
	${Q}rm -rf $(BUILD_DIR)/tests/dict $(BUILD_DIR)/tests/test.dict

clean.test: clean.$(TEST)

#  And the actual script to run each test.
#
#  The parser expects to read "foo/dictionary", so we make a
#  "foo_dir" directory, and copy "foo" into "foo_dir/dictionary"
#
$(OUTPUT)/%: $(DIR)/% $(TESTBINDIR)/unit_test_attribute
	${Q}echo DICT UNIT-TEST $(notdir $@)
	${Q}mkdir -p $@_dir
	${Q}cp $< $@_dir/dictionary
	${Q}if ! $(TESTBIN)/unit_test_attribute -D $(top_srcdir)/share/dictionary -d "$@_dir" -r "$@" -xxx "$(dir $<)/empty.txt" > "$@.log" 2>&1 || ! test -f "$@"; then \
		echo "$(TESTBIN)/unit_test_attribute -D $(top_srcdir)/share/dictionary -d \"$@_dir\" -r \"$@\" \"$(dir $<)/empty.txt\""; \
		cat "$@.log"; \
		rm -f $(BUILD_DIR)/tests/test.dict; \
		exit 1; \
	fi
