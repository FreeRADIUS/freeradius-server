#
#  Create the output directory
#
.PHONY: $(BUILD_DIR)/tests/dict
$(BUILD_DIR)/tests/dict/radius:
	${Q}mkdir -p $@

FILES := $(wildcard $(DIR)/*.dict)

#
#  Files in the output dir depend on the unit tests
#
#  The parser expects to read "foo/dictionary", so we make a
#  "foo_dir" directory, and copy "foo" into "foo_dir/dictionary"
#
$(BUILD_DIR)/tests/dict/%: $(DIR)/% $(BUILD_DIR)/bin/unit_test_attribute $(TESTBINDIR)/unit_test_attribute | $(BUILD_DIR)/tests/dict
	${Q}echo DICT UNIT-TEST $(notdir $@)
	${Q}mkdir -p $@_dir
	${Q}cp $< $@_dir/dictionary
	${Q}if ! $(TESTBIN)/unit_test_attribute -D $(top_srcdir)/share/dictionary -d "$@_dir" -r "$@" -xxx "$(dir $<)/empty.txt" || ! test -f "$@"; then \
		echo "$(TESTBIN)/unit_test_attribute -D $(top_srcdir)/share/dictionary -d \"$@_dir\" -r \"$@\" \"$(dir $<)/empty.txt\""; \
		exit 1; \
	fi

TESTS.DICT_FILES := $(addprefix $(BUILD_DIR)/tests/dict/,$(notdir $(FILES)))

$(TESTS.DICT_FILES): | $(BUILD_DIR)/tests/dict

tests.dict: $(TESTS.DICT_FILES)

.PHONY: clean.tests.dict
clean.tests.dict:
	${Q}rm -rf $(BUILD_DIR)/tests/dict/

