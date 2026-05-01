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
$(OUTPUT)/%: $(DIR)/% $(TEST_BIN_DIR)/unit_test_module $(DIR)/packet | build.raddb
	$(eval CMD := $(TEST_BIN)/unit_test_module -D share/dictionary -d src/tests/xlat/ -r "$@" -i $(dir $<)/packet -I "$<" -xx)
	@echo "XLAT-TEST $(notdir $@)"
	@printf '%s\n' '$(CMD)' > $@.cmd
	${Q}if ! $(CMD) > "$@.log" 2>&1 || ! test -f "$@"; then \
		cat $@.log; \
		rm -f $(BUILD_DIR)/tests/test.xlat; \
		$(call test_record,xlat,$(notdir $@),FAIL,$@.log); \
		exit 1; \
	fi
	@$(call test_record,xlat,$(notdir $@),PASS,$@.log)
