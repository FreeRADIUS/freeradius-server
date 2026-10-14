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
#  The test loads modules at run time, so make needs telling about them.  The
#  list comes from the config itself.
#
$(eval $(call TEST_CONFIG_LIBS,$(DIR)/unit_test_module.conf,$(FILES.$(TEST))))

#
#  And the actual script to run each test.
#
XLAT_CMD = \
	$(TEST_BIN)/unit_test_module \
	-D share/dictionary \
	-d src/tests/xlat/ \
	-r $(call SHELL_QUOTE,$@) \
	-i $(call SHELL_QUOTE,$(dir $<)packet) \
	-I $(call SHELL_QUOTE,$<) \
	-xx

$(OUTPUT)/%: $(DIR)/% $(TEST_BIN_DIR)/unit_test_module $(DIR)/packet | build.raddb
	@echo "XLAT-TEST $(notdir $@)"
	${Q}if ! $(XLAT_CMD) > "$@.log" 2>&1 || ! test -f "$@"; then \
		cat $@.log; \
		echo $(call SHELL_QUOTE,$(XLAT_CMD)); \
		rm -f $(BUILD_DIR)/tests/test.xlat; \
		exit 1; \
	fi
