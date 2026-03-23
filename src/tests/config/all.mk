#
#  Unit tests for configuration files
#


#
#  Test name
#
TEST := test.config

#
#  The test files are files without extensions.
#  The list is unordered.  The order is added in the next step by looking
#  at precursors.
#
FILES := $(filter-out %.ignore %.md %.attrs %.servers %.mk %~ %.rej,$(subst $(DIR)/,,$(wildcard $(DIR)/modules/*)))

$(eval $(call TEST_BOOTSTRAP))

#
#  For sheer laziness, allow "make test.keywords.foo"
#
define CONFIG_TEST
test.config.${1}: $(addprefix $(OUTPUT)/,${1})

test.config.help: TEST_CONFIG_HELP += test.config.${1}
endef
$(foreach x,$(FILES),$(eval $(call CONFIG_TEST,$x)))

#
#  Cache the list of modules which are enabled, so that we don't run
#  the shell script on every build.
#
#  CONFIG_MODULES := $(shell grep -- mods-enabled src/tests/config/unit_test_module.conf | sed 's,.*/,,')
#
$(OUTPUT)/enabled.mk: src/tests/config/unit_test_module.conf | $(OUTPUT)
	${Q}echo "CONFIG_MODULES := " $$(grep -- mods-enabled src/tests/config/unit_test_module.conf | sed 's,.*/,,' | tr '\n' ' ' ) > $@
-include $(OUTPUT)/enabled.mk

CONFIG_LIBS	:= $(addsuffix .la,$(addprefix rlm_,$(CONFIG_MODULES))) rlm_csv.la

#
#  Files in the output dir depend on the unit tests
#
#	src/tests/config/modules/FOO	module configuration
#
#  If the test fails, then look for ERROR in the input.  No error
#  means it's unexpected, so we die.
#
#  Otherwise, check the log file for a parse error which matches the
#  ERROR line in the input.
#
#  NOTE: Grepping for $< is not safe cross platform, as on Linux it
#  expands to the full absolute path, and on macOS it appears to be relative.
#
#  To quickly find all failing tests, run:
#
#	(make -k test.config 2>&1) | grep 'CONFIG=' | sed 's/CONFIG=//;s/ .*$//'
#
$(OUTPUT)/%: $(DIR)/% $(TEST_BIN_DIR)/unit_test_module | $(CONFIG_LIBS)
	@mkdir -p $(dir $@)
	$(eval CMD:=CONFIG_FILE=$(notdir $@) $(TEST_BIN)/unit_test_module $(UNIT_TEST_CONFIG_ARGS.$(subst -,_,$(notdir $@))) -D share/dictionary -d src/tests/config/ -xxC )
	@echo "CONFIG-TEST $(notdir $@)"
	${Q}if ! $(CMD) > "$@.log" 2>&1; then \
		if ! grep ERROR $< 2>&1 > /dev/null; then \
			cat $@.log; \
			echo "# $@.log"; \
			echo $(CMD); \
			rm -f $(BUILD_DIR)/tests/test.config; \
			exit 1; \
		fi; \
		FOUND=$$(grep 'Error : src/tests/config/' $@.log | egrep -v -- '-->' | head -1 | sed 's/]:.*//;s/.*\[//;s/\].*//'); \
		EXPECTED=$$(grep -n ERROR $< | sed 's/:.*//'); \
		if [ "$$EXPECTED" != "$$FOUND" ]; then \
			cat $@.log; \
			echo "# $@.log"; \
			echo $(CMD); \
			rm -f $(BUILD_DIR)/tests/test.config; \
			exit 1; \
		else \
			touch "$@"; \
		fi \
	fi

$(TEST):
	@touch $(BUILD_DIR)/tests/$@

$(TEST).help:
	@echo make $(TEST_CONFIG_HELP)
