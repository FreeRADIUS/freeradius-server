#
#  Unit tests for unlang keywords
#

#
#  The test files are files without extensions.
#  The list is unordered.  The order is added in the next step by looking
#  at precursors.
#
KEYWORD_FILES := $(filter-out %.conf %.md %.attrs %.mk %~ %.rej,$(subst $(DIR)/,,$(wildcard $(DIR)/*)))

ifeq "$(OPENSSL_LIBS)" ""
KEYWORD_FILES := $(filter-out pap-ssha2,$(KEYWORD_FILES))
endif

#
#  Create the output directory
#
.PHONY: $(BUILD_DIR)/tests/keywords
$(BUILD_DIR)/tests/keywords:
	@mkdir -p $@

#
#  For each file, look for precursor test.
#  Ensure that each test depends on its precursors.
#
-include $(BUILD_DIR)/tests/keywords/depends.mk

export OPENSSL_LIBS

$(BUILD_DIR)/tests/keywords/depends.mk: $(addprefix $(DIR)/,$(KEYWORD_FILES)) | $(BUILD_DIR)/tests/keywords
	@rm -f $@
	@for x in $^; do \
		y=`grep 'PRE: ' $$x | sed 's/.*://;s/  / /g;s, , $(BUILD_DIR)/tests/keywords/,g'`; \
		if [ "$$y" != "" ]; then \
			z=`echo $$x | sed 's,src/,$(BUILD_DIR)/',`; \
			echo "$$z: $$y" >> $@; \
			echo "" >> $@; \
		fi \
	done

#
#  For sheer laziness, allow "make test.keywords.foo"
#
define KEYWORD_TEST
tests.keywords.${1}: $(addprefix $(OUTPUT)/,${1})

tests.keywords.help: TEST_KEYWORDS_HELP += tests.keywords.${1}

OUTPUT := $(BUILD_DIR)/tests/keywords

#
#  Create the input attrs, either from the test-specific input,
#  or from the default input.
#
$(OUTPUT)/${1}: $(OUTPUT)/${1}.attrs | $(dir $(OUTPUT)/${1})
$(OUTPUT)/${1}.attrs: | $(dir $(OUTPUT)/${1})

ifneq "$(wildcard src/tests/keywords/${1}.attrs)" ""
$(OUTPUT)/${1}.attrs: src/tests/keywords/${1}.attrs
else
$(OUTPUT)/${1}.attrs: src/tests/keywords/default-input.attrs
endif
	@cp $$< $$@
ifeq "${1}" "mschap"
$(OUTPUT)/${1}: rlm_mschap.la
endif

endef
$(foreach x,$(KEYWORD_FILES),$(eval $(call KEYWORD_TEST,$x)))

#
#  Don't auto-remove the files copied by the rule just above.
#  It's unnecessary, and it clutters the output with crap.
#
.PRECIOUS: $(BUILD_DIR)/tests/keywords/%.attrs

KEYWORD_MODULES := $(shell grep -- mods-enabled src/tests/keywords/radiusd.conf | sed 's,.*/,,')
KEYWORD_RADDB	:= $(addprefix raddb/mods-enabled/,$(KEYWORD_MODULES))
KEYWORD_LIBS	:= $(addsuffix .la,$(addprefix rlm_,$(KEYWORD_MODULES))) rlm_example.la rlm_cache.la

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
$(BUILD_DIR)/tests/keywords/%: ${DIR}/% $(BUILD_DIR)/tests/keywords/%.attrs $(TESTBINDIR)/unittest | $(BUILD_DIR)/tests/keywords $(KEYWORD_RADDB) $(KEYWORD_LIBS) build.raddb rlm_cache_rbtree.la rlm_test.la rlm_unix.la
	@echo UNIT-TEST $(notdir $@)
	@if ! KEYWORD=$(notdir $@) $(TESTBIN)/unittest -D share -d src/tests/keywords/ -i $@.attrs -f $@.attrs -xx > $@.log 2>&1; then \
		if ! grep ERROR $< 2>&1 > /dev/null; then \
			cat $@.log; \
			echo "# $@.log"; \
			echo KEYWORD=$(notdir $@) $(TESTBIN)/unittest -D share -d src/tests/keywords/ -i $@.attrs -f $@.attrs -xx; \
			exit 1; \
		fi; \
		FOUND=$$(grep ^$< $@.log | head -1 | sed 's/:.*//;s/.*\[//;s/\].*//'); \
		EXPECTED=$$(grep -n ERROR $< | sed 's/:.*//'); \
		if [ "$$EXPECTED" != "$$FOUND" ]; then \
			cat $@.log; \
			echo "# $@.log"; \
			echo KEYWORD=$(notdir $@) $(TESTBIN)/unittest -D share -d src/tests/keywords/ -i $@.attrs -f $@.attrs -xx; \
			exit 1; \
		fi \
	fi
	@touch $@

#
#  Get all of the unit test output files
#
TESTS.KEYWORDS_FILES := $(addprefix $(BUILD_DIR)/tests/keywords/,$(KEYWORD_FILES))

#
#  Depend on the output files, and create the directory first.
#
tests.keywords: $(TESTS.KEYWORDS_FILES)

$(TESTS.KEYWORDS_FILES): $(TESTS.XLAT_FILES) $(TESTS.MAP_FILES)

.PHONY: clean.tests.keywords
clean.tests.keywords:
	@rm -rf $(BUILD_DIR)/tests/keywords/
