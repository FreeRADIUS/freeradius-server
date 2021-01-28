#
#  Unit tests for authentication
#

#
#  Test name
#
TEST := test.auth

#
#  The test files are files without extensions.
#  The list is unordered.  The order is added in the next step by looking
#  at precursors.
#
FILES := $(filter-out %.conf %.md %.attrs %.mk %~ %.rej,$(subst $(DIR)/,,$(wildcard $(DIR)/*)))

$(eval $(call TEST_BOOTSTRAP))

#
#  Find which input files are needed by the tests
#  strip out the ones which exist
#  move the filenames to the build directory.
#
AUTH_EXISTS := $(addprefix $(DIR)/,$(addsuffix .attrs,$(FILES)))
AUTH_NEEDS	 := $(filter-out $(wildcard $(AUTH_EXISTS)),$(AUTH_EXISTS))
AUTH	 := $(subst $(DIR),$(OUTPUT),$(AUTH_NEEDS))

AUTH_HAS	 := $(filter $(wildcard $(AUTH_EXISTS)),$(AUTH_EXISTS))
AUTH_COPY	 := $(subst $(DIR),$(OUTPUT),$(AUTH_NEEDS))

#
#  For each file, look for precursor test.
#  Ensure that each test depends on its precursors.
#
-include $(OUTPUT)/depends.mk

$(OUTPUT)/depends.mk: $(addprefix $(DIR)/,$(FILES)) | $(OUTPUT)
	${Q}rm -f $@
	${Q}touch $@
	${Q}for x in $^; do \
		y=`grep 'PRE: ' $$x | sed 's/.*://;s/  / /g;s, , $(OUTPUT)/,g'`; \
		if [ "$$y" != "" ]; then \
			z=`echo $$x | sed 's,src/,$(BUILD_DIR)/',`; \
			echo "$$z: $$y" >> $@; \
			echo "" >> $@; \
		fi \
	done
#
#  These ones get copied over from the default input
#
$(AUTH): $(DIR)/default-input.attrs | $(OUTPUT)
	${Q}cp $< $@

#
#  These ones get copied over from their original files
#
$(OUTPUT)/%.attrs: $(DIR)/%.attrs | $(OUTPUT)
	${Q}cp $< $@

#
#  Don't auto-remove the files copied by the rule just above.
#  It's unnecessary, and it clutters the output with crap.
#
.PRECIOUS: $(OUTPUT)/%.attrs raddb/mods-enabled/wimax

#
#  Cache the list of modules which are enabled, so that we don't run
#  the shell script on every build.
#
#  AUTH_MODULES := $(shell grep -- mods-enabled src/tests/auth/unit_test_module.conf | sed 's,.*/,,')
#
$(OUTPUT)/enabled.mk: src/tests/auth/unit_test_module.conf | $(OUTPUT)
	${Q}echo "auth_MODULES := " $$(grep -- mods-enabled src/tests/auth/unit_test_module.conf | sed 's,.*/,,' | tr '\n' ' ' ) > $@
-include $(OUTPUT)/enabled.mk

AUTH_RADDB	:= $(addprefix raddb/mods-enabled/,$(AUTH_MODULES))
AUTH_LIBS	:= $(addsuffix .la,$(addprefix rlm_,$(AUTH_MODULES)))

#
#  Files in the output dir depend on the unit tests
#
#	src/tests/auth/FOO		unlang for the test
#	src/tests/auth/FOO.attrs	input RADIUS and output filter
#	build/tests/auth/FOO		updated if the test succeeds
#	build/tests/auth/FOO.log	debug output for the test
#
#  Auto-depend on modules via $(AUTH_MODULES)
#
#  If the test fails, then look for ERROR in the input.  No error
#  means it's unexpected, so we die.
#
#  Otherwise, check the log file for a parse error which matches the
#  ERROR line in the input.
#
$(OUTPUT)/%: $(DIR)/% $(OUTPUT)/%.attrs $(TEST_BIN_DIR)/unit_test_module | $(AUTH_RADDB) $(AUTH_LIBS) build.raddb
	@echo "AUTH-TEST $(notdir $@)"
	${Q}if ! TESTDIR=$(notdir $@) $(TEST_BIN)/unit_test_module -D share/dictionary -d src/tests/auth/ -i "$@.attrs" -f "$@.attrs" -r "$@" -xx > "$@.log" 2>&1 || ! test -f "$@"; then \
		if ! grep ERROR $< 2>&1 > /dev/null; then \
			cat $@.log; \
			echo "# $@.log"; \
			echo "TESTDIR=$(notdir $@) $(TEST_BIN)/unit_test_module -D share/dictionary -d src/tests/auth/ -i \"$@.attrs\" -f \"$@.attrs\" -r \"$@\" -xxx > \"$@.log\" 2>&1"; \
			rm -f $(BUILD_DIR)/tests/test.auth; \
			exit 1; \
		fi; \
		FOUND=$$(grep ^$< $@.log | head -1 | sed 's/:.*//;s/.*\[//;s/\].*//'); \
		EXPECTED=$$(grep -n ERROR $< | sed 's/:.*//'); \
		if [ "$$EXPECTED" != "$$FOUND" ]; then \
			cat $@.log; \
			echo "# $@.log"; \
			echo "TESTDIR=$(notdir $@) $(TEST_BIN)/unit_test_module -D share/dictionary -d src/tests/auth/ -i \"$@.attrs\" -f \"$@.attrs\" -r \"$@\" -xxx > \"$@.log\" 2>&1"; \
			rm -f $(BUILD_DIR)/tests/test.auth; \
			exit 1; \
		else \
			touch "$@"; \
		fi \
	fi
