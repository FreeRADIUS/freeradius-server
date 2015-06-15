#
#  Unit tests for authentication
#

#
#  The test files are files without extensions.
#  The list is unordered.  The order is added in the next step by looking
#  at precursors.
#
AUTH_FILES := $(filter-out %.conf %.md %.attrs %.mk %~ %.rej,$(subst $(DIR)/,,$(wildcard $(DIR)/*)))

#
#  Create the output directory
#
.PHONY: $(BUILD_DIR)/tests/auth
$(BUILD_DIR)/tests/auth:
	@mkdir -p $@

#
#  Find which input files are needed by the tests
#  strip out the ones which exist
#  move the filenames to the build directory.
#
AUTH_EXISTS := $(addprefix $(DIR)/,$(addsuffix .attrs,$(AUTH_FILES)))
AUTH_NEEDS	 := $(filter-out $(wildcard $(AUTH_EXISTS)),$(AUTH_EXISTS))
AUTH	 := $(subst $(DIR),$(BUILD_DIR)/tests/auth,$(AUTH_NEEDS))

AUTH_HAS	 := $(filter $(wildcard $(AUTH_EXISTS)),$(AUTH_EXISTS))
AUTH_COPY	 := $(subst $(DIR),$(BUILD_DIR)/tests/auth,$(AUTH_NEEDS))

#
#  For each file, look for precursor test.
#  Ensure that each test depends on its precursors.
#
-include $(BUILD_DIR)/tests/auth/depends.mk

$(BUILD_DIR)/tests/auth/depends.mk: $(addprefix $(DIR)/,$(AUTH_FILES)) | $(BUILD_DIR)/tests/auth
	@rm -f $@
	@for x in $^; do \
		y=`grep 'PRE: ' $$x | sed 's/.*://;s/  / /g;s, , $(BUILD_DIR)/tests/auth/,g'`; \
		if [ "$$y" != "" ]; then \
			z=`echo $$x | sed 's,src/,$(BUILD_DIR)/',`; \
			echo "$$z: $$y" >> $@; \
			echo "" >> $@; \
		fi \
	done
#
#  These ones get copied over from the default input
#
$(AUTH): $(DIR)/default-input.attrs | $(BUILD_DIR)/tests/auth
	@cp $< $@

#
#  These ones get copied over from their original files
#
$(BUILD_DIR)/tests/auth/%.attrs: $(DIR)/%.attrs | $(BUILD_DIR)/tests/auth
	@cp $< $@

#
#  Don't auto-remove the files copied by the rule just above.
#  It's unnecessary, and it clutters the output with crap.
#
.PRECIOUS: $(BUILD_DIR)/tests/auth/%.attrs raddb/mods-enabled/wimax

AUTH_MODULES	:= $(shell grep -- mods-enabled src/tests/auth/radiusd.conf  | sed 's,.*/,,')
AUTH_RADDB	:= $(addprefix raddb/mods-enabled/,$(AUTH_MODULES))
AUTH_LIBS	:= $(addsuffix .la,$(addprefix rlm_,$(AUTH_MODULES)))

#
#  Files in the output dir depend on the unit tests
#
#	src/tests/auth/FOO		unlang for the test
#	src/tests/auth/FOO.attrs	input RADIUS and output filter
#	build/tests/auth/FOO	updated if the test succeeds
#	build/tests/auth/FOO.log	debug output for the test
#
#  Auto-depend on modules via $(shell grep INCLUDE $(DIR)/radiusd.conf | grep mods-enabled | sed 's/.*}/raddb/'))
#
#  If the test fails, then look for ERROR in the input.  No error
#  means it's unexpected, so we die.
#
#  Otherwise, check the log file for a parse error which matches the
#  ERROR line in the input.
#
$(BUILD_DIR)/tests/auth/%: $(DIR)/% $(BUILD_DIR)/tests/auth/%.attrs $(TESTBINDIR)/unittest | $(BUILD_DIR)/tests/auth $(AUTH_RADDB) $(AUTH_LIBS) build.raddb
	@echo UNIT-TEST $(notdir $@)
	@if ! TESTDIR=$(notdir $@) $(TESTBIN)/unittest -D share -d src/tests/auth/ -i $@.attrs -f $@.attrs -xxx > $@.log 2>&1; then \
		if ! grep ERROR $< 2>&1 > /dev/null; then \
			cat $@.log; \
			echo "# $@.log"; \
			echo "TESTDIR=$(notdir $@) $(TESTBIN)/unittest -D share -d src/tests/auth/ -i $@.attrs -f $@.attrs -xxx > $@.log 2>&1"; \
			exit 1; \
		fi; \
		FOUND=$$(grep ^$< $@.log | head -1 | sed 's/:.*//;s/.*\[//;s/\].*//'); \
		EXPECTED=$$(grep -n ERROR $< | sed 's/:.*//'); \
		if [ "$$EXPECTED" != "$$FOUND" ]; then \
			cat $@.log; \
			echo "# $@.log"; \
			echo "TESTDIR=$(notdir $@) $(TESTBIN)/unittest -D share -d src/tests/auth/ -i $@.attrs -f $@.attrs -xxx > $@.log 2>&1"; \
			exit 1; \
		fi \
	fi
	@touch $@

#
#  Get all of the unit test output files
#
TESTS.AUTH_FILES := $(addprefix $(BUILD_DIR)/tests/auth/,$(AUTH_FILES))

#
#  Depend on the output files, and create the directory first.
#
tests.auth: $(TESTS.AUTH_FILES)

$(TESTS.AUTH_FILES): $(TESTS.KEYWORDS_FILES)

.PHONY: clean.tests.auth
clean.tests.auth:
	@rm -rf $(BUILD_DIR)/tests/auth/
