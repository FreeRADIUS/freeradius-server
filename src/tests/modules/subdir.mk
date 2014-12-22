#
# Included by each module, after setting various flags
#

#
#  Find out which test directory included us.  We can't do math in GNU make,
#  so we get the lastword of the makefile list, then strip it out of the
#  makefile list, then get the last word of the resulting list.  Then
#  get the name of the directory which included us
#
MODULE_TEST := $(patsubst src/tests/modules/%/all.mk,%,$(lastword $(subst $(lastword ${MAKEFILE_LIST}),,${MAKEFILE_LIST})))

#
#  This is easier than re-typing them everywhere.
#
MODULE_DIR := modules/$(MODULE_TEST)
TEST_DIR := $(BUILD_DIR)/tests/$(MODULE_DIR)

#
#  The test files are files without extensions.
#  The list is unordered.  The order is added in the next step by looking
#  at precursors.
#
MODULE_FILES := $(subst src/tests/$(MODULE_DIR)/,,$(wildcard src/tests/$(MODULE_DIR)/*.unlang))

#
#  Create the directory where the output files go, because GNU Make is
#  too stupid to do that itself.
#
.PHONY: $(TEST_DIR)
$(TEST_DIR):
	@mkdir -p $@

#
#  For each file, look for precursor test.
#  Ensure that each test depends on its precursors.
#
-include $(TEST_DIR)/depends.mk

$(TEST_DIR)/depends.mk: $(addprefix src/tests/$(MODULE_DIR)/,$(MODULE_FILES)) | $(TEST_DIR)
	@rm -f $@
	@for x in $^; do \
		y=`grep 'PRE: ' $$x | sed 's/.*://;s/  / /g;s, , $(TEST_DIR),g'`; \
		if [ "$$y" != "" ]; then \
			z=`echo $$x | sed 's,src/,$(BUILD_DIR)/',`; \
			echo "$$z: $$y" >> $@; \
			echo "" >> $@; \
		fi \
	done

MODULE_TEST_EXISTS := $(addprefix src/tests/$(MODULE_DIR)/,$(patsubst %.unlang,%.attrs,$(MODULE_FILES)))
MODULE_TEST_NEEDS := $(filter-out $(wildcard $(MODULE_TEST_EXISTS)),$(MODULE_TEST_EXISTS))
MODULE_TEST_COPY   := $(subst src/tests/$(MODULE_DIR),$(TEST_DIR),$(MODULE_TEST_NEEDS))

#
#  These ones get copied over from the default input
#
$(MODULE_TEST_COPY): src/tests/modules/default-input.attrs | $(TEST_DIR)
	@cp $< $@

#
#  These ones get copied over from their original files
#
$(TEST_DIR)/%.attrs: src/tests/$(MODULE_DIR)/%.attrs | $(TEST_DIR)
	@cp $< $@

#
#  Don't auto-remove the files copied by the rule just above.
#  It's unnecessary, and it clutters the output with crap.
#
.PRECIOUS: $(TEST_DIR)/%.attrs

#
#  Files in the output dir depend on the unit tests
#
#	src/tests/$(MODULE_DIR)/FOO		unlang for the test
#	src/tests/$(MODULE_DIR)/FOO.attrs	input RADIUS and output filter
#	build/tests/$(MODULE_DIR)/FOO	updated if the test succeeds
#	build/tests/$(MODULE_DIR)/FOO.log	debug output for the test
#
#  If the test fails, then look for ERROR in the input.  No error
#  means it's unexpected, so we die.
#
#  Otherwise, check the log file for a parse error which matches the
#  ERROR line in the input.
#
$(TEST_DIR)/%: src/tests/$(MODULE_DIR)/%.unlang $(TEST_DIR)/%.attrs $(TESTBINDIR)/unittest | $(TEST_DIR) build.raddb
	@echo UNIT-TEST $(notdir $@)
	@if ! MODULE_TEST_DIR=src/tests/$(MODULE_DIR) MODULE_TEST_UNLANG=src/tests/$(MODULE_DIR)/$(notdir $@).unlang $(TESTBIN)/unittest -D share -d src/tests/modules/ -i $@.attrs -f $@.attrs -xx > $@.log 2>&1; then \
		if ! grep ERROR $< 2>&1 > /dev/null; then \
			cat $@.log; \
			echo "# $@.log"; \
			echo MODULE_TEST_DIR=src/tests/$(MODULE_DIR) MODULE_TEST_UNLANG=src/tests/$(MODULE_DIR)/$(notdir $@).unlang $(TESTBIN)/unittest -D share -d src/tests/modules/ -i $@.attrs -f $@.attrs -xx; \
			exit 1; \
		fi; \
		FOUND=$$(grep ^$< $@.log | head -1 | sed 's/:.*//;s/.*\[//;s/\].*//'); \
		EXPECTED=$$(grep -n ERROR $< | sed 's/:.*//'); \
		if [ "$$EXPECTED" != "$$FOUND" ]; then \
			cat $@.log; \
			echo "# $@.log"; \
			echo MODULE_TEST_DIR=src/tests/$(MODULE_DIR) MODULE_TEST_UNLANG=src/tests/$(MODULE_DIR)/$(notdir $@).unlang $(TESTBIN)/unittest -D share -d src/tests/modules/ -i $@.attrs -f $@.attrs -xx; \
			exit 1; \
		fi \
	fi
	@touch $@

#
#  The input files get stripped of the ".unlang" suffix, and get the
#  test directory added as a prefix.
#
$(MODULE_TEST).test: $(addprefix $(TEST_DIR)/,$(patsubst %.unlang,%,$(MODULE_FILES)))

.PHONY: clean.$(MODULE_TEST).test
clean.$(MODULE_TEST).test:
	@rm -rf $(TEST_DIR)/
