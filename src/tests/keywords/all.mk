#
#  Unit tests for unlang keywords
#

#
#  The files are put here in order.  Later tests need
#  functionality from earlier tests.
#
FILES := update foreach foreach-2 if if-skip if-bob if-else redundant switch switch-default

#
#  Create the output directory
#
.PHONY: $(BUILD_DIR)/tests/keywords
$(BUILD_DIR)/tests/keywords:
	@mkdir -p $@

#
#  Find which input files are needed by the tests
#  strip out the ones which exist
#  move the filenames to the build directory.
#
BOOTSTRAP_EXISTS := $(addprefix $(DIR)/,$(addsuffix .attrs,$(FILES)))
BOOTSTRAP_NEEDS	 := $(filter-out $(wildcard $(BOOTSTRAP_EXISTS)),$(BOOTSTRAP_EXISTS))
BOOTSTRAP	 := $(subst $(DIR),$(BUILD_DIR)/tests/keywords,$(BOOTSTRAP_NEEDS))

BOOTSTRAP_HAS	 := $(filter $(wildcard $(BOOTSTRAP_EXISTS)),$(BOOTSTRAP_EXISTS))
BOOTSTRAP_COPY	 := $(subst $(DIR),$(BUILD_DIR)/tests/keywords,$(BOOTSTRAP_NEEDS))

#
#  These ones get copied over from the default input
#
$(BOOTSTRAP): $(DIR)/default-input.attrs | $(BUILD_DIR)/tests/keywords
	@cp $< $@

#
#  These ones get copied over from their original files
#
$(BUILD_DIR)/tests/keywords/%.attrs: $(DIR)/%.attrs | $(BUILD_DIR)/tests/keywords
	@cp $< $@

#
#  Don't auto-remove the files copied by the rule just above.
#  It's unnecessary, and it clutters the output with crap.
#
.PRECIOUS: $(BUILD_DIR)/tests/keywords/%.attrs

#
#  Files in the output dir depend on the unit tests
#
#	src/tests/keywords/FOO		unlang for the test
#	src/tests/keywords/FOO.attrs	input RADIUS and output filter
#	build/tests/keywords/FOO	updated if the test succeeds
#	build/tests/keywords/FOO.log	debug output for the test
#
$(BUILD_DIR)/tests/keywords/%: $(DIR)/% $(BUILD_DIR)/tests/keywords/%.attrs $(BUILD_DIR)/bin/unittest | $(BUILD_DIR)/tests/keywords raddb/mods-enabled/pap raddb/mods-enabled/always
	@echo UNIT-TEST $(notdir $@)
	@KEYWORD=$(notdir $@) $(JLIBTOOL) --quiet --mode=execute ./$(BUILD_DIR)/bin/unittest -D share -d src/tests/keywords/ -i $@.attrs -f $@.attrs -xx > $@.log 2>&1
	@touch $@


#
#  Get all of the unit test output files
#
TESTS.KEYWORDS_FILES := $(addprefix $(BUILD_DIR)/tests/keywords/,$(FILES))

#
#  Depend on the output files, and create the directory first.
#
tests.keywords: $(TESTS.KEYWORDS_FILES)

#
#  And be a BASTARD about it.  If the unit tests fail,
#  then we can't run radiusd.
#
$(BUILD_DIR)/bin/radiusd: $(TESTS.KEYWORDS_FILES)

.PHONY: clean.tests.keywords
clean.tests.keywords:
	@rm -rf $(BUILD_DIR)/tests/keywords/
