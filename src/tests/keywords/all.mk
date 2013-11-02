#
#  Unit tests for unlang keywords
#

#
#  The files are put here in order.  Later tests need
#  functionality from earlier tests.
#
FILES := update foreach foreach-2 if if-skip

#
#  Create the output directory
#
.PHONY: $(BUILD_DIR)/tests/keywords
$(BUILD_DIR)/tests/keywords:
	@mkdir -p $@

#
#  Files in the output dir depend on the unit tests
#
#	src/tests/keywords/FOO		unlang for the test
#	src/tests/keywords/FOO.txt	input RADIUS and output filter
#	build/tests/keywords/FOO	updated if the test succeeds
#	build/tests/keywords/FOO.log	debug output for the test
#
$(BUILD_DIR)/tests/keywords/%: $(DIR)/% $(DIR)/%.txt ./$(BUILD_DIR)/bin/unittest | $(BUILD_DIR)/tests/keywords
	@echo UNIT-TEST $(notdir $@)
	KEYWORD=$(notdir $@) $(JLIBTOOL) --quiet --mode=execute ./$(BUILD_DIR)/bin/unittest -D share -d src/tests/keywords/ -i $<.txt -f $<.txt -xx
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
	@rm -f $(TESTS.KEYWORDS_FILES)
