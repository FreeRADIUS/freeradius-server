#
#  Unit tests for individual pieces of functionality.
#

#
#  Test name
#
TEST := test.unit

#
#  Base directory for the test files
#
TEST_FILES_DIR := $(top_srcdir)/src/tests/unit

#
#  The files are put here in order.  Later tests need
#  functionality from earlier test.
#
FILES  := $(subst $(TEST_FILES_DIR)/,,$(call FIND_FILES_SUFFIX,$(TEST_FILES_DIR),*.txt))

# dict.txt - removed because the unit tests don't allow for protocol namespaces

# command.txt - removed because commands like ":sql" are not parsed properly any more

$(eval $(call TEST_BOOTSTRAP))

#
#  We use GMT for the tests, so that local time zones don't affect
#  the test outputs.
#
$(FILES.$(TEST)): export TZ = GMT

#
#  And the actual script to run each test.
#
$(OUTPUT)/%: $(DIR)/% $(TESTBINDIR)/unit_test_attribute
	${Q}echo UNIT-TEST $(subst $(TEST_FILES_DIR)/,,$<)
	${Q}if ! $(TESTBIN)/unit_test_attribute -D $(top_srcdir)/share/dictionary -d $(top_srcdir)/src/tests/unit -r "$@" $<; then \
		echo "$(TESTBIN)/unit_test_attribute -D $(top_srcdir)/share/dictionary -d $(top_srcdir)/src/tests/unit -r \"$@\" $<"; \
		rm -f $(BUILD_DIR)/tests/test.unit; \
		exit 1; \
	fi
