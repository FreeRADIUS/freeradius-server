#
#  Unit tests for individual pieces of functionality.
#

#
#  Test name
#
TEST := test.unit

#
#  The files are put here in order.  Later tests need
#  functionality from earlier test.
#
FILES  := $(subst $(DIR)/,,$(call FIND_FILES_SUFFIX,$(DIR),*.txt))

# dict.txt - removed because the unit tests don't allow for protocol namespaces

# command.txt - removed because commands like ":sql" are not parsed properly any more

$(eval $(call TEST_BOOTSTRAP))

#
#  We use GMT for the tests, so that local time zones don't affect
#  the test outputs.
#
$(FILES.$(TEST)): export TZ = GMT

#export ASAN_SYMBOLIZER_PATH=$(shell which llvm-symbolizer)
#export ASAN_OPTIONS=malloc_context_size=50 detect_leaks=1 symbolize=1
#export LSAN_OPTIONS=print_suppressions=0 fast_unwind_on_malloc=0

#
#  And the actual script to run each test.
#
$(OUTPUT)/%: $(DIR)/% $(TESTBINDIR)/unit_test_attribute
	$(eval DIR:=${top_srcdir}/src/tests/unit)
	@echo "UNIT-TEST $(lastword $(subst /, ,$(dir $@))) $(basename $(notdir $@))"
	${Q}if ! $(TESTBIN)/unit_test_attribute -D $(top_srcdir)/share/dictionary -d $(DIR) -r "$@" $<; then \
		echo "$(TESTBIN)/unit_test_attribute -D $(top_srcdir)/share/dictionary -d $(DIR) -r \"$@\" $<"; \
		rm -f $(BUILD_DIR)/tests/test.unit; \
		exit 1; \
	fi
