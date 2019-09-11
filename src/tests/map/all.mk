#
#  Unit tests for individual pieces of functionality.
#

#
#  Test name
#
TEST := test.map

#
#  The files are put here in order.  Later tests need
#  functionality from earlier test.
#
FILES  := \
	base \
	count-error \
	count-list-error

OUTPUT := $(subst $(top_srcdir)/src,$(BUILD_DIR),$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

#
#  Create the output directory
#
.PHONY: $(OUTPUT)
$(OUTPUT):
	${Q}mkdir -p $@

#
#  All of the output files depend on the input files
#
FILES.$(TEST) := $(addprefix $(OUTPUT),$(notdir $(FILES)))

#
#  The output files also depend on the directory
#  and on the previous test.
#
$(FILES.$(TEST)): | $(OUTPUT)

#
#  We have a real file that's created if all of the tests pass.
#
$(BUILD_DIR)/tests/$(TEST): $(FILES.$(TEST))
	${Q}touch $@

#
#  For simplicity, we create a phony target so that the poor developer
#  doesn't need to remember path names
#
$(TEST): $(BUILD_DIR)/tests/$(TEST)

#
#  Clean the ouput directory and files.
#
#  Note that we have to specify the actual filenames here, because
#  of stupidities with GNU Make.
#
.PHONY: clean.$(TEST)
clean.$(TEST):
	${Q}rm -rf $(BUILD_DIR)/tests/unit $(BUILD_DIR)/tests/test.unit

clean.test: clean.$(TEST)

MAP_UNIT := $(TESTBINDIR)/unit_test_map

#
#	Re-run the tests if the input file changes
#
$(BUILD_DIR)/tests/map/%: $(DIR)/% $(TESTBINDIR)/unit_test_map
	${Q}echo MAP_TEST $(notdir $<)
	${Q}if ! $(MAP_UNIT) -d $(top_srcdir)/raddb -D $(top_srcdir)/share/dictionary -r "$@" "$<" > "$@.log" 2>&1 || ! test -f "$@"; then \
		if ! grep ERROR $< 2>&1 > /dev/null; then \
			cat "$@.log"; \
			echo "# $@"; \
			echo FAILED: "$(MAP_UNIT) -d $(top_srcdir)/raddb -D $(top_srcdir)/share/dictionary -r \"$@\" \"$<\""; \
			exit 1; \
		fi; \
		FOUND=$$(grep -E '^(Error : )?$<' $@.log | head -1 | sed 's/.*\[//;s/\].*//'); \
		EXPECTED=$$(grep -n ERROR $< | sed 's/:.*//'); \
		if [ "$$EXPECTED" != "$$FOUND" ]; then \
			cat "$@.log"; \
			echo "# $@"; \
			echo "E $$EXPECTED F $$FOUND"; \
			echo "UNEXPECTED ERROR: $(MAP_UNIT) -d $(top_srcdir)/raddb -D $(top_srcdir)/share/dictionary -r \"$@\" \"$<\""; \
			exit 1; \
		else \
			touch "$@"; \
		fi \
	else \
		if ! diff "$<.log" "$@.log"; then \
			echo "FAILED: diff \"$<.log\" \"$@.log\""; \
			echo "FAILED: $(MAP_UNIT) -d $(top_srcdir)/raddb -D $(top_srcdir)/share/dictionary -r \"$@\" \"$<\""; \
			exit 1; \
		fi; \
	fi
