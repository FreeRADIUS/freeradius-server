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

$(eval $(call TEST_BOOTSTRAP))

MAP_UNIT := $(TESTBINDIR)/unit_test_map

#
#	Re-run the tests if the input file changes
#
$(OUTPUT)/%: $(DIR)/% $(TESTBINDIR)/unit_test_map
	${Q}echo MAP-TEST $(notdir $<)
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
