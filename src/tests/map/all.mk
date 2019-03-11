MAP_TESTS	:= $(patsubst $(top_srcdir)/src/tests/map/%,%,$(filter-log %.conf %.md %.attrs %.c %.mk %~ %.rej %.log,$(wildcard $(top_srcdir)/src/tests/map/*)))
MAP_OUTPUT	:= $(addsuffix .log,$(addprefix $(BUILD_DIR)/tests/map/,$(MAP_TESTS)))
MAP_UNIT_BIN	:= $(BUILD_DIR)/bin/local/unit_test_map
MAP_UNIT	:= ./build/make/jlibtool --silent --mode=execute $(MAP_UNIT_BIN)

.PHONY: $(BUILD_DIR)/tests/map/
$(BUILD_DIR)/tests/map/:
	${Q}mkdir -p $@

#
#	Re-run the tests if the test program changes
#
#	Create the logput directory before the files
#
$(MAP_OUTPUT): $(MAP_UNIT_BIN) | $(BUILD_DIR)/tests/map/

#
#	Re-run the tests if the input file changes
#
$(BUILD_DIR)/tests/map/%: $(top_srcdir)/src/tests/map/%
	${Q}echo MAP_TEST $(notdir $<)
	${Q}if ! $(MAP_UNIT) -d $(top_srcdir)/raddb -D $(top_srcdir)/share/dictionary -r "$@" $< > "$@.log" 2>&1 || ! test -f "$@"; then \
		if ! grep ERROR $< 2>&1 > /dev/null; then \
			cat $@; \
			echo "# $@"; \
			echo FAILED: "$(MAP_UNIT) -d $(top_srcdir)/raddb -D $(top_srcdir)/share/dictionary -r \"$@\" $<"; \
			exit 1; \
		fi; \
		FOUND=$$(grep $< $@ | head -1 | sed 's,^.*$(top_srcdir),,;s/:.*//;s/.*\[//;s/\].*//'); \
		EXPECTED=$$(grep -n ERROR $< | sed 's/:.*//'); \
		if [ "$$EXPECTED" != "$$FOUND" ]; then \
			cat $@; \
			echo "# $@"; \
			echo "E $$EXPECTED F $$FOUND"; \
			echo UNEXPECTED ERROR: "$(MAP_UNIT) -d $(top_srcdir)/raddb -D $(top_srcdir)/share/dictionary -r \"$@\" $<"; \
			exit 1; \
		fi; \
	else \
		if ! diff $<.log $@; then \
			echo FAILED: " diff $<.log $@"; \
			echo FAILED: "$(MAP_UNIT) -d $(top_srcdir)/raddb -D $(top_srcdir)/share/dictionary -r \"$@\" $<"; \
			exit 1; \
		fi; \
	fi

TESTS.MAP_FILES := $(MAP_OUTPUT)

$(TESTS.MAP_FILES): $(TESTS.UNIT_FILES)

tests.map: $(MAP_OUTPUT)

.PHONY: clean.tests.map
clean.tests.map:
	${Q}rm -rf $(BUILD_DIR)/tests/map/

