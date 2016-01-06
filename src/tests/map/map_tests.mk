MAP_TESTS	:= $(patsubst $(top_srcdir)/src/tests/map/%,%,$(filter-out %.conf %.md %.attrs %.c %.mk %~ %.rej %.out,$(wildcard $(top_srcdir)/src/tests/map/*)))
MAP_OUTPUT	:= $(addsuffix .out,$(addprefix $(BUILD_DIR)/tests/map/,$(MAP_TESTS)))
MAP_UNIT_BIN	:= $(BUILD_DIR)/bin/local/map_unit
MAP_UNIT	:= ./build/make/jlibtool --silent --mode=execute $(MAP_UNIT_BIN)

.PHONY: $(BUILD_DIR)/tests/map/
$(BUILD_DIR)/tests/map/:
	@mkdir -p $@

#
#	Re-run the tests if the test program changes
#
#	Create the output directory before the files
#
$(MAP_OUTPUT): $(MAP_UNIT_BIN) | $(BUILD_DIR)/tests/map/

#
#	Re-run the tests if the input file changes
#
$(BUILD_DIR)/tests/map/%.out: $(top_srcdir)/src/tests/map/%
	@echo MAP_TEST $(notdir $<)
	@if ! $(MAP_UNIT) -d $(top_srcdir)/raddb -D $(top_srcdir)/share $< > $@ 2>&1; then \
		if ! grep ERROR $< 2>&1 > /dev/null; then \
			cat $@; \
			echo "# $@"; \
			echo FAILED: "$(MAP_UNIT) -d $(top_srcdir)/raddb -D $(top_srcdir)/share $<"; \
			exit 1; \
		fi; \
		FOUND=$$(grep $< $@ | head -1 | sed 's,^.*$(top_srcdir),,;s/:.*//;s/.*\[//;s/\].*//'); \
		EXPECTED=$$(grep -n ERROR $< | sed 's/:.*//'); \
		if [ "$$EXPECTED" != "$$FOUND" ]; then \
			cat $@; \
			echo "# $@"; \
			echo "E $$EXPECTED F $$FOUND"; \
			echo UNEXPECTED ERROR: "$(MAP_UNIT) -d $(top_srcdir)/raddb -D $(top_srcdir)/share $<"; \
			exit 1; \
		fi; \
	else \
		if ! diff $<.out $@; then \
			echo FAILED: " diff $<.out $@"; \
			echo FAILED: "$(MAP_UNIT) -d $(top_srcdir)/raddb -D $(top_srcdir)/share $<"; \
			exit 1; \
		fi; \
	fi

TESTS.MAP_FILES := $(MAP_OUTPUT)

$(TESTS.MAP_FILES): $(TESTS.UNIT_FILES)

tests.map: $(MAP_OUTPUT)
