#
#	Unit tests for misc tests
#

#
#	Test name
#
TEST := test.misc

$(eval $(call TEST_BOOTSTRAP))

$(BUILD_DIR)/bin/test_cursor: src/lib/util/cursor.c
	${Q}$(CC) $^ -g3 -Wall -DTESTING_CURSOR $(CPPFLAGS) -I${top_srcdir}/src/lib -I${top_srcdir}/src -include src/include/build.h $(TALLOC_LDFLAGS) $(TALLOC_LIBS) -o $@

$(OUTPUT)/cursor.log: $(BUILD_DIR)/bin/test_cursor | $(OUTPUT)
	@echo "MISC-TEST cursor"
	${Q}if ! $^ > $@ ; then \
		echo FAILED "$^ > $@"; \
	fi

$(TEST): $(OUTPUT)/cursor.log
