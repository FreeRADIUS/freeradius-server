$(BUILD_DIR)/bin/test_cursor: src/lib/util/cursor.c
	${Q}$(CC) $^ -g3 -Wall -DTESTING_CURSOR $(CPPFLAGS) -I${top_srcdir}/src/lib -I${top_srcdir}/src -include src/include/build.h $(TALLOC_LDFLAGS) $(TALLOC_LIBS) -o $@

OUTPUT := $(BUILD_DIR)/tests/misc

.PHONY: $(OUTPUT)
$(OUTPUT):
	@${Q}mkdir -p $@

$(OUTPUT)/cursor.log: $(BUILD_DIR)/bin/test_cursor | $(OUTPUT)
	${Q}if ! $^ > $@ ; then \
		echo FAILED "$^ > $@"; \
	fi

test.misc: $(OUTPUT)/cursor.log

