$(BUILD_DIR)/bin/test_cursor: src/lib/util/cursor.c
	${Q}$(CC) $^ -g3 -Wall -DTESTING_CURSOR -Isrc/ -Isrc/lib/ -include src/include/build.h -l talloc -o $@

OUTPUT := $(BUILD_DIR)/tests/misc

.PHONY: $(OUTPUT)
$(OUTPUT):
	@${Q}mkdir -p $@

$(OUTPUT)/cursor.log: $(BUILD_DIR)/bin/test_cursor | $(OUTPUT)
	${Q}if ! $^ > $@ ; then \
		echo FAILED "$^ > $@"; \
	fi

test.misc: $(OUTPUT)/cursor.log

