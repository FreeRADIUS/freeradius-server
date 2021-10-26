.PHONY: logid.help
logid.help:
	@echo ""
	@echo "Make targets:"
	@echo "    logid.check              - check and verify log IDs"
	@echo "    logid.update             - update log IDs"

LOGID_FILES := $(shell grep -l LOG_ID ${ALL_MAKEFILES})

logid.check: $(LOGID_FILES)
	@./scripts/build/logid-check.pl $^

logid.update: $(shell find src -name "*.c" -print)
	@./scripts/build/logid-update.pl $^
