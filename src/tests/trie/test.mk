#
#  Get the test files.
#
TRIE_FILES := $(subst $(DIR)/,,$(wildcard $(DIR)/*.txt))

#
#  Create the output directory
#
.PHONY: $(BUILD_DIR)/tests/trie
$(BUILD_DIR)/tests/trie:
	${Q}mkdir -p $@

$(BUILD_DIR)/tests/trie/trie-%: $(DIR)/% $(TESTBINDIR)/trie | $(BUILD_DIR)/tests/trie
	@echo TRIE-TEST $(dir $@)
	@$(TESTBINDIR)/trie $^ > $@

$(BUILD_DIR)/tests/trie/nopc-%: $(DIR)/% $(TESTBINDIR)/nopc | $(BUILD_DIR)/tests/trie
	@echo TRIE-NO-PC-TEST $(dir $@)
	@$(TESTBINDIR)/nopc $^ > $@

#
#  Get all of the unit test output files
#
TESTS.TRIE_FILES := $(addprefix $(BUILD_DIR)/tests/trie/trie-,$(TRIE_FILES))
#TESTS.TRIE_FILES += $(addprefix $(BUILD_DIR)/tests/trie/nopc-,$(TRIE_FILES))

#
#  Depend on the output files, and create the directory first.
#
tests.trie: $(TESTS.TRIE_FILES)

$(TESTS.TRIE_FILES): $(TESTS.UNIT_FILES)

.PHONY: clean.tests.trie
clean.tests.trie:
	${Q}rm -rf $(BUILD_DIR)/tests/trie/
