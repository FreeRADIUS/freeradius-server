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

$(BUILD_DIR)/tests/trie/trie-%: $(DIR)/% $(TEST_BIN_DIR)/trie | $(BUILD_DIR)/tests/trie
	$(eval CMD := $(TEST_BIN)/trie $^)
	@echo TRIE-TEST $(notdir $@)
	@printf '%s\n' '$(CMD)' > $@.cmd
	@if $(CMD) > $@ 2> $@.log; then \
		$(call test_record,trie,$(notdir $@),PASS,$@.log); \
	else \
		cat $@.log; \
		rm -f $@; \
		$(call test_record,trie,$(notdir $@),FAIL,$@.log); \
		exit 1; \
	fi

$(BUILD_DIR)/tests/trie/nopc-%: $(DIR)/% $(TEST_BIN_DIR)/nopc | $(BUILD_DIR)/tests/trie
	$(eval CMD := $(TEST_BIN)/nopc $^)
	@echo TRIE-NO-PC-TEST $(notdir $@)
	@printf '%s\n' '$(CMD)' > $@.cmd
	@if $(CMD) > $@ 2> $@.log; then \
		$(call test_record,trie,$(notdir $@),PASS,$@.log); \
	else \
		cat $@.log; \
		rm -f $@; \
		$(call test_record,trie,$(notdir $@),FAIL,$@.log); \
		exit 1; \
	fi

#
#  Get all of the unit test output files
#
TEST.TRIE_FILES := $(addprefix $(BUILD_DIR)/tests/trie/trie-,$(TRIE_FILES))
#TEST.TRIE_FILES += $(addprefix $(BUILD_DIR)/tests/trie/nopc-,$(TRIE_FILES))

#
#  Depend on the output files, and create the directory first.
#
test.trie: $(TEST.TRIE_FILES)

$(TEST.TRIE_FILES): $(TEST.UNIT_FILES)

.PHONY: clean.test.trie
clean.test.trie:
	${Q}rm -rf $(BUILD_DIR)/tests/trie/

clean.test: clean.test.trie
