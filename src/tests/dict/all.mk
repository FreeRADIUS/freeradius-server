#
#  Test name
#
TEST := test.dict

#
#  Input files.
#
FILES := $(subst $(DIR)/,,$(wildcard $(DIR)/*.dict) $(wildcard $(DIR)/*.error))

$(eval $(call TEST_BOOTSTRAP))

#
#
DICT_CMD = \
	$(TEST_BIN)/unit_test_attribute \
	-D $(top_srcdir)/share/dictionary \
	-o $(call SHELL_QUOTE,$@) \
	$(call SHELL_QUOTE,$@.txt)

#  And the actual script to run each test.
#
#  The parser expects to read "foo/dictionary", so we make a
#  "foo_dir" directory, and copy "foo" into "foo_dir/dictionary"
#
$(OUTPUT)/%.dict: $(DIR)/%.dict $(TEST_BIN_DIR)/unit_test_attribute
	@echo "DICT-TEST $(notdir $@)"
	@cp $< $@
	@cp src/tests/dict/base.txt $@.txt
	@echo "load-dictionary $(top_srcdir)/$<" >> $@.txt
	${Q}if ! $(DICT_CMD) > "$@.log" 2>&1 || ! test -f "$@"; then \
		rm -f $@; \
		cat "$@.log"; \
		echo "# $@.log"; \
		echo $(call SHELL_QUOTE,$(DICT_CMD)); \
		exit 1; \
	fi

DICT_ERROR_CMD = \
	$(TEST_BIN)/unit_test_attribute \
	-D $(top_srcdir)/share/dictionary \
	$(call SHELL_QUOTE,$@.txt)

#
#  Tests which are supposed to fail.
#
#  Run the test.  If it passes, that's a problem.
#
#  Fix the output to remove the full pathname.
#
#  See if the current output and the expected output are the same.
#
$(OUTPUT)/%.error: $(DIR)/%.error $(TEST_BIN_DIR)/unit_test_attribute
	@echo "DICT-TEST $(notdir $@)"
	@cp $< $@
	@cp src/tests/dict/base.txt $@.txt
	@echo "load-dictionary $(top_srcdir)/$<" >> $@.txt
	${Q}if $(DICT_ERROR_CMD) > "$@.log" 2>&1 ; then \
		rm -f $@; \
		cat "$@.log"; \
		echo "# $@.log"; \
		echo $(call SHELL_QUOTE,$(DICT_ERROR_CMD)); \
		exit 1; \
	fi
	${Q}sed 's,${top_srcdir}/,,g' < "$@.log" > "$@.out"
	${Q}if ! diff "$@.out" "$(subst .error,,$<).out" ; then \
		rm -f $@; \
		echo "diff $@.out $(subst .error,,$<).out"; \
		echo $(call SHELL_QUOTE,$(DICT_ERROR_CMD)); \
		echo "FAILED"; \
		exit 1; \
	fi
