#
#  Test name
#
TEST := test.dict

#
#  Input files.
#
FILES := $(subst $(DIR)/,,$(wildcard $(DIR)/*.dict) $(wildcard $(DIR)/*.error))

$(eval $(call TEST_BOOTSTRAP))

#  And the actual script to run each test.
#
#  The parser expects to read "foo/dictionary", so we make a
#  "foo_dir" directory, and copy "foo" into "foo_dir/dictionary"
#
$(OUTPUT)/%.dict: $(DIR)/%.dict $(TEST_BIN_DIR)/unit_test_attribute
	$(eval CMD := $(TEST_BIN)/unit_test_attribute -D $(top_srcdir)/share/dictionary -o "$@" "$@.txt")
	@echo "DICT-TEST $(notdir $@)"
	@cp $< $@
	@cp src/tests/dict/base.txt $@.txt
	@echo "load-dictionary $(top_srcdir)/$<" >> $@.txt
	@printf '%s\n' '$(CMD)' > $@.cmd
	${Q}if ! $(CMD) > "$@.log" 2>&1 || ! test -f "$@"; then \
		rm -f $@; \
		cat "$@.log"; \
		echo "# $@.log"; \
		$(call test_record,dict,$(notdir $@),FAIL,$@.log); \
		exit 1; \
	fi
	@$(call test_record,dict,$(notdir $@),PASS,$@.log)

#  And the actual script to run each test.
#
#  The parser expects to read "foo/dictionary", so we make a
#  "foo_dir" directory, and copy "foo" into "foo_dir/dictionary"
#
$(OUTPUT)/%.dict: $(DIR)/%.dict $(TEST_BIN_DIR)/unit_test_attribute
	$(eval CMD := $(TEST_BIN)/unit_test_attribute -D $(top_srcdir)/share/dictionary -o "$@" "$@.txt")
	@echo "DICT-TEST $(notdir $@)"
	@cp $< $@
	@cp src/tests/dict/base.txt $@.txt
	@echo "load-dictionary $(top_srcdir)/$<" >> $@.txt
	@printf '%s\n' '$(CMD)' > $@.cmd
	${Q}if ! $(CMD) > "$@.log" 2>&1 || ! test -f "$@"; then \
		rm -f $@; \
		cat "$@.log"; \
		echo "# $@.log"; \
		$(call test_record,dict,$(notdir $@),FAIL,$@.log); \
		exit 1; \
	fi
	@$(call test_record,dict,$(notdir $@),PASS,$@.log)

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
	$(eval CMD := $(TEST_BIN)/unit_test_attribute -D $(top_srcdir)/share/dictionary "$@.txt")
	@echo "DICT-TEST $(notdir $@)"
	@cp $< $@
	@cp src/tests/dict/base.txt $@.txt
	@echo "load-dictionary $(top_srcdir)/$<" >> $@.txt
	@printf '%s\n' '$(CMD)' > $@.cmd
	${Q}if $(CMD) > "$@.log" 2>&1 ; then \
		rm -f $@; \
		cat "$@.log"; \
		echo "# $@.log"; \
		$(call test_record,dict,$(notdir $@),FAIL,$@.log); \
		exit 1; \
	fi
	${Q}sed 's,${top_srcdir}/,,g' < "$@.log" > "$@.out"
	${Q}if ! diff "$@.out" "$(subst .error,,$<).out" ; then \
		echo "diff $@.out $(subst .error,,$<).out"; \
		echo "FAILED"; \
	fi
	@$(call test_record,dict,$(notdir $@),PASS,$@.log)
