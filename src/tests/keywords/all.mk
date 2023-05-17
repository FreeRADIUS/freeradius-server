#
#  Unit tests for unlang keywords
#


#
#  Test name
#
TEST := test.keywords

#
#  The test files are files without extensions.
#  The list is unordered.  The order is added in the next step by looking
#  at precursors.
#
FILES := $(filter-out %.ignore %.conf %.md %.attrs %.mk %~ %.rej,$(subst $(DIR)/,,$(wildcard $(DIR)/*)))

#
#  Don't run SSHA tests if there's no SSL
#
ifeq "$(OPENSSL_LIBS)" ""
FILES := $(filter-out pap-ssha2 sha2,$(FILES))
endif

#
#  Some tests require PCRE or PCRE2
#
ifeq "$(AC_HAVE_REGEX_PCRE)$(AC_HAVE_REGEX_PCRE2)" ""
FILES := $(filter-out if-regex-match-named,$(FILES))
endif

$(eval $(call TEST_BOOTSTRAP))

#
#  For sheer laziness, allow "make test.keywords.foo"
#
define KEYWORD_TEST
test.keywords.${1}: $(addprefix $(OUTPUT)/,${1})

test.keywords.help: TEST_KEYWORDS_HELP += test.keywords.${1}

#
#  Create the input attrs, either from the test-specific input,
#  or from the default input.
#
$(OUTPUT)/${1}: $(OUTPUT)/${1}.attrs | $(dir $(OUTPUT)/${1})
$(OUTPUT)/${1}.attrs: | $(dir $(OUTPUT)/${1})

ifneq "$(wildcard src/tests/keywords/${1}.attrs)" ""
$(OUTPUT)/${1}.attrs: src/tests/keywords/${1}.attrs
else
$(OUTPUT)/${1}.attrs: src/tests/keywords/default-input.attrs
endif
	@cp $$< $$@

#
#  All of the "update" tests which should also be run with "-S rewrite_update=yes"
#
#  update-attr-ref-null		&foo := &bar, where bar doesn't exist.  Now does nothing
#  update-error-3		is now a run-time error instead of parse error
#  update-group-error		error is on a different line
#  update-null-value-assign	foo := "%{...}" should be an empty string
#  update-remove-index		used to do???, now is parse-time error
#  update-filter		lots of errors
#
KEYWORD_UPDATE_TESTS := update-attr-ref-null update-error-3 update-group-error update-null-value-assign update-remove-index update-filter

KEYWORD_UPDATE_REWRITE_TESTS := update-all update-array update-delete update-remove-any update-group update-hex update-remove-value update-index update-list-error update-remove-list update-prepend unknown-update  update-error update-error-2 update-exec-error update-list-null-rhs update-exec

#
#  Migration support.  Some of the tests don't run under the new
#  conditions, so we don't run them under the new conditions.
#
ifneq "$(findstring ${1}, paircmp if-paircmp)" ""
$(OUTPUT)/${1}: NEW_COND=-S use_new_conditions=no
else ifneq "$(findstring ${1}, comments update-to-edit if-regex-multivalue smash wimax unknown $(KEYWORD_UPDATE_TESTS) vendor_specific vendor_specific.raw xlat-unknown update-proto update-proto-error)" ""
$(OUTPUT)/${1}: NEW_COND=-S use_new_conditions=yes
else ifneq "$(findstring ${1}, $(KEYWORD_UPDATE_REWRITE_TESTS))" ""
$(OUTPUT)/${1}: NEW_COND=-S use_new_conditions=yes -S rewrite_update=yes
else
$(OUTPUT)/${1}: NEW_COND=-S use_new_conditions=yes -S forbid_update=yes

ifeq "${1}" "mschap"
$(OUTPUT)/${1}: rlm_mschap.la
endif
endif

endef
$(foreach x,$(FILES),$(eval $(call KEYWORD_TEST,$x)))

#
#  For each file, look for precursor test.
#  Ensure that each test depends on its precursors.
#
-include $(OUTPUT)/depends.mk

export OPENSSL_LIBS

$(OUTPUT)/depends.mk: $(addprefix $(DIR)/,$(sort $(FILES))) | $(OUTPUT)
	${Q}rm -f $@
	${Q}touch $@
	${Q}for x in $^; do \
		y=`grep 'PRE: ' $$x | sed 's/.*://;s/  / /g;s, , $(BUILD_DIR)/tests/keywords/,g'`; \
		if [ "$$y" != "" ]; then \
			z=`echo $$x | sed 's,src/,$(BUILD_DIR)/',`; \
			echo "$$z: $$y" >> $@; \
			echo "" >> $@; \
		fi; \
		y=`grep 'PROTOCOL: ' $$x | sed 's/.*://;s/  / /g'`; \
		if [ "$$y" != "" ]; then \
			z=`echo $$x | sed 's,src/tests/keywords/,,;s/-/_/g'`; \
			echo "UNIT_TEST_KEYWORD_ARGS.$$z=-p $$y" >> $@; \
			echo "" >> $@; \
		fi \
	done

#
#  Cache the list of modules which are enabled, so that we don't run
#  the shell script on every build.
#
#  KEYWORD_MODULES := $(shell grep -- mods-enabled src/tests/keywords/unit_test_module.conf | sed 's,.*/,,')
#
$(OUTPUT)/enabled.mk: src/tests/keywords/unit_test_module.conf | $(OUTPUT)
	${Q}echo "KEYWORD_MODULES := " $$(grep -- mods-enabled src/tests/keywords/unit_test_module.conf | sed 's,.*/,,' | tr '\n' ' ' ) > $@
-include $(OUTPUT)/enabled.mk

KEYWORD_RADDB	:= $(addprefix raddb/mods-enabled/,$(KEYWORD_MODULES))
KEYWORD_LIBS	:= $(addsuffix .la,$(addprefix rlm_,$(KEYWORD_MODULES))) rlm_csv.la

#
#  Files in the output dir depend on the unit tests
#
#	src/tests/keywords/FOO		unlang for the test
#	src/tests/keywords/FOO.attrs	input RADIUS and output filter
#	build/tests/keywords/FOO	updated if the test succeeds
#	build/tests/keywords/FOO.log	debug output for the test
#
#  Auto-depend on modules via $(shell grep INCLUDE $(DIR)/radiusd.conf | grep mods-enabled | sed 's/.*}/raddb/'))
#
#  If the test fails, then look for ERROR in the input.  No error
#  means it's unexpected, so we die.
#
#  Otherwise, check the log file for a parse error which matches the
#  ERROR line in the input.
#
#  NOTE: Grepping for $< is not safe cross platform, as on Linux it
#  expands to the full absolute path, and on macOS it appears to be relative.
#
#  To quickly find all failing tests, run:
#
#	(make -k test.keywords 2>&1) | grep 'KEYWORD=' | sed 's/KEYWORD=//;s/ .*$//'
#
$(OUTPUT)/%: $(DIR)/% $(TEST_BIN_DIR)/unit_test_module | $(KEYWORD_RADDB) $(KEYWORD_LIBS) build.raddb rlm_test.la rlm_csv.la rlm_unpack.la
	$(eval CMD:=KEYWORD=$(notdir $@) $(TEST_BIN)/unit_test_module $(NEW_COND) $(UNIT_TEST_KEYWORD_ARGS.$(subst -,_,$(notdir $@))) -D share/dictionary -d src/tests/keywords/ -i "$@.attrs" -f "$@.attrs" -r "$@" -xx)
	@echo "KEYWORD-TEST $(notdir $@)"
	${Q}if ! $(CMD) > "$@.log" 2>&1 || ! test -f "$@"; then \
		if ! grep ERROR $< 2>&1 > /dev/null; then \
			cat $@.log; \
			echo "# $@.log"; \
			echo $(CMD); \
			rm -f $(BUILD_DIR)/tests/test.keywords; \
			exit 1; \
		fi; \
		FOUND=$$(grep 'Error : src/tests/keywords/' $@.log | head -1 | sed 's/]:.*//;s/.*\[//;s/\].*//'); \
		EXPECTED=$$(grep -n ERROR $< | sed 's/:.*//'); \
		if [ "$$EXPECTED" != "$$FOUND" ]; then \
			cat $@.log; \
			echo "# $@.log"; \
			echo $(CMD); \
			rm -f $(BUILD_DIR)/tests/test.keywords; \
			exit 1; \
		else \
			touch "$@"; \
		fi \
	fi

$(TEST):
	@touch $(BUILD_DIR)/tests/$@

$(TEST).help:
	@echo make $(TEST_KEYWORDS_HELP)
