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
FILES := $(filter-out %.ignore %.conf %.md %.attrs %.servers %.mk %~ %.rej,$(subst $(DIR)/,,$(wildcard $(DIR)/*)))

#
#  Don't run SSHA tests if there's no SSL
#
ifeq "$(OPENSSL_LIBS)" ""
FILES := $(filter-out pap-ssha2 sha2,$(FILES))
endif

#
#  Some tests require PCRE2
#
ifeq "$(AC_HAVE_REGEX_PCRE2)" ""
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

ifeq "${1}" "mschap"
$(OUTPUT)/${1}: $(BUILD_DIR)/lib/local/rlm_mschap.la $(BUILD_DIR)/lib/rlm_mschap.la
endif

ifeq "${1}" "kv"
$(OUTPUT)/${1}: $(BUILD_DIR)/lib/local/rlm_kv.la $(BUILD_DIR)/lib/rlm_kv.la
endif

ifeq "${1}" "xlat-dhcpv4"
$(OUTPUT)/${1}: $(BUILD_DIR)/lib/local/libfreeradius-dhcpv4.la $(BUILD_DIR)/lib/libfreeradius-dhcpv4.la
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
		out=`echo $$x | sed 's,src/,$(BUILD_DIR)/',`; \
		if [ "$$y" != "" ]; then \
			echo "$$out: $$y" >> $@; \
			echo "" >> $@; \
		fi; \
		y=`grep 'PROTOCOL: ' $$x | sed 's/^.*: //'`; \
		if [ "$$y" != "" ]; then \
			z=`echo $$x | sed 's,src/tests/keywords/,,;s/-/_/g'`; \
			echo "UNIT_TEST_KEYWORD_ARGS.$$z=-p $$y" >> $@; \
			echo "" >> $@; \
			echo "$$out: src/tests/keywords/$$y.conf" >> $@; \
		else \
			echo "$$out: src/tests/keywords/radius.conf" >> $@; \
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
	$(eval CMD:=KEYWORD=$(notdir $@) $(TEST_BIN)/unit_test_module $(UNIT_TEST_KEYWORD_ARGS.$(subst -,_,$(notdir $@))) -D share/dictionary -d src/tests/keywords/ -i "$@.attrs" -f "$@.attrs" -r "$@" -xx )
	@echo "KEYWORD-TEST $(notdir $@)"
	${Q}if ! $(CMD) > "$@.log" 2>&1 || ! test -f "$@"; then \
		if ! grep ERROR $< 2>&1 > /dev/null; then \
			cat $@.log; \
			echo "# $@.log"; \
			echo $(CMD); \
			rm -f $(BUILD_DIR)/tests/test.keywords; \
			exit 1; \
		fi; \
		FOUND=$$(grep 'Error : src/tests/keywords/' $@.log | egrep -v -- '-->' | head -1 | sed 's/]:.*//;s/.*\[//;s/\].*//'); \
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
