#
#  Unit tests for process state machines
#


#
#  Test name
#
TEST := test.process

#
#  The test files are files without extensions.
#  The list is unordered.  The order is added in the next step by looking
#  at precursors.
#
#  * search ALL_TGTS
#  * for process_foo targets
#  * strip add "process_" prefix
#  * strip off ".whatever" suffix
#  * add directory name and wildcard file
#  * use wildcard to find existing files
#  * strip off directory name
#  * filter out files we don't care about
#
#  We're left with a set of files to run the tests on.
#
FILES := $(filter-out %.ignore %.conf %.md %.attrs %.mk %~ %.rej,$(subst $(DIR)/,,$(wildcard $(patsubst %,$(DIR)/%/*,$(basename $(subst process_,,$(filter process%,$(ALL_TGTS))))))))

$(eval $(call TEST_BOOTSTRAP))

# -S use_new_conditions=yes -S forbid_update=yes

#
#  The dictionaries are in "share", because the server tries to load
#  local dictionaries from "./dictionary".
#
src/tests/process/share/%: ${top_srcdir}/share/dictionary/%
	@ln -sf $< $@

ifneq "$(OPENSSL_LIBS)" ""
PROCESS_DICT_TLS := $(DIR)/share/tls
endif

#
#  For sheer laziness, allow "make test.process.foo"
#
define PROCESS_TEST
test.process.${1}: $(addprefix $(OUTPUT)/,${1})

test.process.help: TEST_PROCESS_HELP += test.process.${1}

#
#  The output depends on the process_foo state machine,
#  and on the "test" process state machine.
#
#  With filenames added for the output files
#
$(OUTPUT)/${1}: $(patsubst %,${BUILD_DIR}/lib/local/process_%.la,$(subst /,,$(dir ${1})) test)

$(OUTPUT)/${1}: $(DIR)/$(subst /,,$(dir ${1}))/server.conf

$(OUTPUT)/${1}: | $(DIR)/share/$(subst /,,$(dir ${1})) $(DIR)/share/freeradius $(PROCESS_DICT_TLS)
endef
$(foreach x,$(FILES),$(eval $(call PROCESS_TEST,$x)))

#
#  Files in the output dir depend on the unit tests
#
#	src/tests/process/radius/FOO		unlang for the test
#	build/tests/process/radius/FOO		updated if the test succeeds
#	build/tests/process/radius/FOO.log	debug output for the test
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
#	(make -k test.process 2>&1) | grep 'PROCESS=' | sed 's/PROCESS=//;s/ .*$//'
#
PROCESS_ARGS := -p test
PROCESS_ARGS += -D $(DIR)/share -d $(DIR)/
PROCESS_ARGS += -S use_new_conditions=yes -S forbid_update=yes
PROCESS_ARGS += -i $(DIR)/test.attrs -f $(DIR)/test.attrs

$(OUTPUT)/%: $(DIR)/% $(TEST_BIN_DIR)/unit_test_module $(DIR)/unit_test_module.conf
	$(eval CMD:=PROCESS=$< PROTOCOL=$(dir $<) $(TEST_BIN)/unit_test_module $(PROCESS_ARGS) -r "$@" -xx)
	@echo PROCESS-TEST $(notdir $@)
	@mkdir -p $(dir $@)
	@if ! $(CMD) > "$@.log" 2>&1 || ! test -f "$@"; then \
		cat $@.log; \
		echo "# $@.log"; \
		echo $(CMD); \
		exit 1; \
	fi

$(TEST):
	@touch $(BUILD_DIR)/tests/$@

$(TEST).help:
	@echo make $(TEST_PROCESS_HELP)
