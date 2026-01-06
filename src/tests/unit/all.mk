#
#  Unit tests for individual pieces of functionality.
#

#
#  Test name
#
TEST := test.unit

#
#  Get all .txt files
#
FILES  := $(filter-out $(DIR)/files/%,$(call FIND_FILES_SUFFIX,$(DIR),*.txt))

#
#  If we don't have OpenSSL, filter out tests which need TLS.
#
ifeq "$(AC_HAVE_OPENSSL_SSL_H)" ""
FILES := $(filter-out $(shell grep -l 'need-feature tls' $(FILES)),$(FILES))
endif

#
#  Remove our directory prefix, which is needed by the bootstrap function.
#
FILES := $(subst $(DIR)/,,$(FILES))

# dict.txt - removed because the unit tests don't allow for protocol namespaces

# command.txt - removed because commands like ":sql" are not parsed properly any more

#
#  Bootstrap the test framework.
#
$(eval $(call TEST_BOOTSTRAP))

#
#  We use GMT for the tests, so that local time zones don't affect
#  the test outputs.
#
$(FILES.$(TEST)): export TZ = GMT

#
#  Ensure that the protocol tests are run if any of the protocol dictionaries change
#
PROTOCOLS := $(subst $(DIR)/protocols/,,$(wildcard $(DIR)/protocols/*))
define UNIT_TEST_PROTOCOLS
$(addprefix $(OUTPUT)/,$(filter protocols/${1}/%.txt,$(FILES))): $(wildcard $(top_srcdir)/share/dictionary/${1}/dictionary* $(top_srcdir)/src/tests/unit/protocols/${1}/dictionary*) $(BUILD_DIR)/lib/local/libfreeradius-${1}.la $(BUILD_DIR)/lib/libfreeradius-${1}.la

ifeq "${1}" "eap"
$(addprefix $(OUTPUT)/,$(filter protocols/${1}/%.txt,$(FILES))): $(wildcard $(top_srcdir)/share/dictionary/${1}/dictionary*) $(BUILD_DIR)/lib/local/libfreeradius-${1}.la $(BUILD_DIR)/lib/libfreeradius-eap-aka-sim.la
endif

test.unit.${1}: $(addprefix $(OUTPUT)/,$(filter protocols/${1}/%.txt,$(FILES))) $(BUILD_DIR)/lib/libfreeradius-${1}.la $(BUILD_DIR)/lib/local/libfreeradius-${1}.la

.PHONY: clean.test.unit.${1}
clean.test.unit.${1}:
	@rm -f $(addprefix $(OUTPUT)/,$(filter protocols/${1}/%.txt,$(FILES)))

test.unit.help: TEST_UNIT_HELP += test.unit.${1}
endef
$(foreach x,$(PROTOCOLS),$(eval $(call UNIT_TEST_PROTOCOLS,$x)))

test.unit.xlat: $(addprefix $(OUTPUT)/,$(filter xlat/%.txt,$(FILES))) $(BUILD_DIR)/lib/libfreeradius-unlang.la

test.unit.purify: $(addprefix $(OUTPUT)/,$(filter purify/%.txt,$(FILES))) $(BUILD_DIR)/lib/libfreeradius-unlang.la

test.unit.condition: $(addprefix $(OUTPUT)/,$(filter condition/%.txt,$(FILES))) $(BUILD_DIR)/lib/libfreeradius-server.la

test.unit.tmpl: $(addprefix $(OUTPUT)/,$(filter tmpl/%.txt,$(FILES))) $(BUILD_DIR)/lib/libfreeradius-server.la

test.unit.help: TEST_UNIT_HELP += test.unit.xlat

#
#  Add special command-line flag for purify tests.
#
$(filter $(BUILD_DIR)/tests/unit/purify/%,$(FILES.$(TEST))): PURIFY=-p

#
#  For automatically fixing the tests when only the output has changed
#
#  The unit_test_attribute program will copy the inputs to the outputs, and rewrite the "expected" output
#  with the "actual" output.  But only for the "match" command.  Everything is including comments and blank
#  lines is copied verbatim.
#
#REWRITE_FLAGS = -w $(BUILD_DIR)/tmp

#
#  And the actual script to run each test.
#
$(OUTPUT)/%: $(DIR)/% $(TEST_BIN_DIR)/unit_test_attribute
	$(eval DIR:=${top_srcdir}/src/tests/unit)
	$(eval export UNIT_TEST_ATTRIBUTE:=TZ=GMT $(TEST_BIN_NO_TIMEOUT)/unit_test_attribute $(PURIFY) -F ./src/tests/fuzzer-corpus -D ./share/dictionary -d $(DIR) -r \"$@\" $<)
	${Q}$(TEST_BIN)/unit_test_attribute $(PURIFY) $(REWRITE_FLAGS) -F ./src/tests/fuzzer-corpus -D ./share/dictionary -d $(DIR) -r "$@" $<

$(TEST):
	@touch $(BUILD_DIR)/tests/$@

$(TEST).help:
	@echo make $(TEST_UNIT_HELP)
