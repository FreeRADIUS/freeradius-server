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
FILES  := $(call FIND_FILES_SUFFIX,$(DIR),*.txt)

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
$(addprefix $(OUTPUT)/,$(filter protocols/${1}/%.txt,$(FILES))): $(wildcard $(top_srcdir)/share/dictionary/${1}/dictionary*) $(BUILD_DIR)/lib/libfreeradius-${1}.la

test.unit.${1}: $(addprefix $(OUTPUT)/,$(filter protocols/${1}/%.txt,$(FILES))) $(BUILD_DIR)/lib/libfreeradius-${1}.la
endef
$(foreach x,$(PROTOCOLS),$(eval $(call UNIT_TEST_PROTOCOLS,$x)))

#  This is useful, too
test.unit.condition: $(addprefix $(OUTPUT)/,$(filter condition/%.txt,$(FILES))) $(BUILD_DIR)/lib/libfreeradius-server.la

#
#  And the actual script to run each test.
#
$(OUTPUT)/%: $(DIR)/% $(TEST_BIN_DIR)/unit_test_attribute
	$(eval DIR:=${top_srcdir}/src/tests/unit)
	@echo "UNIT-TEST $(lastword $(subst /, ,$(dir $@))) $(basename $(notdir $@))"
	${Q}if ! $(TEST_BIN)/unit_test_attribute -D ./share/dictionary -d $(DIR) -r "$@" $<; then \
		echo "TZ=GMT $(TEST_BIN)/unit_test_attribute -D ./share/dictionary -d $(DIR) -r \"$@\" $<"; \
		rm -f $(BUILD_DIR)/tests/test.unit; \
		exit 1; \
	fi

$(TEST):
	@touch $(BUILD_DIR)/tests/$@
