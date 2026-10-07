#
#  Tests for unit_test_tls: one script per test, each running TLS handshakes
#  against the program.
#

#
#  Test name
#
TEST := test.tls

#
#  TEST is a global which the next test directory overwrites.  Recipe bodies
#  are expanded long after that has happened, so a copy is kept here.
#
TLS_TEST := test.tls

#
#  unit_test_tls is only built when the server has OpenSSL, see
#  src/bin/unit_test_tls.mk.  With no program there is nothing to test, so
#  everything below is skipped, and the test says why.
#
ifeq "$(filter unit_test_tls,$(ALL_TGTS))" ""

.PHONY: $(TEST) $(TEST).help clean.$(TEST)
$(TEST):
	@echo "$(TLS_TEST) - skipped, unit_test_tls was not built"

$(TEST).help:
	@echo make $(TLS_TEST)

clean.$(TEST):

clean.test: clean.$(TEST)

else

#
#  The tests are the scripts listed below, so there are no per-file tests
#  here.
#
FILES :=

$(eval $(call TEST_BOOTSTRAP))

#
#  DIR and OUTPUT are globals which the next test directory overwrites, so
#  TLS_DIR and TLS_OUTPUT copy the two globals here, while the globals still
#  name this directory.
#
TLS_DIR     := $(DIR)
TLS_OUTPUT  := $(OUTPUT)
TLS_CONF    := $(DIR)/unit_test_tls.conf
TLS_COMMON  := $(DIR)/common.conf

#
#  Every script in this directory is a test.  The comment at the top of the
#  script says what the test covers.  The script writes a receipt named
#  after the script when the test passes, so alpn.sh writes alpn.receipt.
#  A test with a configuration file named after the script uses that
#  configuration file, so psk.sh uses psk.conf.  Every other test uses
#  unit_test_tls.conf.
#
TLS_TESTS := $(patsubst $(DIR)/%.sh,%,$(wildcard $(DIR)/*.sh))

#
#  The suite takes one block of 20 ports from the allocator in
#  scripts/build/make/port.c, the block size that radiusd.mk takes for a
#  server.  Each test takes the port at the position of the test in
#  TLS_TESTS.  The tests can therefore run at the same time, and a second
#  build tree can run the suite at the same time.  Each test script passes
#  PORT to the client, and the configuration file reads the server port
#  from $ENV{PORT}.
#
TLS_PORT_FIRST := $(unique-port $(PORT_FILE),$(TLS_TEST),20,$(PORT_FIRST))
TLS_PORTS := $(shell seq $(TLS_PORT_FIRST) $$(($(TLS_PORT_FIRST) + 19)))

#
#  TLS_TEST_RULE defines the rule for one test.  ${1} is the test name.
#
#  When a test fails, the recipe prints the log of the test and the command
#  which ran the test, so the reader can run the test again by hand.
#
define TLS_TEST_RULE
TLS_PORT.${1} := $(word $(words $(TLS_RECEIPTS) ${1}),$(TLS_PORTS))
TLS_CMD.${1} := OUTPUT="$(TLS_OUTPUT)" CONFDIR="$(top_srcdir)/$(TLS_DIR)" CERTDIR="$(top_srcdir)/raddb/certs/rsa" DICT_PATH="$(DICT_PATH)" PORT="$$(TLS_PORT.${1})" UNIT_TEST_TLS="$(TEST_BIN)/unit_test_tls" $(SHELL) $(TLS_DIR)/${1}.sh

$(TLS_OUTPUT)/${1}.receipt: $(or $(wildcard $(TLS_DIR)/${1}.conf),$(TLS_CONF)) $(TLS_COMMON) $(TLS_DIR)/${1}.sh $(TEST_BIN_DIR)/unit_test_tls $(GENERATED_CERT_FILES) | $(TLS_OUTPUT)
	@echo "TLS-TEST ${1}"
	$${Q}if ! $$(TLS_CMD.${1}) > $$@.log 2>&1 || ! test -f $$@; then \
		cat $$@.log; \
		echo "# $$@.log"; \
		echo $$(TLS_CMD.${1}); \
		rm -f $(BUILD_DIR)/tests/$(TLS_TEST); \
		exit 1; \
	fi

TLS_RECEIPTS += $(TLS_OUTPUT)/${1}.receipt
endef

TLS_RECEIPTS :=
$(foreach x,$(TLS_TESTS),$(eval $(call TLS_TEST_RULE,$x)))

#
#  unit_test_tls loads a process module and rlm_* modules at run time, so
#  make cannot see the dependency on those libraries.  TEST_CONFIG_LIBS in
#  src/tests/all.mk reads the module list from common.conf, which holds the
#  modules section.
#
$(eval $(call TEST_CONFIG_LIBS,$(TLS_COMMON),$(TLS_RECEIPTS)))

$(BUILD_DIR)/tests/$(TEST): $(TLS_RECEIPTS)

$(TEST).help:
	@echo make $(TLS_TEST)

endif
