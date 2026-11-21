#
#  Tests for the retry and timeout rules of the `radius` module.  Each test
#  starts radiusd with a configuration file, and a home server which
#  rlm_radius_test.py runs.
#

#
#  Test name
#
TEST := test.radius

#
#  TEST is a global which the next test directory overwrites.  Recipe bodies
#  are expanded long after that has happened, so a copy is kept here.
#
RADIUS_TEST := test.radius

#
#  The home server and the checks are a Python program.  Without a Python 3
#  interpreter there is nothing to run, and the test says why.
#
RADIUS_PYTHON := $(shell python3 -c 'import hashlib, signal, socket, ssl, struct, threading' 2>/dev/null && command -v python3)

ifeq "$(RADIUS_PYTHON)" ""

.PHONY: $(TEST) $(TEST).help clean.$(TEST)
$(TEST):
	@echo "$(RADIUS_TEST) - skipped, no Python 3 interpreter"

$(TEST).help:
	@echo make $(RADIUS_TEST)

clean.$(TEST):

clean.test: clean.$(TEST)

else

#
#  The tests are the configuration files listed below, so there are no
#  per-file tests here.
#
FILES :=

$(eval $(call TEST_BOOTSTRAP))

#
#  DIR and OUTPUT are globals which the next test directory overwrites, so
#  RADIUS_DIR and RADIUS_OUTPUT copy the two globals here, while the globals
#  still name this directory.
#
RADIUS_DIR    := $(DIR)
RADIUS_OUTPUT := $(OUTPUT)
RADIUS_PROG   := $(DIR)/rlm_radius_test.py

#
#  Every configuration file in this directory is a test.  The comment at the
#  top of the configuration file says what the test covers, and
#  rlm_radius_test.py has a function with the name of the test.  The program
#  writes a receipt named after the test when the test passes, so
#  udp_proxy_once.conf writes udp_proxy_once.receipt.
#
RADIUS_ALL_TESTS := $(patsubst $(DIR)/%.conf,%,$(wildcard $(DIR)/*.conf))

#
#  The tls_* tests configure a "tls" subsection, which the radius module has only when the server is
#  built with OpenSSL.  Without OpenSSL, radiusd rejects the configuration files.  unit_test_tls is built
#  only when the server has OpenSSL, see src/bin/unit_test_tls.mk, and src/tests/tls/all.mk uses the same
#  check.  The tls_* tests are not run when the server has no OpenSSL.
#
ifeq "$(filter unit_test_tls,$(ALL_TGTS))" ""
RADIUS_ALL_TESTS := $(filter-out tls_%,$(RADIUS_ALL_TESTS))
endif

#
#  The slow tests wait for a timer to run out.  Each test takes 5 seconds or more, because the
#  tests wait for max_rtx_duration, which is 5 seconds.  The zombie tests take 9 to 20 seconds.
#  The tests which send a packet and get a reply, and the configuration checks, take less than 5
#  seconds.
#
#  "make test.radius" does not run the slow tests.  "make test.radius.slow" runs only the slow
#  tests.  A new udp_zombie_* test is slow without an entry here.
#
RADIUS_SLOW_NAMES := \
	replicate_udp \
	tcp_client_once \
	tcp_proxy_once \
	udp_proxy_dup \
	udp_proxy_once

RADIUS_SLOW_TESTS := $(filter $(RADIUS_SLOW_NAMES) udp_zombie_%,$(RADIUS_ALL_TESTS))
RADIUS_TESTS := $(filter-out $(RADIUS_SLOW_TESTS),$(RADIUS_ALL_TESTS))

#
#  The suite takes one block of ports from the allocator in
#  scripts/build/make/port.c.  Each test takes two ports.  PORT is the port
#  of the home server, and LPORT is the UDP port where radiusd listens.  The
#  home server may use UDP, so the two ports cannot be the same number.  The
#  first half of the block holds the ports of the home servers, and the
#  second half holds the ports of the listeners.  The tests can therefore run
#  at the same time, and a second build tree can run the suite at the same
#  time.
#
RADIUS_PORT_COUNT := 64
RADIUS_PORT_FIRST := $(unique-port $(PORT_FILE),$(RADIUS_TEST),$(RADIUS_PORT_COUNT),$(PORT_FIRST))
RADIUS_PORTS := $(shell seq $(RADIUS_PORT_FIRST) $$(($(RADIUS_PORT_FIRST) + $(RADIUS_PORT_COUNT) - 1)))
RADIUS_HALF := $(shell echo $$(($(RADIUS_PORT_COUNT) / 2)))

#
#  RADIUS_TEST_RULE defines the rule for one test.  ${1} is the test name.
#
define RADIUS_TEST_RULE
RADIUS_PORT.${1} := $(word $(words $(RADIUS_RECEIPTS) ${1}),$(RADIUS_PORTS))
RADIUS_LPORT.${1} := $(word $(shell echo $$(($(words $(RADIUS_RECEIPTS) ${1}) + $(RADIUS_HALF)))),$(RADIUS_PORTS))
RADIUS_CMD.${1} := \
	TEST=${1} \
	OUTPUT=$(call SHELL_QUOTE,$(RADIUS_OUTPUT)) \
	CONFDIR=$(call SHELL_QUOTE,$(top_srcdir)/$(RADIUS_DIR)) \
	DICT_PATH=$(call SHELL_QUOTE,$(DICT_PATH)) \
	CERTDIR=$(call SHELL_QUOTE,$(top_srcdir)/raddb/certs/rsa) \
	PORT=$$(RADIUS_PORT.${1}) \
	LPORT=$$(RADIUS_LPORT.${1}) \
	RADIUSD=$(call SHELL_QUOTE,$(TEST_BIN)/radiusd) \
	$(RADIUS_PYTHON) -I $(RADIUS_PROG)

$(RADIUS_OUTPUT)/${1}.receipt: $(RADIUS_DIR)/${1}.conf $(RADIUS_PROG) $(TEST_BIN_DIR)/radiusd | $(RADIUS_OUTPUT)
	@echo "RADIUS-TEST ${1}"
	$${Q}if ! $$(RADIUS_CMD.${1}) > $$@.out 2>&1 || ! test -f $$@; then \
		cat $$@.out; \
		echo "# $$@.out"; \
		echo $$(call SHELL_QUOTE,$$(RADIUS_CMD.${1})); \
		rm -f $(BUILD_DIR)/tests/$(RADIUS_TEST); \
		exit 1; \
	fi

RADIUS_RECEIPTS += $(RADIUS_OUTPUT)/${1}.receipt
endef

#
#  Every test, including the slow tests, takes a pair of ports from the block, so the tests never share
#  ports.  The ordinary tests and the slow tests have separate lists of receipts, which the two targets
#  below depend on.
#
RADIUS_RECEIPTS :=
$(foreach x,$(RADIUS_TESTS) $(RADIUS_SLOW_TESTS),$(eval $(call RADIUS_TEST_RULE,$x)))

RADIUS_SLOW_RECEIPTS := $(addprefix $(RADIUS_OUTPUT)/,$(addsuffix .receipt,$(RADIUS_SLOW_TESTS)))
RADIUS_FAST_RECEIPTS := $(filter-out $(RADIUS_SLOW_RECEIPTS),$(RADIUS_RECEIPTS))

#
#  A test beyond half of the block would take a port from the second half.
#
ifeq "$(shell test $(words $(RADIUS_RECEIPTS)) -gt $(RADIUS_HALF) && echo overflow)" "overflow"
$(error src/tests/radius has $(words $(RADIUS_RECEIPTS)) tests and only $(RADIUS_HALF) ports for the home servers.  Raise RADIUS_PORT_COUNT)
endif

#
#  radiusd loads the `radius` module at run time, so make cannot see the
#  dependency on the library.  TEST_CONFIG_LIBS in src/tests/all.mk reads the
#  module list from the configuration files.
#
$(eval $(call TEST_CONFIG_LIBS,$(wildcard $(RADIUS_DIR)/*.conf),$(RADIUS_RECEIPTS)))

$(BUILD_DIR)/tests/$(TEST): $(RADIUS_FAST_RECEIPTS)

#
#  The slow tests run only when the user asks for the tests.
#
.PHONY: $(TEST).slow
$(TEST).slow: $(RADIUS_SLOW_RECEIPTS)

$(TEST).help:
	@echo make $(RADIUS_TEST)
	@echo make $(RADIUS_TEST).slow - the tests which wait for a timer, which $(RADIUS_TEST) does not run

endif
