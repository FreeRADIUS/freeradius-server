#
#  Test for unit_test_tls: run one TLS handshake against it.
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
#  One script runs the whole test, so there are no per-file tests here.
#
FILES :=

$(eval $(call TEST_BOOTSTRAP))

#
#  DIR and OUTPUT are globals which the next test directory overwrites, so
#  every one of them a recipe needs is captured here, while they still name
#  this directory.
#
TLS_DIR     := $(DIR)
TLS_OUTPUT  := $(OUTPUT)
TLS_SCRIPT  := $(DIR)/unit_test_tls.sh
TLS_CACHE   := $(DIR)/session_cache.sh
TLS_ALERT   := $(DIR)/alert.sh
TLS_ALERT_RECV := $(DIR)/alert_recv.sh
TLS_ALERT_SEND := $(DIR)/alert_send.sh
TLS_REJECT  := $(DIR)/reject.sh
TLS_NOCACHE := $(DIR)/no_cache.sh
TLS_FAILRES := $(DIR)/fail_resumed.sh
TLS_STATELESS := $(DIR)/stateless.sh
TLS_NOTICKET := $(DIR)/no_ticket.sh
TLS_ALPN     := $(DIR)/alpn.sh
TLS_INVALID  := $(DIR)/invalid.sh
TLS_CLOSE    := $(DIR)/close_notify.sh
TLS_CONF    := $(DIR)/unit_test_tls.conf
TLS_COMMON  := $(DIR)/common.conf
TLS_NC_CONF := $(DIR)/no_cache.conf
TLS_SL_CONF := $(DIR)/stateless.conf
TLS_NT_CONF := $(DIR)/no_ticket.conf
TLS_RECEIPT := $(OUTPUT)/unit_test_tls.receipt
TLS_CACHE_RECEIPT := $(OUTPUT)/session_cache_client.receipt
TLS_ALERT_RECEIPT := $(OUTPUT)/alert.receipt
TLS_ALERT_RECV_RECEIPT := $(OUTPUT)/alert_recv.receipt
TLS_ALERT_SEND_RECEIPT := $(OUTPUT)/alert_send.receipt
TLS_REJECT_RECEIPT := $(OUTPUT)/reject.receipt
TLS_NOCACHE_RECEIPT := $(OUTPUT)/no_cache_client.receipt
TLS_FAILRES_RECEIPT := $(OUTPUT)/fail_resumed.receipt
TLS_STATELESS_RECEIPT := $(OUTPUT)/stateless_client.receipt
TLS_NOTICKET_RECEIPT := $(OUTPUT)/no_ticket_client.receipt
TLS_ALPN_RECEIPT := $(OUTPUT)/alpn.receipt
TLS_INVALID_RECEIPT := $(OUTPUT)/invalid.receipt
TLS_CLOSE_RECEIPT := $(OUTPUT)/close_notify.receipt

#
#  The script and the configuration have to agree on the port, so the script
#  is told what the configuration says.  The port is in common.conf, which
#  every configuration here includes, so one port serves them all.
#
TLS_PORT := $(shell sed -n 's/^[ 	]*port[ 	]*=[ 	]*\([0-9][0-9]*\).*/\1/p' $(TLS_CONF))

#
#  unit_test_tls loads its process module and its rlm_* modules at run time,
#  so make cannot see those dependencies.  The list is read from common.conf,
#  which is where the modules section lives, see TEST_CONFIG_LIBS in
#  src/tests/all.mk.
#
$(eval $(call TEST_CONFIG_LIBS,$(TLS_COMMON),$(TLS_RECEIPT)))

#
#  The script creates the receipt file, which is what says the test passed.
#
$(TLS_RECEIPT): $(TLS_CONF) $(TLS_COMMON) $(TLS_SCRIPT) $(TEST_BIN_DIR)/unit_test_tls $(GENERATED_CERT_FILES) | $(TLS_OUTPUT)
	@echo "TLS-TEST unit_test_tls"
	${Q}OUTPUT="$(TLS_OUTPUT)" \
	    CONFDIR="$(top_srcdir)/$(TLS_DIR)" \
	    CERTDIR="$(top_srcdir)/raddb/certs/rsa" \
	    DICT_PATH="$(DICT_PATH)" \
	    PORT="$(TLS_PORT)" \
	    UNIT_TEST_TLS="$(TEST_BIN)/unit_test_tls" \
	    $(SHELL) $(TLS_SCRIPT)

#
#  TEST_BOOTSTRAP gave this target the recipe.  Only the prerequisite is
#  added here.
#
#
#  Session resumption, with unit_test_tls on both ends.
#
$(TLS_CACHE_RECEIPT): $(TLS_CONF) $(TLS_COMMON) $(TLS_CACHE) $(TEST_BIN_DIR)/unit_test_tls $(GENERATED_CERT_FILES) | $(TLS_OUTPUT)
	@echo "TLS-TEST session-cache"
	${Q}OUTPUT="$(TLS_OUTPUT)" \
	    CONFDIR="$(top_srcdir)/$(TLS_DIR)" \
	    DICT_PATH="$(DICT_PATH)" \
	    PORT="$(TLS_PORT)" \
	    UNIT_TEST_TLS="$(TEST_BIN)/unit_test_tls" \
	    $(SHELL) $(TLS_CACHE)

#
#  A handshake which is rejected with a fatal TLS alert.
#
$(TLS_ALERT_RECEIPT): $(TLS_CONF) $(TLS_COMMON) $(TLS_ALERT) $(TEST_BIN_DIR)/unit_test_tls $(GENERATED_CERT_FILES) | $(TLS_OUTPUT)
	@echo "TLS-TEST alert"
	${Q}OUTPUT="$(TLS_OUTPUT)" \
	    CONFDIR="$(top_srcdir)/$(TLS_DIR)" \
	    CERTDIR="$(top_srcdir)/raddb/certs/rsa" \
	    DICT_PATH="$(DICT_PATH)" \
	    PORT="$(TLS_PORT)" \
	    UNIT_TEST_TLS="$(TEST_BIN)/unit_test_tls" \
	    $(SHELL) $(TLS_ALERT)

#
#  A handshake where the peer rejects us, and sends a fatal TLS alert.  The
#  one test where FreeRADIUS reads an alert rather than writing one.
#
$(TLS_ALERT_RECV_RECEIPT): $(TLS_CONF) $(TLS_COMMON) $(TLS_ALERT_RECV) $(TEST_BIN_DIR)/unit_test_tls $(GENERATED_CERT_FILES) | $(TLS_OUTPUT)
	@echo "TLS-TEST alert-recv"
	${Q}OUTPUT="$(TLS_OUTPUT)" \
	    CONFDIR="$(top_srcdir)/$(TLS_DIR)" \
	    CERTDIR="$(top_srcdir)/raddb/certs/rsa" \
	    DICT_PATH="$(DICT_PATH)" \
	    PORT="$(TLS_PORT)" \
	    UNIT_TEST_TLS="$(TEST_BIN)/unit_test_tls" \
	    $(SHELL) $(TLS_ALERT_RECV)

#
#  A handshake where FreeRADIUS rejects the peer, and OpenSSL sends the fatal
#  TLS alert.  alert.sh covers the other way of sending one, where the record
#  is built by hand.
#
$(TLS_ALERT_SEND_RECEIPT): $(TLS_CONF) $(TLS_COMMON) $(TLS_ALERT_SEND) $(TEST_BIN_DIR)/unit_test_tls $(GENERATED_CERT_FILES) | $(TLS_OUTPUT)
	@echo "TLS-TEST alert-send"
	${Q}OUTPUT="$(TLS_OUTPUT)" \
	    CONFDIR="$(top_srcdir)/$(TLS_DIR)" \
	    CERTDIR="$(top_srcdir)/raddb/certs/rsa" \
	    DICT_PATH="$(DICT_PATH)" \
	    PORT="$(TLS_PORT)" \
	    UNIT_TEST_TLS="$(TEST_BIN)/unit_test_tls" \
	    $(SHELL) $(TLS_ALERT_SEND)

#
#  A session which is rejected after the handshake succeeded.
#
$(TLS_REJECT_RECEIPT): $(TLS_CONF) $(TLS_COMMON) $(TLS_REJECT) $(TEST_BIN_DIR)/unit_test_tls $(GENERATED_CERT_FILES) | $(TLS_OUTPUT)
	@echo "TLS-TEST reject"
	${Q}OUTPUT="$(TLS_OUTPUT)" \
	    CONFDIR="$(top_srcdir)/$(TLS_DIR)" \
	    CERTDIR="$(top_srcdir)/raddb/certs/rsa" \
	    DICT_PATH="$(DICT_PATH)" \
	    PORT="$(TLS_PORT)" \
	    UNIT_TEST_TLS="$(TEST_BIN)/unit_test_tls" \
	    $(SHELL) $(TLS_REJECT)

#
#  Two connections between a server and a client which have session caching
#  turned off.  Every other test here runs with caching on, so this is the
#  only one which takes the NULL tls_session->cache paths.
#
$(TLS_NOCACHE_RECEIPT): $(TLS_NC_CONF) $(TLS_COMMON) $(TLS_NOCACHE) $(TEST_BIN_DIR)/unit_test_tls $(GENERATED_CERT_FILES) | $(TLS_OUTPUT)
	@echo "TLS-TEST no-cache"
	${Q}OUTPUT="$(TLS_OUTPUT)" \
	    CONFDIR="$(top_srcdir)/$(TLS_DIR)" \
	    DICT_PATH="$(DICT_PATH)" \
	    PORT="$(TLS_PORT)" \
	    UNIT_TEST_TLS="$(TEST_BIN)/unit_test_tls" \
	    $(SHELL) $(TLS_NOCACHE)

#
#  A session which is resumed from the cache and then rejected.  The clear
#  runs here, where reject.sh proves it does not run without a load.
#
$(TLS_FAILRES_RECEIPT): $(TLS_CONF) $(TLS_COMMON) $(TLS_FAILRES) $(TEST_BIN_DIR)/unit_test_tls $(GENERATED_CERT_FILES) | $(TLS_OUTPUT)
	@echo "TLS-TEST fail-resumed"
	${Q}OUTPUT="$(TLS_OUTPUT)" \
	    CONFDIR="$(top_srcdir)/$(TLS_DIR)" \
	    DICT_PATH="$(DICT_PATH)" \
	    PORT="$(TLS_PORT)" \
	    UNIT_TEST_TLS="$(TEST_BIN)/unit_test_tls" \
	    $(SHELL) $(TLS_FAILRES)

#
#  Stateless session resumption over TLS 1.3.  The only test here which runs
#  `encode session` and `decode session`, and the only one which negotiates
#  1.3, because stateful resumption is not defined above 1.2.
#
$(TLS_STATELESS_RECEIPT): $(TLS_SL_CONF) $(TLS_COMMON) $(TLS_STATELESS) $(TEST_BIN_DIR)/unit_test_tls $(GENERATED_CERT_FILES) | $(TLS_OUTPUT)
	@echo "TLS-TEST stateless"
	${Q}OUTPUT="$(TLS_OUTPUT)" \
	    CONFDIR="$(top_srcdir)/$(TLS_DIR)" \
	    DICT_PATH="$(DICT_PATH)" \
	    PORT="$(TLS_PORT)" \
	    UNIT_TEST_TLS="$(TEST_BIN)/unit_test_tls" \
	    $(SHELL) $(TLS_STATELESS)

#
#  A server which issues no ticket, talking to a client which expects one.
#  The only test which pins the application-data signal, because it is the
#  only one where nothing else can release the client.
#
$(TLS_NOTICKET_RECEIPT): $(TLS_NT_CONF) $(TLS_COMMON) $(TLS_NOTICKET) $(TEST_BIN_DIR)/unit_test_tls $(GENERATED_CERT_FILES) | $(TLS_OUTPUT)
	@echo "TLS-TEST no-ticket"
	${Q}OUTPUT="$(TLS_OUTPUT)" \
	    CONFDIR="$(top_srcdir)/$(TLS_DIR)" \
	    DICT_PATH="$(DICT_PATH)" \
	    PORT="$(TLS_PORT)" \
	    UNIT_TEST_TLS="$(TEST_BIN)/unit_test_tls" \
	    $(SHELL) $(TLS_NOTICKET)

#
#  Application Layer Protocol Negotiation.  Four cases in one script, see the
#  comment at the top of alpn.sh for why.
#
$(TLS_ALPN_RECEIPT): $(TLS_CONF) $(TLS_COMMON) $(TLS_ALPN) $(TEST_BIN_DIR)/unit_test_tls $(GENERATED_CERT_FILES) | $(TLS_OUTPUT)
	@echo "TLS-TEST alpn"
	${Q}OUTPUT="$(TLS_OUTPUT)" \
	    CONFDIR="$(top_srcdir)/$(TLS_DIR)" \
	    DICT_PATH="$(DICT_PATH)" \
	    PORT="$(TLS_PORT)" \
	    UNIT_TEST_TLS="$(TEST_BIN)/unit_test_tls" \
	    $(SHELL) $(TLS_ALPN)

#
#  A session which FreeRADIUS itself refuses, rather than OpenSSL.
#
$(TLS_INVALID_RECEIPT): $(TLS_CONF) $(TLS_COMMON) $(TLS_INVALID) $(TEST_BIN_DIR)/unit_test_tls $(GENERATED_CERT_FILES) | $(TLS_OUTPUT)
	@echo "TLS-TEST invalid"
	${Q}OUTPUT="$(TLS_OUTPUT)" \
	    CONFDIR="$(top_srcdir)/$(TLS_DIR)" \
	    DICT_PATH="$(DICT_PATH)" \
	    PORT="$(TLS_PORT)" \
	    UNIT_TEST_TLS="$(TEST_BIN)/unit_test_tls" \
	    $(SHELL) $(TLS_INVALID)

#
#  A peer which FreeRADIUS refuses after the handshake has finished.
#
$(TLS_CLOSE_RECEIPT): $(TLS_CONF) $(TLS_COMMON) $(TLS_CLOSE) $(TEST_BIN_DIR)/unit_test_tls $(GENERATED_CERT_FILES) | $(TLS_OUTPUT)
	@echo "TLS-TEST close-notify"
	${Q}OUTPUT="$(TLS_OUTPUT)" \
	    CONFDIR="$(top_srcdir)/$(TLS_DIR)" \
	    CERTDIR="$(top_srcdir)/raddb/certs/rsa" \
	    DICT_PATH="$(DICT_PATH)" \
	    PORT="$(TLS_PORT)" \
	    UNIT_TEST_TLS="$(TEST_BIN)/unit_test_tls" \
	    $(SHELL) $(TLS_CLOSE)

#
#  The thirteen tests share a port, so they must not run at the same time.
#
$(TLS_CACHE_RECEIPT): $(TLS_RECEIPT)
$(TLS_ALERT_RECEIPT): $(TLS_CACHE_RECEIPT)
$(TLS_ALERT_RECV_RECEIPT): $(TLS_ALERT_RECEIPT)
$(TLS_ALERT_SEND_RECEIPT): $(TLS_ALERT_RECV_RECEIPT)
$(TLS_REJECT_RECEIPT): $(TLS_ALERT_SEND_RECEIPT)
$(TLS_NOCACHE_RECEIPT): $(TLS_REJECT_RECEIPT)
$(TLS_FAILRES_RECEIPT): $(TLS_NOCACHE_RECEIPT)
$(TLS_STATELESS_RECEIPT): $(TLS_FAILRES_RECEIPT)
$(TLS_NOTICKET_RECEIPT): $(TLS_STATELESS_RECEIPT)
$(TLS_ALPN_RECEIPT): $(TLS_NOTICKET_RECEIPT)
$(TLS_INVALID_RECEIPT): $(TLS_ALPN_RECEIPT)
$(TLS_CLOSE_RECEIPT): $(TLS_INVALID_RECEIPT)

$(BUILD_DIR)/tests/$(TEST): $(TLS_RECEIPT) $(TLS_CACHE_RECEIPT) $(TLS_ALERT_RECEIPT) $(TLS_ALERT_RECV_RECEIPT) $(TLS_ALERT_SEND_RECEIPT) $(TLS_REJECT_RECEIPT) $(TLS_NOCACHE_RECEIPT) $(TLS_FAILRES_RECEIPT) $(TLS_STATELESS_RECEIPT) $(TLS_NOTICKET_RECEIPT) $(TLS_ALPN_RECEIPT) $(TLS_INVALID_RECEIPT) $(TLS_CLOSE_RECEIPT)

$(TEST).help:
	@echo make $(TLS_TEST)

endif
