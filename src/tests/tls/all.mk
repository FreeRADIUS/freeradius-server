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
TLS_REJECT  := $(DIR)/reject.sh
TLS_NOCACHE := $(DIR)/no_cache.sh
TLS_FAILRES := $(DIR)/fail_resumed.sh
TLS_CONF    := $(DIR)/unit_test_tls.conf
TLS_COMMON  := $(DIR)/common.conf
TLS_NC_CONF := $(DIR)/no_cache.conf
TLS_RECEIPT := $(OUTPUT)/unit_test_tls.receipt
TLS_CACHE_RECEIPT := $(OUTPUT)/session_cache_client.receipt
TLS_ALERT_RECEIPT := $(OUTPUT)/alert.receipt
TLS_REJECT_RECEIPT := $(OUTPUT)/reject.receipt
TLS_NOCACHE_RECEIPT := $(OUTPUT)/no_cache_client.receipt
TLS_FAILRES_RECEIPT := $(OUTPUT)/fail_resumed.receipt

#
#  The script and the configuration have to agree on the port, so the script
#  is told what the configuration says.  The port is in common.conf, which
#  every configuration here includes, so one port serves them all.
#
TLS_PORT := $(shell sed -n 's/^[ 	]*port[ 	]*=[ 	]*\([0-9][0-9]*\).*/\1/p' $(TLS_COMMON))

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
#  The six tests share a port, so they must not run at the same time.
#
$(TLS_CACHE_RECEIPT): $(TLS_RECEIPT)
$(TLS_ALERT_RECEIPT): $(TLS_CACHE_RECEIPT)
$(TLS_REJECT_RECEIPT): $(TLS_ALERT_RECEIPT)
$(TLS_NOCACHE_RECEIPT): $(TLS_REJECT_RECEIPT)
$(TLS_FAILRES_RECEIPT): $(TLS_NOCACHE_RECEIPT)

$(BUILD_DIR)/tests/$(TEST): $(TLS_RECEIPT) $(TLS_CACHE_RECEIPT) $(TLS_ALERT_RECEIPT) $(TLS_REJECT_RECEIPT) $(TLS_NOCACHE_RECEIPT) $(TLS_FAILRES_RECEIPT)

$(TEST).help:
	@echo make $(TLS_TEST)

endif
