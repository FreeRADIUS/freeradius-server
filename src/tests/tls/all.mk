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
TLS_CONF    := $(DIR)/unit_test_tls.conf
TLS_RECEIPT := $(OUTPUT)/unit_test_tls.receipt
TLS_CACHE_RECEIPT := $(OUTPUT)/session_cache_client.receipt
TLS_ALERT_RECEIPT := $(OUTPUT)/alert.receipt

#
#  The script and the configuration have to agree on the port, so the script
#  is told what the configuration says.
#
TLS_PORT := $(shell sed -n 's/^[ 	]*port[ 	]*=[ 	]*\([0-9][0-9]*\).*/\1/p' $(TLS_CONF))

#
#  unit_test_tls loads its process module and its rlm_* modules at run time,
#  so make cannot see those dependencies.  The list is read from the
#  configuration, see TEST_CONFIG_LIBS in src/tests/all.mk.
#
$(eval $(call TEST_CONFIG_LIBS,$(TLS_CONF),$(TLS_RECEIPT)))

#
#  The script creates the receipt file, which is what says the test passed.
#
$(TLS_RECEIPT): $(TLS_CONF) $(TLS_SCRIPT) $(TEST_BIN_DIR)/unit_test_tls $(GENERATED_CERT_FILES) | $(TLS_OUTPUT)
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
$(TLS_CACHE_RECEIPT): $(TLS_CONF) $(TLS_CACHE) $(TEST_BIN_DIR)/unit_test_tls $(GENERATED_CERT_FILES) | $(TLS_OUTPUT)
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
$(TLS_ALERT_RECEIPT): $(TLS_CONF) $(TLS_ALERT) $(TEST_BIN_DIR)/unit_test_tls $(GENERATED_CERT_FILES) | $(TLS_OUTPUT)
	@echo "TLS-TEST alert"
	${Q}OUTPUT="$(TLS_OUTPUT)" \
	    CONFDIR="$(top_srcdir)/$(TLS_DIR)" \
	    CERTDIR="$(top_srcdir)/raddb/certs/rsa" \
	    DICT_PATH="$(DICT_PATH)" \
	    PORT="$(TLS_PORT)" \
	    UNIT_TEST_TLS="$(TEST_BIN)/unit_test_tls" \
	    $(SHELL) $(TLS_ALERT)

#
#  The three tests share a port, so they must not run at the same time.
#
$(TLS_CACHE_RECEIPT): $(TLS_RECEIPT)
$(TLS_ALERT_RECEIPT): $(TLS_CACHE_RECEIPT)

$(BUILD_DIR)/tests/$(TEST): $(TLS_RECEIPT) $(TLS_CACHE_RECEIPT) $(TLS_ALERT_RECEIPT)

$(TEST).help:
	@echo make $(TLS_TEST)

endif
