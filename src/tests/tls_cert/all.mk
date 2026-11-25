#
#  Test that the server warns at start when a certificate it loads has
#  expired, or is not yet valid.  The certificates are made by
#  certs.sh, with dates in the past and in the future.
#
TLS_CERT_DIR	:= $(DIR)
TLS_CERT_OUT	:= $(BUILD_DIR)/tests/tls_cert
TLS_CERT_RUN	:= TLS_CERT_OUT=$(TLS_CERT_OUT) $(TESTBIN)/radiusd -XC -d $(TLS_CERT_DIR)/config -D $(DICT_PATH)

.PHONY: tests.tls_cert

#
#  Check OpenSSL is present and version > 1.0. Prior to that, all the certs get
#  the same name and the below check fails, so skip in that case.
#
TLS_CERT_OPENSSL := $(shell openssl version 2>/dev/null | grep -Ev '^OpenSSL (0\.|1\.0\.)')

ifneq "$(and $(findstring rlm_eap_tls,$(ALL_TGTS)),$(TLS_CERT_OPENSSL))" ""
tests.tls_cert: $(TLS_CERT_OUT)/validity

$(TLS_CERT_OUT)/chain.pem: $(TLS_CERT_DIR)/certs.sh $(TLS_CERT_DIR)/config/ca.cnf
	${Q}sh $(TLS_CERT_DIR)/certs.sh $(TLS_CERT_DIR)/config/ca.cnf $(TLS_CERT_OUT)

#
#  Each certificate outside of its validity period gets a warning, and
#  the valid one doesn't.
#
$(TLS_CERT_OUT)/validity: $(TLS_CERT_DIR)/config/radiusd.conf $(TLS_CERT_OUT)/chain.pem $(TESTBINDIR)/radiusd
	${Q}echo "TLS-CERT-TEST validity"
	${Q}if ! $(TLS_CERT_RUN) > $(TLS_CERT_OUT)/radiusd.log 2>&1; then \
		tail -n 50 $(TLS_CERT_OUT)/radiusd.log; \
		echo "RADIUSD: $(TLS_CERT_RUN)"; \
		exit 1; \
	fi
	${Q}ok=yes; \
	grep -q 'Certificate "/CN=Expired test certificate" in file ".*/expired.pem" expired on Jan  2 00:00:00 2000 GMT' $(TLS_CERT_OUT)/radiusd.log || ok=no; \
	grep -q 'Certificate "/CN=Future test certificate" in file ".*/future.pem" is not valid until Jan  1 00:00:00 2099 GMT' $(TLS_CERT_OUT)/radiusd.log || ok=no; \
	grep -q 'Certificate "/CN=Expired test certificate" in file ".*/chain.pem" expired on' $(TLS_CERT_OUT)/radiusd.log || ok=no; \
	! grep -q 'Certificate "/CN=Valid test certificate"' $(TLS_CERT_OUT)/radiusd.log || ok=no; \
	if [ "$$ok" != "yes" ]; then \
		grep 'Certificate "' $(TLS_CERT_OUT)/radiusd.log; \
		echo "Missing or unexpected warnings in $(TLS_CERT_OUT)/radiusd.log"; \
		echo "RADIUSD: $(TLS_CERT_RUN)"; \
		exit 1; \
	fi
	${Q}touch $@
else
tests.tls_cert:
	@echo "TLS-CERT-TEST skipped, as rlm_eap_tls or openssl >= 1.1 is not available"
endif

.PHONY: clean.tests.tls_cert
clean.tests.tls_cert:
	${Q}rm -rf $(TLS_CERT_OUT)

clean.test: clean.tests.tls_cert
