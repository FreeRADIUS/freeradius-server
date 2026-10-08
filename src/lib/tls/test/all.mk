#
#  The TLS library is only built when the server has OpenSSL.
#
ifneq ($(OPENSSL_LIBS),)
SUBMAKEFILES := \
	tls_bio_tests.mk
endif
