include ../../Make.inc

TESTS	= user_password chap mschapv1 digest-auth-MD5 digest-auth-int \
	digest-auth-noalgo digest-md5-sess digest-auth-MD5_Sess \
	digest-auth_int-MD5 digest-auth_int-MD5_Sess digest-auth_int-noalgo \
	example.com stripped.example.com

EAPOL_TEST = eapol_test

EAP_TLS_TESTS = eap-ttls-pap.conf eap-ttls-mschapv2.conf peap-mschapv2.conf

SECRET	= testing123

.PHONY: all eap

#
#	Build the directory for testing the server
#
all: tests

#
#  Copy all of the files in a portable way
#
#  Then, over-write the radiusd.conf && dictionary files with
#  entries that point to this directory, and to the modules in
#  the local build directory.
#
raddb/.raddb:
	rm -rf raddb
	@(cd ../..; tar -cf - raddb) | tar -xf -
	@echo '$$INCLUDE ' $(top_builddir)/src/tests/dictionary.test > raddb/dictionary
	@echo '$$INCLUDE ' $(top_builddir)/share/dictionary >> raddb/dictionary
	@echo "raddbdir = " $(top_builddir)/src/tests/raddb > raddb/radiusd.conf
	@echo "libdir = " $(top_builddir)/src/modules/lib >> raddb/radiusd.conf
	@echo '$$INCLUDE ' $(top_builddir)/raddb/radiusd.conf >> raddb/radiusd.conf
	@cp proxy.conf raddb
	@touch raddb/.raddb

tests: raddb/.raddb
	@chmod a+x runtests.sh
	./runtests.sh $(TESTS)

eap: $(EAP_TLS_TESTS)
	$(EAPOL_TEST) -c eap-ttls-pap.conf -s $(SECRET) 
	$(EAPOL_TEST) -c peap-mschapv2.conf -s $(SECRET)
	$(EAPOL_TEST) -c eap-ttls-mschapv2.conf -s $(SECRET)
