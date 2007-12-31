include ../../Make.inc

TESTS	= user_password chap mschapv1 digest-auth-MD5 digest-auth-int \
	digest-auth-noalgo digest-md5-sess digest-auth-MD5_Sess \
	digest-auth_int-MD5 digest-auth_int-MD5_Sess digest-auth_int-noalgo

#	example.com stripped.example.com

EAPOL_TEST = /usr/bin/env eapol_test

EAP_TLS_TESTS = eap-ttls-pap.conf eap-ttls-mschapv2.conf peap-mschapv2.conf

SECRET	= testing123

.PHONY: all eap test.conf dictionary clean

#
#	Build the directory for testing the server
#
all: tests

clean:
	@rm -f ../../raddb/test.conf test.conf dictionary

test.conf:
	@echo "# test configuration file.  Do not install.  Delete at any time." > test.conf
	@echo "libdir =" $(top_builddir)/src/modules/lib >> test.conf
	@echo "dictionary =" $(top_builddir)/src/tests/ >> test.conf
	@echo "testdir =" $(top_builddir)/src/tests/ >> test.conf
	@echo '$$INCLUDE radiusd.conf' >> test.conf
	@echo '$$INCLUDE $${testdir}/config/' >> test.conf
	@[ -f ../../raddb/test.conf ] || ln -s ../src/tests/test.conf ../../raddb/

dictionary:
	@echo '$$INCLUDE ' $(top_builddir)/share/dictionary > dictionary
	@echo '$$INCLUDE ' $(top_builddir)/src/tests/dictionary.test >> dictionary

tests: test.conf dictionary
	@chmod a+x runtests.sh
	./runtests.sh $(TESTS)

eap: $(EAP_TLS_TESTS)
	$(EAPOL_TEST) -c eap-ttls-pap.conf -s $(SECRET) 
	$(EAPOL_TEST) -c peap-mschapv2.conf -s $(SECRET)
	$(EAPOL_TEST) -c eap-ttls-mschapv2.conf -s $(SECRET)

md5:
	$(EAPOL_TEST) -c eap-md5.conf -s $(SECRET) 

tls:
	$(EAPOL_TEST) -c eap-ttls-tls.conf -s $(SECRET)

ttls:
	$(EAPOL_TEST) -c eap-ttls-pap.conf -s $(SECRET)

peap:
	$(EAPOL_TEST) -c peap-mschapv2.conf -s $(SECRET)

leap:
	$(EAPOL_TEST) -c leap.conf -s $(SECRET)
