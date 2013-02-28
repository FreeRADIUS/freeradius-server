# -*- text -*-
##
## Makefile -- Build and run tests for the server.
##
##	http://www.freeradius.org/
##	$Id$
##
#
include ../../Make.inc

TESTS	= user_password chap mschapv1 digest-01/digest* test.example.com \
	wimax

PORT	 = 12340
ACCTPORT = $(shell expr $(PORT) + 1)

#	example.com stripped.example.com

EAPOL_TEST = eapol_test

EAP_TLS_TESTS = eap-ttls-pap.conf eap-mschapv2.conf \
	      eap-ttls-mschapv2.conf peap-mschapv2.conf

SECRET	= testing123

.PHONY: all eap dictionary clean

#
#	Build the directory for testing the server
#
all: tests

clean:
	@rm -f $(top_builddir)/raddb/test.conf test.conf dictionary

dictionary:
	@echo "# test dictionary not install.  Delete at any time." > dictionary
	@echo '$$INCLUDE ' $(top_builddir)/share/dictionary >> dictionary
	@echo '$$INCLUDE ' $(top_builddir)/src/tests/dictionary.test >> dictionary

test.conf: dictionary
	@echo "# test configuration file.  Do not install.  Delete at any time." > test.conf
	@echo "libdir =" $(top_builddir)/src/modules/lib/.libs/ >> test.conf
	@echo "testdir =" $(top_builddir)/src/tests/ >> test.conf
	@echo 'dictionary = $${testdir}' >> test.conf
	@echo 'logdir = $${testdir}' >> test.conf
	@echo 'radacctdir = $${testdir}' >> test.conf
	@echo 'pidfile = $${testdir}/radiusd.pid' >> test.conf
	@echo '$$INCLUDE radiusd.conf' >> test.conf
	@echo '$$INCLUDE $${testdir}/config/' >> test.conf

radiusd.pid: ../../raddb/test.conf test.conf
	@$(top_builddir)/src/main/radiusd -txxl `pwd`/radius.log -md $(top_builddir)/raddb/ -n test -i 127.0.0.1 -p $(PORT) || tail -n 20 `pwd`/radius.log

# We can't make this depend on radiusd.pid, because then make will create
# radiusd.pid when we make radiusd.kill, which we don't want.
.PHONY: radiusd.kill
radiusd.kill:
	@if [ -f radiusd.pid ]; then \
		(kill -TERM `cat radiusd.pid` >/dev/null 2>&1) || exit 0; \
	fi
	@rm -f radiusd.pid

#  Link from the main database directory to here
$(top_builddir)/raddb/test.conf: test.conf
	@[ -f $(top_builddir)/raddb/test.conf ] || ln -s $(top_builddir)/src/tests/test.conf $(top_builddir)/raddb/

# kill the server (if it's running)
# start the server
# run the tests (ignoring any failures)
# kill the server
# remove the changes to raddb/
tests: $(top_builddir)/raddb/test.conf radiusd.kill
	@chmod a+x runtests.sh
	@rm -f radius.log
	@$(MAKE) radiusd.pid
	@./runtests.sh $(TESTS)
	@$(MAKE) radiusd.kill
	@rm -f $(top_builddir)/raddb/test.conf

tests.eap: $(top_builddir)/raddb/test.conf radiusd.kill
	@chmod a+x runtests.sh
	@rm -f radius.log
	@$(MAKE) radiusd.pid
	@$(MAKE) eap
	@$(MAKE) radiusd.kill
	@rm -f $(top_buildir)/raddb/test.conf

eap: $(EAP_TLS_TESTS)
	for x in $(EAP_TLS_TESTS); do \
		$(EAPOL_TEST) -c $$x -p $(PORT) -s $(SECRET); \
	done

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
