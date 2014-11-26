# -*- makefile -*-
##
## Makefile -- Build and run tests for the server.
##
##	http://www.freeradius.org/
##	$Id$
##
#
include ../../Make.inc

BUILD_PATH := $(top_builddir)/build
TEST_PATH := $(top_builddir)/src/tests
BIN_PATH := $(BUILD_PATH)/bin/local
LIB_PATH := $(BUILD_PATH)/lib/.libs/
DYLD_LIBRARY_PATH := $(DYLD_LIBRARY_PATH):$(LIB_PATH)

export DYLD_LIBRARY_PATH

RADDB_PATH := $(top_builddir)/raddb

TESTS	= mschapv1 digest-01/digest* \
	test.example.com

PORT	 = 12340
#PORT	 = 1812
ACCTPORT = $(shell expr $(PORT) + 1)

#	example.com stripped.example.com

EAPOL_TEST = $(shell which eapol_test)

EAP_TLS_TESTS = eap-ttls-pap.conf eap-ttls-mschapv2.conf peap-mschapv2.conf

SECRET	= testing123

.PHONY: all eap dictionary clean

#
#	Build the directory for testing the server
#
all: parse tests

clean:
	@rm -f test.conf dictionary *.ok *.log

dictionary:
	@echo "# test dictionary not install.  Delete at any time." > dictionary
	@echo '$$INCLUDE ' $(top_builddir)/share/dictionary >> dictionary
	@echo '$$INCLUDE ' $(top_builddir)/src/tests/dictionary.test >> dictionary
	@echo '$$INCLUDE ' $(top_builddir)/share/dictionary.dhcp >> dictionary
	@echo '$$INCLUDE ' $(top_builddir)/share/dictionary.vqp >> dictionary

test.conf: dictionary
	@echo "# test configuration file.  Do not install.  Delete at any time." > test.conf
	@echo "libdir =" $(LIB_PATH) >> test.conf
	@echo "testdir =" $(TEST_PATH) >> test.conf
	@echo 'logdir = $${testdir}' >> test.conf
	@echo 'maindir = ${top_builddir}/raddb/' >> test.conf
	@echo 'radacctdir = $${testdir}' >> test.conf
	@echo 'pidfile = $${testdir}/radiusd.pid' >> test.conf
	@echo 'panic_action = "gdb -batch -x ${testdir}/panic.gdb %e %p > ${testdir}/gdb.log 2>&1; cat ${testdir}/gdb.log"' >> test.conf
	@echo 'security {' >> $@
	@echo '        allow_vulnerable_openssl = yes' >> $@
	@echo '}' >> $@
	@echo >> $@
	@echo 'modconfdir = $${maindir}mods-config' >> $@
	@echo 'certdir = $${maindir}/certs' >> $@
	@echo 'cadir   = $${maindir}/certs' >> $@
	@echo '$$INCLUDE $${testdir}/config/' >> test.conf
	@echo '$$INCLUDE $${maindir}/radiusd.conf' >> test.conf

radiusd.pid: test.conf
	@rm -f $(TEST_PATH)/gdb.log $(TEST_PATH)/radius.log
	@printf "Starting server... "
	@if ! $(BIN_PATH)/radiusd -Pxxxxml $(TEST_PATH)/radius.log -d ${top_builddir}/src/tests -n test -i 127.0.0.1 -p $(PORT) -D $(TEST_PATH); then\
		echo "failed"; \
		echo "Last log entries were:"; \
		tail -n 20 "$(TEST_PATH)/radius.log"; \
	fi
	@echo "ok"

# We can't make this depend on radiusd.pid, because then make will create
# radiusd.pid when we make radiusd.kill, which we don't want.
.PHONY: radiusd.kill
radiusd.kill:
	@if [ -f radiusd.pid ]; then \
	    ret=0; \
	    if ! ps `cat $(TEST_PATH)/radiusd.pid` >/dev/null 2>&1; then \
		rm -f radiusd.pid; \
		echo "FreeRADIUS terminated during test"; \
		echo "GDB output was:"; \
		cat "$(TEST_PATH)/gdb.log"; \
		echo "Last log entries were:"; \
		tail -n 20 $(TEST_PATH)/radius.log; \
		ret=1; \
	    fi; \
		if ! kill -TERM `cat $(TEST_PATH)/radiusd.pid` >/dev/null 2>&1; then \
		    ret=1; \
		fi; \
		exit $$ret; \
	fi
	@rm -f radiusd.pid

#
#  Run eapol_test if it exists.  Otherwise do nothing
#
ifneq "$(EAPOL_TEST)" ""
%.ok: %.conf
	@echo EAPOL_TEST $(patsubst %.conf,%,$<)
	@$(EAPOL_TEST) -c $< -p $(PORT) -s $(SECRET) > $(patsubst %.conf,%.log,$<) 2>&1
	@touch $@

tests.eap: $(patsubst %.conf,%.ok, $(EAP_TLS_TESTS))

endif

# kill the server (if it's running)
# start the server
# run the tests (ignoring any failures)
# kill the server
# remove the changes to raddb/
tests: test.conf | radiusd.kill radiusd.pid
	@chmod a+x runtests.sh
	@BIN_PATH="$(BIN_PATH)" PORT="$(PORT)" ./runtests.sh $(TESTS)
ifneq "$(EAPOL_TEST)" ""
	@$(MAKE) tests.eap
endif
	@$(MAKE) radiusd.kill
