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
TEST_PATH := $(top_srcdir)/src/tests
BIN_PATH := $(BUILD_PATH)/bin/local
LIB_PATH := $(BUILD_PATH)/lib/local/.libs/
FR_LIBRARY_PATH := $(BUILD_PATH)/lib/local/.libs/

export FR_LIBRARY_PATH

RADDB_PATH := $(top_srcdir)/raddb

TEST = mschapv1 digest-01/digest* test.example.com

PORT := 12340

#	example.com stripped.example.com
SECRET := testing123

.PHONY: all eap clean

#
#	Build the directory for testing the server
#
all: parse tests

clean:
	@rm -f test.conf *.ok *.log

test.conf: dictionary
	@echo "# test configuration file.  Do not install.  Delete at any time." > $@
	@echo "testdir =" $(TEST_PATH) >> $@
	@echo 'logdir = $${testdir}' >> $@
	@echo 'maindir = ${top_srcdir}/raddb/' >> $@
	@echo 'radacctdir = $${testdir}' >> $@
	@echo 'pidfile = $${testdir}/radiusd.pid' >> $@
	@echo 'panic_action = "gdb -batch -x ${testdir}/panic.gdb %e %p > ${testdir}/gdb.log 2>&1; cat ${testdir}/gdb.log"' >> $@
	@echo 'security {' >> $@
	@echo '        allow_vulnerable_openssl = yes' >> $@
	@echo '}' >> $@
	@echo >> $@
	@echo 'modconfdir = $${maindir}mods-config' >> $@
	@echo 'certdir = $${maindir}/certs' >> $@
	@echo 'cadir   = $${maindir}/certs' >> $@
	@echo '$$INCLUDE $${testdir}/config/' >> $@

radiusd.pid: test.conf
	@rm -f $(TEST_PATH)/gdb.log $(TEST_PATH)/radius.log
	@printf "TEST-SERVER Starting server... "
	@if ! TEST_PORT=$(PORT) $(BIN_PATH)/radiusd -Pxxl stdout -d ${top_srcdir}/src/tests -n test -D "${top_srcdir}/share/dictionary/" >  ${top_srcdir}/src/tests/radius.log 2>&1 ; then\
		echo "failed"; \
		echo "Last log entries were:"; \
		tail -n 20 "$(TEST_PATH)/radius.log"; \
		echo "Last entries in server log $(TEST_PATH)/radius.log"; \
	fi
	@echo "ok"
	@echo "TEST_PORT=$(PORT) $(BIN_PATH)/radiusd -Pfxxxxl stdout -d ${top_builddir}/src/tests -n test -D \"${top_srcdir}/share/dictionary/\"";
	@echo "Server logging to \"$(TEST_PATH)/radius.log\""

# We can't make this depend on radiusd.pid, because then make will create
# radiusd.pid when we make radiusd.kill, which we don't want.
.PHONY: radiusd.kill
radiusd.kill:
	@if [ -f radiusd.pid ]; then \
		ret=0; \
		if ! ps `cat $(TEST_PATH)/radiusd.pid` >/dev/null 2>&1; then \
			echo "FreeRADIUS terminated during test"; \
			echo "GDB output was:"; \
			cat "$(TEST_PATH)/gdb.log"; \
			echo "Last log entries were:"; \
			tail -n 20 $(TEST_PATH)/radius.log; \
			echo "Last entries in server log $(TEST_PATH)/radius.log"; \
			ret=1; \
		elif ! kill -TERM `cat $(TEST_PATH)/radiusd.pid` >/dev/null 2>&1; then \
			echo "Failed terminating FreeRADIUS process"; \
			ret=1; \
		fi; \
		rm -f radiusd.pid \
		exit $$ret; \
	fi


# kill the server (if it's running)
# start the server
# run the tests (ignoring any failures)
# kill the server
# remove the changes to raddb/
tests: test.conf | radiusd.kill radiusd.pid
	@chmod a+x runtest.sh
	@echo BIN_PATH="$(BIN_PATH)" PORT="$(PORT)" ./runtest.sh $(TEST)
	@BIN_PATH="$(BIN_PATH)" PORT="$(PORT)" TOP_BUILDDIR="${top_builddir}" ./runtest.sh $(TEST)
	@$(MAKE) radiusd.kill
