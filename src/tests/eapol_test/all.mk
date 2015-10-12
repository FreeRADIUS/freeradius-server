# -*- makefile -*-
##
## Makefile -- Build and run tests for the server.
##
##	http://www.freeradius.org/
##	$Id$
##
#
BUILD_PATH := $(top_builddir)/build
TEST_PATH := $(top_builddir)/src/tests/eapol_test
CONFIG_PATH := $(TEST_PATH)/config
RADIUS_LOG := $(TEST_PATH)/radius.log
GDB_LOG := $(TEST_PATH)/gdb.log
BIN_PATH := $(BUILD_PATH)/bin/local

#
#   This ensures that FreeRADIUS uses modules from the build directory
#
FR_LIBRARY_PATH := $(BUILD_PATH)/lib/.libs/
export FR_LIBRARY_PATH

#
#   We use the stock raddb modules to help detect typos and other issues
#
RADDB_PATH := $(top_builddir)/raddb

PORT := 12350
SECRET := testing123

EAPOL_TEST_FILES := $(wildcard $(TEST_PATH)/*eap*.conf)

#
#   Link all the methods we have configuration files for
#
$(shell mkdir -p $(CONFIG_PATH)/methods-enabled/)
$(shell ln -f -s $(CONFIG_PATH)/methods-available/* $(CONFIG_PATH)/methods-enabled/)

#
#   If we didn't build the rlm_eap_pwd module, don't perform the test
#
ifneq (,$(wildcard "$(FR_LIBRARY_PATH)/rlm_eap_pwd*"))
    EAPOL_TEST_FILES := $(subst eap-pwd.conf,,$(EAPOL_TEST_FILES))
    $(shell rm $(CONFIG_PATH)/methods-enabled/pwd)
endif

.PHONY: eap dictionary clean tests.eap.clean
clean: tests.eap.clean

#
#   Only run EAP tests if we have eapol_test in our path
#
EAPOL_TEST = $(shell $(top_builddir)/scripts/travis/eapol_test-build.sh)
ifneq "$(EAPOL_TEST)" ""
#
#	Build the directory for testing the server
#
tests.eap.clean:
	@rm -f "$(TEST_PATH)/"*.ok "$(TEST_PATH)/"*.log
	@rm -f "$(CONFIG_PATH)/test.conf"
	@rm -f "$(CONFIG_PATH)/dictionary"
	@rm -rf "$(CONFIG_PATH)/methods-enabled"

$(CONFIG_PATH)/dictionary:
	@echo "# test dictionary not install.  Delete at any time." > $@
	@echo '$$INCLUDE ' $(top_builddir)/share/dictionary >> $@
	@echo '$$INCLUDE ' $(top_builddir)/src/tests/dictionary.test >> $@
	@echo '$$INCLUDE ' $(top_builddir)/share/dictionary.dhcp >> $@
	@echo '$$INCLUDE ' $(top_builddir)/share/dictionary.vqp >> $@

$(CONFIG_PATH)/test.conf: $(CONFIG_PATH)/dictionary
	@echo "# test configuration file.  Do not install.  Delete at any time." > $@
	@echo "testdir =" $(CONFIG_PATH) >> $@
	@echo 'logdir = $${testdir}' >> $@
	@echo 'maindir = ${top_builddir}/raddb/' >> $@
	@echo 'radacctdir = $${testdir}' >> $@
	@echo 'pidfile = $${testdir}/radiusd.pid' >> $@
	@echo 'panic_action = "gdb -batch -x ${testdir}/panic.gdb %e %p > $(GDB_LOG) 2>&1; cat $(GDB_LOG)"' >> $@
	@echo 'security {' >> $@
	@echo '        allow_vulnerable_openssl = yes' >> $@
	@echo '}' >> $@
	@echo >> $@
	@echo 'modconfdir = $${maindir}mods-config' >> $@
	@echo 'certdir = $${maindir}/certs' >> $@
	@echo 'cadir   = $${maindir}/certs' >> $@
	@echo '$$INCLUDE $${testdir}/servers.conf' >> $@

$(CONFIG_PATH)/radiusd.pid: $(CONFIG_PATH)/test.conf
	@rm -f $(GDB_LOG) $(RADIUS_LOG)
	@printf "Starting EAP test server... "
	@if ! TEST_PORT=$(PORT) $(BIN_PATH)/radiusd -Pxxxxml $(RADIUS_LOG) -d $(CONFIG_PATH) -n test -D $(CONFIG_PATH); then\
		echo "failed"; \
		echo "Last log entries were:"; \
		tail -n 20 "$(RADIUS_LOG)"; \
	else \
		echo "ok"; \
	fi

# We can't make this depend on radiusd.pid, because then make will create
# radiusd.pid when we make radiusd.kill, which we don't want.
.PHONY: radiusd.kill
radiusd.kill:
	@if [ -f $(CONFIG_PATH)/radiusd.pid ]; then \
		ret=0; \
		if ! ps `cat $(CONFIG_PATH)/radiusd.pid` >/dev/null 2>&1; then \
		rm -f $(CONFIG_PATH)/radiusd.pid; \
		echo "FreeRADIUS terminated during test"; \
		echo "GDB output was:"; \
		cat "$(GDB_LOG)"; \
		echo "Last log entries were:"; \
		tail -n 20 $(RADIUS_LOG); \
		ret=1; \
		fi; \
		if ! kill -TERM `cat $(CONFIG_PATH)/radiusd.pid` >/dev/null 2>&1; then \
			ret=1; \
		fi; \
		exit $$ret; \
	fi

#
#  Run eapol_test if it exists.  Otherwise do nothing
#
$(TEST_PATH)/%.ok: $(TEST_PATH)/%.conf | radiusd.kill $(CONFIG_PATH)/radiusd.pid
	@echo EAPOL_TEST $(notdir $(patsubst %.conf,%,$<))
	@if ( grep 'key_mgmt=NONE' '$<' > /dev/null && \
		$(EAPOL_TEST) -c $< -p $(PORT) -s $(SECRET) -n > $(patsubst %.conf,%.log,$<) 2>&1 ) || \
		$(EAPOL_TEST) -c $< -p $(PORT) -s $(SECRET) > $(patsubst %.conf,%.log,$<) 2>&1; then\
		touch $@; \
	else \
		echo "Last entries in supplicant log ($(patsubst %.conf,%.log,$<)):"; \
		tail -n 40 "$(patsubst %.conf,%.log,$<)"; \
		echo "Last entires in server log ($(RADIUS_LOG)):"; \
		tail -n 40 "$(RADIUS_LOG)"; \
		echo "$(EAPOL_TEST) -c \"$<\" -p $(PORT) -s $(SECRET)"; \
		exit 1;\
	fi

tests.eap: $(patsubst %.conf,%.ok, $(EAPOL_TEST_FILES))
	@$(MAKE) radiusd.kill
else
tests.eap:
endif
