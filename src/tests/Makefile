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

#
#  Build eapol_test if requested to.
#
.PHONY: eapol_test
eapol_test: $(BUILD_PATH)/tests/eapol_test/eapol_test.mk
	@echo EAPOL_TEST=$(EAPOL_TEST)

#
#  If we're doing anything resembling EAP, then make sure that
#  EAPOL_TEST is defined.
#
ifneq "(findstring eap,$(MAKECMDGOALS))" ""
$(BUILD_PATH)/tests/eapol_test:
	@mkdir -p $@

#
#  Build eapol_test, and cache its output.  Note that EAPOL_TEST may not be
#  defined, so we have to run the shell script for the second line, too.
#
$(BUILD_PATH)/tests/eapol_test/eapol_test.mk: | $(BUILD_PATH)/tests/eapol_test
	@echo "EAPOL_TEST=" $(shell $(top_builddir)/scripts/ci/eapol_test-build.sh) > $@
	@echo "TLS1_3=" $(shell strings $(shell $(top_builddir)/scripts/ci/eapol_test-build.sh) | grep '1_3' | head -n 1) >> $@

-include $(BUILD_PATH)/tests/eapol_test/eapol_test.mk
endif

TEST_PATH := $(top_builddir)/src/tests
DICT_PATH := $(TEST_PATH)
BIN_PATH := $(BUILD_PATH)/bin/local
RADIUSD_BIN := $(BIN_PATH)/radiusd

ifeq "$(DICT_PATH)" "$(TEST_PATH)"
LIB_PATH := $(BUILD_PATH)/lib/local/.libs/
DYLD_LIBRARY_PATH := $(DYLD_LIBRARY_PATH):$(LIB_PATH)
export DYLD_LIBRARY_PATH
endif

RADDB_PATH := $(top_builddir)/raddb/

TESTS	= mschapv1 digest-01/digest* \
	test.example.com

PORT	 = 12340
ACCTPORT = $(shell expr $(PORT) + 1)

#	example.com stripped.example.com

SECRET	= testing123

.PHONY: all eap dictionary clean

#
#	Build the directory for testing the server
#
all: tests

clean:
	@rm -f test.conf dictionary *.ok *.log $(BUILD_DIR)/tests/eap

dictionary:
	@echo "# test dictionary not install.  Delete at any time." > dictionary;  \
	echo '$$INCLUDE ' $(top_builddir)/share/dictionary >> dictionary;          \
	echo '$$INCLUDE ' $(top_builddir)/src/tests/dictionary.test >> dictionary; \
	if [ "$(DICT_PATH)" = "$(TEST_PATH)" ]; then                               \
	    echo '$$INCLUDE ' $(top_builddir)/share/dictionary.dhcp >> dictionary; \
	    echo '$$INCLUDE ' $(top_builddir)/share/dictionary.vqp >> dictionary;  \
	fi

test.conf: dictionary config/eap-test
	@echo "# test configuration file.  Do not install.  Delete at any time." > $@
	@if [ -n "$(LIB_PATH)" ]; then  \
	    echo "libdir =" $(LIB_PATH) >> $@; \
	fi
	@echo "testdir =" $(TEST_PATH) >> $@
	@echo 'logdir = $${testdir}' >> $@
	@echo "maindir =" $(RADDB_PATH) >> $@
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
	@echo '$$INCLUDE $${maindir}/radiusd.conf' >> $@

#
#  Rename "inner-tunnel", and ensure that it only uses the "eap-test" module.
#
config/eap-test-inner-tunnel: $(RADDB_PATH)sites-available/inner-tunnel
	@sed 's/eap/eap-test/;s/server inner-tunnel/server eap-test-inner-tunnel/' < $< > $@

#
#  * Same renames as above
#  * enable caching
#  * uncomment caching directory
#  * set the minimum TLS version to 1.0 for testing
#  * set the maximum TLS version to 1.2 or 1.3, depending if 1.3 is available
#  * always enable TLS 1.3 for the tests, via the super-secret magic flag.
#  * tell OpenSSL to enable insecure ciphers TLS 1.0 and TLS 1.1
#
config/eap-test: $(RADDB_PATH)mods-available/eap config/eap-test-inner-tunnel
	@sed -e 's/eap {/eap eap-test {/' \
	     -e 's/= inner-tunnel/= eap-test-inner-tunnel/;s/use_tunneled_reply = no/use_tunneled_reply = yes/' \
	     -e 's/enable = no/enable = yes/' \
	     -e 's/^\(.*\)persist_dir =/  persist_dir =/' \
	     -e 's/tls_min_version = "1.2"/tls_min_version = "1.0"/' \
	     -e '$(if $(TLS1_3),s/tls_max_version = "1.2"/tls_max_version = "1.3"/)' \
	     -e  '/tls_max_version/s/^//p; /tls_max_version/s/^.*/        tls13_enable=true/' \
	     -e 's/cipher_list = "DEFAULT"/cipher_list = "DEFAULT@SECLEVEL=1"/' \
		 < $< > $@

radiusd.pid: test.conf
	@rm -rf $(TEST_PATH)/gdb.log $(TEST_PATH)/radius.log $(TEST_PATH)/tlscache
	@mkdir -p $(TEST_PATH)/tlscache
	@printf "Starting server... "
	@if ! $(RADIUSD_BIN) -Pxxxxml $(TEST_PATH)/radius.log -d ${top_builddir}/src/tests -n test -i 127.0.0.1 -p $(PORT) -D $(DICT_PATH); then \
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
EAP_FILES	= eap-md5.conf
EAP_TLS_FILES	= eap-ttls-pap.conf eap-ttls-mschapv2.conf peap-mschapv2.conf
EAP_TLS_VERSIONS = 1.1 1.2
ifneq "$(TLS1_3)" ""
EAP_TLS_VERSIONS += 1.3
endif
EAP_TLS_DISABLE_STRING=tls_disable_tlsv1_0=1 tls_disable_tlsv1_1=1 tls_disable_tlsv1_2=1 $(TLS1_3)

.PHONY: $(BUILD_PATH)/tests/eap
$(BUILD_PATH)/tests/eap:
	@mkdir -p $@

.PHONY: clean.tests.eap
clean.tests.eap:
	@rm -rf $(BUILD_PATH)/tests/eap config/tlscache config/eap-test config/eap-test-inner-tunnel

#
#  Set target-specific variables, so that the later shell scripts are rather more understandable.
#
#  MD5 doesn't use MPPE keys
#
$(BUILD_PATH)/tests/eap/%.ok: NO_MPPE = $(filter eap-md5,$(basename $(notdir $@)))
$(BUILD_PATH)/tests/eap/%.ok: CMD =  $(EAPOL_TEST) -c $< -p $(PORT) -s $(SECRET) $(if $(NO_MPPE),-n)
$(BUILD_PATH)/tests/eap/%.ok: LOG =  $(patsubst %.ok,%,$@).log

$(BUILD_PATH)/tests/eap/%.ok: $(top_builddir)/src/tests/%.conf | radiusd.kill $(BUILD_PATH)/tests/eap radiusd.pid radiusd.kill
	@printf 'EAPOL_TEST %s ' $(notdir $(patsubst %.conf,%,$<))
	@if ! $(CMD) > $(LOG) 2>&1; then \
		echo " - " FAILED - command failed; \
		echo ">>> cmd -" $(CMD); \
		echo ">>> log -" $(LOG); \
		echo "===================="; \
		tail -10 $$(LOG); \
		echo "===================="; \
		$(MAKE) radiusd.kill; \
		exit 1; \
	fi
	@echo
	@touch $@

#
#  Don't run the full TLS version tests for CI post-install.
#
ifneq "$(prefix)" ""
#
#  ${1} is the config file
#  ${2} is the TLS version to use.
#
#  Update the phase1 configuration to enable/disable various TLS versions
#  insert an OpenSSL cipher configuration line by cloning "password" and editing it.
#
define EAP_TLS_CONFIG
$(BUILD_PATH)/tests/eap/${1}-${2}.conf: $(top_builddir)/src/tests/${1}.conf
	@sed -e 's/phase1="/phase1="$(subst $(subst .,_,${2})=1,$(subst .,_,${2})=0,$(EAP_TLS_DISABLE_STRING)) /' \
	     -e  '/password/s/^//p; /password/s/^.*/        openssl_ciphers="DEFAULT@SECLEVEL=1"/' \
		< $$< > $$@

$(BUILD_PATH)/tests/eap/${1}-${2}.ok: $(BUILD_PATH)/tests/eap/${1}-${2}.conf
	@printf 'EAPOL_TEST %s' $$(notdir $$(patsubst %.ok,%,$$@))
	@if ! $$(CMD) -r 1 > $$(LOG) 2>&1; then \
		echo " - " FAILED  - command failed; \
		echo ">>> cmd -" $$(CMD) -r 1; \
		echo ">>> log -" $$(LOG); \
		echo "===================="; \
		tail -10 $$(LOG); \
		echo "===================="; \
		$(MAKE) radiusd.kill; \
		exit 1; \
	elif ! grep -q '^SSL: Using TLS version TLSv${2}$$$$' $$(patsubst %.ok,%,$$@).log; then \
		echo " - " FAILED - not using TLS version ${2}; \
		echo ">>> cmd -" $$(CMD) -r 1; \
		echo ">>> log -" $$(LOG); \
		$(MAKE) radiusd.kill; \
		exit 1; \
	elif ! grep -q '^OpenSSL: Handshake finished - resumed=1$$$$' $$(patsubst %.ok,%,$$@).log; then \
		echo " - " FAILED - did not use resumption; \
		echo ">>> cmd -" $$(CMD) -r 1; \
		echo ">>> log -" $$(LOG); \
		$(MAKE) radiusd.kill; \
		exit 1; \
	fi
	@echo
	@touch $$@

# EAP-FAST doesn't do TLS 1.3
ifneq "${1}-${2}" "eap-fast-1.3"
EAP_TLS_VERSION_FILES += $(BUILD_PATH)/tests/eap/${1}-${2}.ok
endif
endef

$(foreach FILE,$(patsubst %.conf,%,$(EAP_TLS_FILES)),$(foreach TLS,$(EAP_TLS_VERSIONS),$(eval $(call EAP_TLS_CONFIG,${FILE},${TLS}))))
endif # there's no "prefix", so we don't run the full EAP tests

EAPOL_OK_FILES := $(sort $(addprefix $(BUILD_PATH)/tests/eap/,$(patsubst %.conf,%.ok, $(notdir $(EAP_TLS_FILES) $(EAP_FILES)))) $(EAP_TLS_VERSION_FILES))

tests.eap: $(EAPOL_OK_FILES) | radiusd.kill radiusd.pid
	@$(MAKE) radiusd.kill

endif # we have eapol_test built

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
