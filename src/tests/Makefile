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
#  The "build eapol_test" makefile contains only a definition of
#  EAPOL_TEST, which is where the binary is located.
#
#  But, we only try to build eapol_test if we're asked to ("eapol_test"
#  target), in which case we skip the rest of these tests.
#
ifneq "$(findstring eapol_test,$(MAKECMDGOALS))" ""
$(BUILD_PATH)/tests/eapol_test:
	@mkdir -p $@

# define where the EAPOL_TEST is located.  If necessary, build it.
$(BUILD_PATH)/tests/eapol_test/eapol_test.mk: | $(BUILD_PATH)/tests/eapol_test
	@echo "EAPOL_TEST=" $(shell $(top_builddir)/scripts/ci/eapol_test-build.sh) > $@

# include the above definition.  If the "mk" file doesn't exist, then the preceding
# rule will cause it to be build.
-include $(BUILD_PATH)/tests/eapol_test/eapol_test.mk

#  A helpful target which causes eapol_test to be built, BUT does not run any
#  test targets.
eapol_test: $(BUILD_PATH)/tests/eapol_test/eapol_test.mk
	@echo EAPOL_TEST=$(EAPOL_TEST)
else

-include $(BUILD_PATH)/tests/eapol_test/eapol_test.mk
ifeq "$(EAPOL_TEST)" ""
EAPOL_TEST := $(shell $(top_builddir)/scripts/ci/eapol_test-build.sh)
endif

endif # check for eapol_test

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
#  Same as above, but enable caching, and set the persist_dir
#
config/eap-test: $(RADDB_PATH)mods-available/eap config/eap-test-inner-tunnel
	@sed 's/eap {/eap eap-test {/;s/= inner-tunnel/= eap-test-inner-tunnel/;s/use_tunneled_reply = no/use_tunneled_reply = yes/;s/enable = no/enable = yes/;s/^\(.*\)persist_dir =/  persist_dir =/' < $< > $@

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
TLS1_3=$(shell strings `which eapol_test` | grep '1_3' | head -n 1)

EAP_FILES	= eap-md5.conf
EAP_TLS_FILES	= eap-ttls-pap.conf eap-ttls-mschapv2.conf peap-mschapv2.conf
EAP_TLS_VERSIONS = 1.2
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
#  MD5 doesn't use MPPE keys
#
$(BUILD_PATH)/tests/eap/%.ok: NO_MPPE = $(filter eap-md5,$(basename $(notdir $@)))

$(BUILD_PATH)/tests/eap/%.ok: $(top_builddir)/src/tests/%.conf | radiusd.kill $(BUILD_PATH)/tests/eap radiusd.pid radiusd.kill
	@echo EAPOL_TEST $(notdir $(patsubst %.conf,%,$<))
	@if ! $(EAPOL_TEST) -c $< -p $(PORT) -s $(SECRET) $(if $(NO_MPPE),-n) > $(patsubst %.ok,%,$@).log 2>&1; then \
		echo "    " FAILED; \
		$(MAKE) radiusd.kill; \
		exit 1; \
	fi
	@touch $@

#
#  Don't run the full TLS version tests for CI post-install.
#
ifneq "$(prefix)" ""
#
#  ${1} is the config file
#  ${2} is the TLS version to use.
#
define EAP_TLS_CONFIG
$(BUILD_PATH)/tests/eap/${1}-${2}.conf: $(top_builddir)/src/tests/${1}.conf
	@sed 's/phase1="/phase1="$(subst $(subst .,_,${2})=1,$(subst .,_,${2})=0,$(EAP_TLS_DISABLE_STRING)) /' < $$< > $$@
#   Just keep the TLS versions that we want to disable. e.g: tls_disable_tlsv1_XX=1
	@sed '/phase1=/s/tls_disable_tlsv1_[0-9]=0//g' < $$@ > $$@.tmp
	@mv -f $$@.tmp $$@

$(BUILD_PATH)/tests/eap/${1}-${2}.ok: $(BUILD_PATH)/tests/eap/${1}-${2}.conf
	@echo EAPOL_TEST $$(notdir $$(patsubst %.ok,%,$$@))
	@if ! $(EAPOL_TEST) -r 1 -c $$< -p $(PORT) -s $(SECRET) > $$(patsubst %.ok,%,$$@).log 2>&1; then \
		echo FAILED; \
		echo "        " $(EAPOL_TEST) -c $$< -p $(PORT) -s $(SECRET); \
		$(MAKE) radiusd.kill; \
		exit 1; \
	elif ! grep -q '^SSL: Using TLS version TLSv${2}$$$$' $$(patsubst %.ok,%,$$@).log; then \
		echo "    " FAILED - not using TLS version ${2}; \
		echo "        " $(EAPOL_TEST) -c $$< -p $(PORT) -s $(SECRET); \
		$(MAKE) radiusd.kill; \
		exit 1; \
	elif ! grep -q '^OpenSSL: Handshake finished - resumed=1$$$$' $$(patsubst %.ok,%,$$@).log; then \
		echo "    " FAILED - did not use resumption; \
		echo "        " $(EAPOL_TEST) -r -c $$< -p $(PORT) -s $(SECRET); \
		$(MAKE) radiusd.kill; \
		exit 1; \
	fi
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
