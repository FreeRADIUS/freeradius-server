# -*- makefile -*-
##
## Makefile -- Build and run tests for the server.
##
##	http://www.freeradius.org/
##	$Id$
##
#
TEST_PATH := ${top_srcdir}/src/tests/eapol_test
CONFIG_PATH := $(TEST_PATH)/config

OUTPUT_DIR := $(BUILD_DIR)/tests/eapol_test
RADIUS_LOG := $(OUTPUT_DIR)/radius.log
GDB_LOG := $(OUTPUT_DIR)/gdb.log
BIN_PATH := $(BUILD_DIR)/bin/local

#
#   This ensures that FreeRADIUS uses modules from the build directory
#
FR_LIBRARY_PATH := $(BUILD_DIR)/lib/local/.libs/
export FR_LIBRARY_PATH

#
#   We use the stock raddb modules to help detect typos and other issues
#
RADDB_PATH := $(top_builddir)/raddb

PORT := 12350
SECRET := testing123

EAP_TARGETS	:= $(filter rlm_eap_%,$(ALL_TGTS))
EAP_TYPES	:= $(patsubst rlm_eap_%.la,%,$(EAP_TARGETS))

EAPOL_TEST_FILES := $(foreach x,$(EAP_TYPES),$(wildcard $(DIR)/$(x)*.conf))
EAPOL_OK_FILES	 := $(patsubst $(DIR)/%.conf,$(OUTPUT_DIR)/%.ok,$(EAPOL_TEST_FILES))
EAPOL_METH_FILES := $(addprefix $(CONFIG_PATH)/methods-enabled/,$(EAP_TYPES))


.PHONY: $(OUTPUT_DIR)
$(OUTPUT_DIR):
	@mkdir -p $@

.PHONY: $(CONFIG_PATH)/methods-enabled
$(CONFIG_PATH)/methods-enabled:
	@mkdir -p $@

$(CONFIG_PATH)/methods-enabled/%: $(BUILD_DIR)/lib/rlm_eap_%.la | $(CONFIG_PATH)/methods-enabled
	@ln -sf $(CONFIG_PATH)/methods-available/$(notdir $@) $(CONFIG_PATH)/methods-enabled/

.PHONY: eap dictionary clean clean.tests.eap
clean: clean.tests.eap

#
#   Only run EAP tests if we have a "test" target
#
ifneq (,$(findstring test,$(MAKECMDGOALS)))
EAPOL_TEST = $(shell test -e "$(OUTPUT_DIR)/eapol_test.skip" || $(top_builddir)/scripts/travis/eapol_test-build.sh)
endif

# This gets called recursively, so has to be outside of the condition below
# We can't make this depend on radiusd.pid, because then make will create
# radiusd.pid when we make radiusd.kill, which we don't want.
.PHONY: radiusd.kill
radiusd.kill: | $(OUTPUT_DIR)
	@if [ -f $(CONFIG_PATH)/radiusd.pid ]; then \
		ret=0; \
		if ! ps `cat $(CONFIG_PATH)/radiusd.pid` >/dev/null 2>&1; then \
		    rm -f $(CONFIG_PATH)/radiusd.pid; \
		    echo "FreeRADIUS terminated during test"; \
		    echo "GDB output was:"; \
		    cat "$(GDB_LOG)"; \
		    echo "--------------------------------------------------"; \
		    tail -n 40 "$(RADIUS_LOG)"; \
		    echo "Last entries in server log ($(RADIUS_LOG)):"; \
		    ret=1; \
		fi; \
		if ! kill -TERM `cat $(CONFIG_PATH)/radiusd.pid` >/dev/null 2>&1; then \
			ret=1; \
		fi; \
		exit $$ret; \
	fi

clean.tests.eap:
	@rm -f $(OUTPUT_DIR)/*.ok $(OUTPUT_DIR)/*.log $(OUTPUT_DIR)/eapol_test.skip
	@rm -f "$(CONFIG_PATH)/test.conf"
	@rm -f "$(CONFIG_PATH)/dictionary"
	@rm -rf "$(CONFIG_PATH)/methods-enabled"

ifneq "$(EAPOL_TEST)" ""
$(CONFIG_PATH)/dictionary:
	@echo "# test dictionary not install.  Delete at any time." > $@
	@echo '$$INCLUDE ' $(top_builddir)/share/dictionary >> $@
	@echo '$$INCLUDE ' $(top_builddir)/src/tests/dictionary.test >> $@
	@echo '$$INCLUDE ' $(top_builddir)/share/dictionary.dhcp >> $@
	@echo '$$INCLUDE ' $(top_builddir)/share/dictionary.vqp >> $@

$(CONFIG_PATH)/test.conf: $(CONFIG_PATH)/dictionary src/tests/eapol_test/all.mk
	@echo "# test configuration file.  Do not install.  Delete at any time." > $@
	@echo 'testdir =' $(CONFIG_PATH) >> $@
	@echo 'logdir =' $(OUTPUT_DIR) >> $@
	@echo 'maindir = ${top_builddir}/raddb/' >> $@
	@echo 'radacctdir = $${testdir}' >> $@
	@echo 'pidfile = $${testdir}/radiusd.pid' >> $@
	@echo 'panic_action = "gdb -batch -x ${top_srcdir}/src/tests/panic.gdb %e %p > $(GDB_LOG) 2>&1; cat $(GDB_LOG)"' >> $@
	@echo 'security {' >> $@
	@echo '        allow_vulnerable_openssl = yes' >> $@
	@echo '}' >> $@
	@echo >> $@
	@echo 'modconfdir = $${maindir}mods-config' >> $@
	@echo 'certdir = $${maindir}/certs' >> $@
	@echo 'cadir   = $${maindir}/certs' >> $@
	@echo '$$INCLUDE $${testdir}/servers.conf' >> $@

#
#  Build snakoil certs if they don't exist
#
$(RADDB_PATH)/certs/%:
	@make -C $(dir $@)

$(CONFIG_PATH)/radiusd.pid: $(CONFIG_PATH)/test.conf $(RADDB_PATH)/certs/server.pem | $(EAPOL_METH_FILES) $(OUTPUT_DIR)
	@rm -f $(GDB_LOG) $(RADIUS_LOG)
	@printf "Starting EAP test server... "
	@if ! TEST_PORT=$(PORT) $(JLIBTOOL) --mode=execute $(BIN_PATH)/radiusd -Pxxxl $(RADIUS_LOG) -d $(CONFIG_PATH) -n test -D $(CONFIG_PATH); then\
		echo "FAILED STARTING RADIUSD"; \
		tail -n 40 "$(RADIUS_LOG)"; \
		echo "Last entries in server log ($(RADIUS_LOG)):"; \
	else \
		echo "ok"; \
	fi

#
#  We want the tests to depend on the method configuration used by the
#  server, too.
#
#  This monstrosity does that.  Note that:
#
#  eapol_test configuration files are named "method" or "method-foo"
#
#  radiusd configuration files are named "method".
#
$(foreach x,$(EAPOL_TEST_FILES),$(eval \
	$(patsubst $(DIR)/%.conf,$(OUTPUT_DIR)/%.ok,${x}): ${CONFIG_PATH}/methods-enabled/$(basename $(notdir $(word 1,$(subst -, ,$(x))))) \
))


#
#  Run eapol_test if it exists.  Otherwise do nothing
#
$(OUTPUT_DIR)/%.ok: $(DIR)/%.conf | radiusd.kill $(CONFIG_PATH)/radiusd.pid
	@echo EAPOL_TEST $(notdir $(patsubst %.conf,%,$<))
	@if ( grep 'key_mgmt=NONE' '$<' > /dev/null && $(EAPOL_TEST) -t 2 -c $< -p $(PORT) -s $(SECRET) -n > $(patsubst %.conf,%.log,$@) 2>&1 ) || \
		$(EAPOL_TEST) -t 2 -c $< -p $(PORT) -s $(SECRET) > $(patsubst %.conf,%.log,$@) 2>&1; then\
		touch $@; \
	else \
		echo "Last entries in supplicant log ($(patsubst %.conf,%.log,$<)):"; \
		tail -n 40 "$(patsubst %.conf,%.log,$<)"; \
		echo "--------------------------------------------------"; \
		tail -n 40 "$(RADIUS_LOG)"; \
		echo "Last entries in server log ($(RADIUS_LOG)):"; \
		echo "--------------------------------------------------"; \
		echo "TEST_PORT=$(PORT) $(JLIBTOOL) --mode=execute $(BIN_PATH)/radiusd -PX -d \"$(CONFIG_PATH)\" -n test -D \"$(CONFIG_PATH)\""; \
		echo "$(EAPOL_TEST) -c \"$<\" -p $(PORT) -s $(SECRET)"; \
		$(MAKE) radiusd.kill; \
		exit 1;\
	fi

tests.eap: $(EAPOL_OK_FILES)
	@$(MAKE) radiusd.kill
else
tests.eap: $(OUTPUT_DIR)
	@echo "Skipping EAP tests due to previous build error"
	@echo "Retry with: $(MAKE) clean.$@ && $(MAKE) $@"
	@touch "$(OUTPUT_DIR)/eapol_test.skip"
endif
