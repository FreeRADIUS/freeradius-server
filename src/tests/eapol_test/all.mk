#
#	Tests for EAP support
#
TEST := test.eap
$(eval $(call TEST_BOOTSTRAP))

TEST_PATH := ${top_srcdir}/src/tests/eapol_test
CONFIG_PATH := $(TEST_PATH)/config
RADIUS_LOG := $(OUTPUT)/radiusd.log
GDB_LOG := $(OUTPUT)/gdb.log
BIN_PATH := $(BUILD_DIR)/bin/local

#
#   We use the stock raddb modules to help detect typos and other issues
#
RADDB_PATH := $(top_builddir)/raddb

#
#   This ensures that FreeRADIUS uses modules from the build directory
#
EAP_TARGETS      := $(filter rlm_eap_%,$(ALL_TGTS))
EAP_TYPES        := $(patsubst rlm_eap_%.la,%,$(EAP_TARGETS))
EAPOL_TEST_FILES := $(foreach x,$(EAP_TYPES),$(wildcard $(DIR)/$(x)*.conf))
EAPOL_OK_FILES  := $(patsubst $(DIR)/%.conf,$(OUTPUT)/%.ok,$(EAPOL_TEST_FILES))
EAPOL_METH_FILES := $(addprefix $(CONFIG_PATH)/methods-enabled/,$(EAP_TYPES))

#
#  Generic rules to start / stop the radius service.
#
include src/tests/radiusd.mk
$(eval $(call RADIUSD_SERVICE,servers,$(OUTPUT)))

.PHONY: $(CONFIG_PATH)/methods-enabled
$(CONFIG_PATH)/methods-enabled:
	${Q}mkdir -p $@

$(CONFIG_PATH)/methods-enabled/%: $(BUILD_DIR)/lib/rlm_eap_%.la | $(CONFIG_PATH)/methods-enabled
	${Q}ln -sf $(CONFIG_PATH)/methods-available/$(notdir $@) $(CONFIG_PATH)/methods-enabled/

#
#   Only run EAP tests if we have a "test" target
#
ifneq (,$(findstring test,$(MAKECMDGOALS)))
EAPOL_TEST = $(shell test -e "$(OUTPUT)/eapol_test.skip" || $(top_builddir)/scripts/travis/eapol_test-build.sh)
endif

ifneq "$(EAPOL_TEST)" ""

#
#  Build snakoil certs if they don't exist
#
$(RADDB_PATH)/certs/%:
	${Q}make -C $(dir $@) 2>&1

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
	$(patsubst $(DIR)/%.conf,$(OUTPUT)/%.ok,${x}): ${CONFIG_PATH}/methods-enabled/$(basename $(notdir $(word 1,$(subst -, ,$(x))))) \
))

#
#  Separate the dependencies here just to keep a bit clear.
#
test.eap.depends: $(RADDB_PATH)/certs/server.pem | $(EAPOL_METH_FILES) $(OUTPUT)

#
#  Run eapol_test if it exists.  Otherwise do nothing
#
$(OUTPUT)/%.ok: $(DIR)/%.conf | test.eap.radiusd_kill test.eap.depends test.eap.radiusd_start
	$(eval OUT := $(patsubst %.conf,%.log,$@))
	${Q}echo EAPOL_TEST $(notdir $(patsubst %.conf,%,$<))
	${Q}if ( grep 'key_mgmt=NONE' '$<' > /dev/null && $(EAPOL_TEST) -t 2 -c $< -p $(PORT) -s $(SECRET) -n > $(OUT) 2>&1 ) || \
		$(EAPOL_TEST) -t 2 -c $< -p $(PORT) -s $(SECRET) > $(OUT) 2>&1; then\
		touch $@; \
	else \
		echo "Last entries in supplicant log ($(patsubst %.conf,%.log,$@)):"; \
		tail -n 40 "$(patsubst %.conf,%.log,$@)"; \
		echo "--------------------------------------------------"; \
		tail -n 40 "$(RADIUS_LOG)"; \
		echo "Last entries in server log ($(RADIUS_LOG)):"; \
		echo "--------------------------------------------------"; \
		echo "$(EAPOL_TEST) -c \"$<\" -p $(PORT) -s $(SECRET)"; \
		$(MAKE) test.eap.radiusd_kill; \
		exit 1;\
	fi

$(TEST): $(EAPOL_OK_FILES)
	${Q}$(MAKE) test.eap.radiusd_kill
else
#
#  Build rules and the make file get evaluated at different times
#  if we don't touch the test skipped file immediately, users can
#  cntrl-c out of the build process, and the skip file never gets
#  created as the test.eap target is evaluated much later in the
#  build process.2
#
ifneq (,$(findstring test,$(MAKECMDGOALS)))
$(shell touch "$(OUTPUT)/eapol_test.skip")
endif

$(TEST): $(OUTPUT)
	${Q}echo "Retry with: $(MAKE) clean.$@ && $(MAKE) $@"
endif
