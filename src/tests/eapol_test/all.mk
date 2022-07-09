#
#  The "build eapol_test" makefile contains only a definition of
#  EAPOL_TEST, which is where the binary is located.
#
#  But, we only try to build eapol_test if we're building _any_ tests.
#
#  If we're not running tests, OR if EAPOL_TEST isn't defined, then we
#  skip the rest of these tests.
#
ifneq "$(findstring test,$(MAKECMDGOALS))" ""
# define where the EAPOL_TEST is located.  If necessary, build it.
$(BUILD_DIR)/tests/eapol_test/eapol_test.mk: | $(BUILD_DIR)/tests/eapol_test
	${Q}echo "EAPOL_TEST=" $(shell $(top_srcdir)/scripts/ci/eapol_test-build.sh) > $@

# include the above definition.  If the "mk" file doesn't exist, then the preceding
# rule will cause it to be build.
-include $(BUILD_DIR)/tests/eapol_test/eapol_test.mk

#  A helpful target which causes eapol_test to be built, BUT does not run the
#  "test.eap" targets.
.PHONY:
eapol_test:
	@echo EAPOL_TEST=$(EAPOL_TEST)
endif

#
#	Tests for EAP support
#
TEST := test.eap

ifneq "$(EAPOL_TEST)" ""
$(eval $(call TEST_BOOTSTRAP))

TEST_PATH := ${top_srcdir}/src/tests/eapol_test
CONFIG_PATH := $(TEST_PATH)/config
GDB_LOG := $(OUTPUT)/gdb.log
TEST_BIN := $(BUILD_DIR)/bin/local

#
#   We use the stock raddb modules to help detect typos and other issues
#
RADDB_PATH := $(top_builddir)/raddb

#
#	Disabled modules.
#
IGNORED_EAP_TYPES := peap ttls

#
#   This ensures that FreeRADIUS uses modules from the build directory
#
EAP_TARGETS      := $(filter rlm_eap_%,$(ALL_TGTS))
EAP_TYPES_LIST   := $(patsubst rlm_eap_%.la,%,$(EAP_TARGETS))
EAP_TYPES        := $(filter-out $(IGNORED_EAP_TYPES),$(EAP_TYPES_LIST))
EAPOL_TEST_FILES := $(foreach x,$(EAP_TYPES),$(wildcard $(DIR)/$(x)*.conf))
EAPOL_OK_FILES	 := $(patsubst $(DIR)/%.conf,$(OUTPUT)/%.ok,$(EAPOL_TEST_FILES))

#
#  Add rules so that we can run individual tests for each EAP method.
#
define ADD_TEST_EAP
test.eap.${1}: $(OUTPUT)/${1}.ok
endef
$(foreach x,$(patsubst $(DIR)/%.conf,%,$(EAPOL_TEST_FILES)),$(eval $(call ADD_TEST_EAP,$x)))


#
#  Generic rules to start / stop the radius service.
#
include src/tests/radiusd.mk

define ADD_TEST_EAP_OUTPUT
$(OUTPUT)/${1}:
	$(Q)mkdir -p $$@
endef

#
#  Setup rules to spawn a different RADIUSD instance for each EAP type
#
$(foreach TEST,$(addprefix test., $(subst _,-,$(EAP_TYPES))),$(eval $(call RADIUSD_SERVICE,servers,$(OUTPUT)/$(TEST)))$(eval $(call ADD_TEST_EAP_OUTPUT,$(TEST))))

#  Reset
TEST := test.eap

#
#	Print the disabled list.
#
$(IGNORED_EAP_TYPES):
	@echo "EAPOL-TEST $@ - Disabled.  Enable by removing '$@' from 'IGNORED_EAP_TYPES' in src/tests/eapol_test/all.mk"

#
#  Separate the dependencies here just to keep a bit clear.
#
test.eap.check: $(IGNORED_EAP_TYPES) | $(OUTPUT) $(GENERATED_CERT_FILES)

#
#  Run EAP tests.
#
#  We don't depend on server build artifacts when we are executing from the post-install test environment
#
$(OUTPUT)/%.ok: $(DIR)/%.conf $(if $(POST_INSTALL_MAKEFILE_ARG),,$(BUILD_DIR)/lib/libfreeradius-server.la $(BUILD_DIR)/lib/libfreeradius-util.la) | $(GENERATED_CERT_FILES)
	$(eval EAPOL_TEST_LOG := $(patsubst %.ok,%.log,$@))
	$(eval METHOD := $(notdir $(patsubst %.conf,%,$<)))
	$(eval KEY := $(shell grep key_mgmt=NONE $< | sed 's/key_mgmt=NONE/-n/'))
	$(eval RADIUS_LOG := $(dir $@)/test.$(METHOD)/radiusd.log)
	$(eval TEST_PORT := $($(METHOD)_port))
	@echo "EAPOL-TEST $(METHOD)"
	${Q}$(MAKE) $(POST_INSTALL_MAKEFILE_ARG) --no-print-directory test.$(METHOD).radiusd_kill
	${Q}$(MAKE) $(POST_INSTALL_MAKEFILE_ARG) --no-print-directory test.$(METHOD).radiusd_start $(POST_INSTALL_RADIUSD_BIN_ARG)
	${Q}if ! $(EAPOL_TEST) -t 10 -c $< -p $(TEST_PORT) -s $(SECRET) $(KEY) > $(EAPOL_TEST_LOG) 2>&1; then	\
		echo "Last entries in supplicant log ($(EAPOL_TEST_LOG)):";	\
		tail -n 40 "$(EAPOL_TEST_LOG)";							\
		echo "--------------------------------------------------";		\
		tail -n 40 "$(RADIUS_LOG)";						\
		echo "Last entries in server log ($(RADIUS_LOG)):";			\
		echo "--------------------------------------------------";		\
		echo "RADIUSD :  OUTPUT=$(dir $@) TESTDIR=$(dir $<) TEST=$(METHOD) TEST_PORT=$(TEST_PORT) $(RADIUSD_BIN) -fxxx -n servers -d $(dir $<)config -D $(DICT_PATH) -lstdout -f"; \
		echo "EAPOL   :  $(EAPOL_TEST) -c \"$<\" -p $(TEST_PORT) -s $(SECRET) $(KEY) "; \
		echo "           log is in $(OUT)"; \
		rm -f $(BUILD_DIR)/tests/test.eap;                                      \
		$(MAKE) $(POST_INSTALL_MAKEFILE_ARG) --no-print-directory test.$(METHOD).radiusd_kill;			\
		exit 1;\
	fi
	${Q}$(MAKE) $(POST_INSTALL_MAKEFILE_ARG) --no-print-directory test.$(METHOD).radiusd_stop
	${Q}touch $@

$(TEST): $(EAPOL_OK_FILES)
	@touch $(BUILD_DIR)/tests/$@

else
$(BUILD_DIR)/tests/eapol_test:
	@mkdir -p $@

$(TEST):
	@echo "eapol_test build previously failed, skipping... retry with: $(MAKE) clean.$@ && $(MAKE) $@"

.PHONY: clean.test.eap
clean.test.eap:
	${Q}rm -f $(BUILD_DIR)/tests/eapol_test
endif
